package udpx

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-quic/congestion"

	E "github.com/sagernet/sing/common/exceptions"
)

// Association is one association between a client and a server.
//
// It is what the rest of the transport runs over: everything an association
// sends is a packet whose number is visible on the wire, so recovering a lost
// packet and retransmitting one are the same decision made in one place.
type Association interface {
	// LocalAddr is the address this end receives on.
	LocalAddr() net.Addr
	// RemoteAddr is where the peer is now. A packet that authenticates from a
	// new address moves the association there, which is all a NAT rebinding
	// needs: there is no path validation to run, because the peer address was
	// never load bearing.
	RemoteAddr() net.Addr
	// Context is done when the association ended. context.Cause says why:
	// net.ErrClosed for a close of either end, ErrIdleTimeout for silence,
	// ErrStatelessReset for a reset.
	Context() context.Context
	// CloseWithError closes the association towards the peer, which reports err
	// as the reason.
	CloseWithError(err error) error
	// OpenStream opens a stream towards the peer.
	OpenStream(ctx context.Context) (*Stream, error)
	// AcceptStream returns the next stream the peer opened.
	AcceptStream(ctx context.Context) (*Stream, error)
	// KeyID is the key the client authenticated with. A server uses it to find
	// the account of a connection it just accepted, and a client to know which
	// of its credentials was used.
	KeyID() [keyIDLen]byte
	// SendDatagram sends one message to the peer on a channel of the caller's
	// choosing. The message is not retransmitted: a datagram is a datagram.
	SendDatagram(channel uint32, data []byte) error
	// ReceiveDatagram returns the next message the peer sent, whole, from
	// whichever channel it belongs to.
	ReceiveDatagram(ctx context.Context) (Datagram, error)
}

var (
	// ErrIdleTimeout is the reason of an association both ends fell silent on.
	ErrIdleTimeout = E.New("udpx: idle timeout")

	// ErrStatelessReset is the reason of an association reset by a peer that
	// kept no state for it.
	ErrStatelessReset = E.New("udpx: stateless reset")
)

const (
	// maxPacketSize is the size of the largest packet either end sends. Path MTU
	// discovery is not on the list of things this transport does, so the value
	// is a constant with a hard ceiling.
	maxPacketSize = 1452

	// resetLen is the size of the body of a reset packet. It is random and
	// carries nothing: a reset says that the peer has no state for the
	// association, and there is nothing further to say.
	resetLen = 16

	// defaultIdleTimeout is how long an association may see no traffic before it
	// closes itself.
	defaultIdleTimeout = 30 * time.Second

	// helloRetransmitInterval is how long the client waits for an answer before
	// it sends its hello again. A hello is answered from no state, so sending
	// the same bytes again is safe and needs no retransmission machinery.
	helloRetransmitInterval = 250 * time.Millisecond

	// defaultHandshakeTimeout bounds a handshake started without a deadline, so
	// a client with a password the server does not know fails instead of waiting
	// for an answer that will never come.
	defaultHandshakeTimeout = 10 * time.Second
)

// Options are what the caller tunes about an association. Everything else is a
// constant of the protocol.
type Options struct {
	// IdleTimeout is how long an association may see no traffic before it
	// closes itself.
	IdleTimeout time.Duration

	// KeepAlivePeriod is how often an association with nothing to send sends a
	// ping. Zero means never, which leaves the association to the NAT mapping it
	// was created through.
	KeepAlivePeriod time.Duration

	// Congestion is the BBR profile of the congestion controller. The zero value
	// is the conservative one.
	Congestion congestion.Profile
}

func (o Options) withDefaults() Options {
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = defaultIdleTimeout
	}
	if o.KeepAlivePeriod < 0 {
		o.KeepAlivePeriod = 0
	}
	if o.Congestion == (congestion.Profile{}) {
		o.Congestion = congestion.ProfileConservative
	}
	return o
}

// association is one association as this end keeps it.
//
// Each direction has its own key ring and packet numbers and is driven by one
// goroutine: the send side by whoever sends, serialized by sendMu because packet
// numbers must leave in the order they were assigned, and the receive side by
// the one goroutine that reads the socket.
type association struct {
	localConnID connectionID
	peerConnID  connectionID
	keyID       [keyIDLen]byte
	conn        net.PacketConn
	options     Options
	ctx         context.Context
	cancel      context.CancelCauseFunc

	// peerAddr is where the peer is now. Whoever sends reads it, so it is an
	// atomic rather than a field under sendMu.
	peerAddr atomic.Pointer[net.Addr]

	sendMu      sync.Mutex
	sendRing    keyRing
	sendPacket  uint32
	sendBuffer  []byte
	buildBuffer []byte
	queue       frameQueue

	recvRing keyRing

	// idleTimer closes the association when it falls silent. It is reset from
	// both sides.
	idleTimer *time.Timer

	// ackMu guards the receive side's acknowledgement state, which is driven by
	// the goroutine that reads the socket and by the timer that sends a delayed
	// acknowledgement.
	ackMu    sync.Mutex
	ack      ackScheduler
	ackTimer *time.Timer

	// flightMu guards the packets in flight and the round trip estimate. The
	// send path records a packet as it leaves and the receive path takes it out
	// again when an acknowledgement covers it, so both sides need the lock; it is
	// never held while a packet is being sent, because sending takes sendMu and
	// holding both in the other order is how two paths deadlock.
	flightMu sync.Mutex
	inFlight sentPackets
	rtt      rttEstimator
	// probes counts the probes that went unanswered, which is what the wait
	// before the next one doubles with.
	probes   int
	ptoTimer *time.Timer

	// ccMu is the innermost lock: the congestion controller is called with it held,
	// after the send lock or the flight lock, never around them.
	ccMu      sync.Mutex
	cc        congestion.Controller
	rttStats  rttSnapshot
	paceTimer *time.Timer

	// streamsMu guards the streams of the association. The table is what turns a
	// stream id on the wire into a stream, and what bounds how many the peer may
	// have open at once.
	streamsMu    sync.Mutex
	streams      map[uint32]*Stream
	endedStreams endedStreams
	acceptStream chan *Stream
	nextStreamID uint32

	// datagramMu guards the datagram side: the message numbers this end hands
	// out, the reassemblies in progress, and the messages waiting for the
	// application. A datagram carries no promise, so nothing here waits for
	// anything: what does not fit is dropped.
	datagramMu      sync.Mutex
	datagramMessage uint16
	defragger       datagramDefragger
	datagrams       chan Datagram

	// fcMu guards the association window: what the peer allows this end to send,
	// and what this end allows the peer to send.
	fcMu         sync.Mutex
	sendCredit   credit
	recvLimit    uint64
	recvRead     uint64
	recvReceived uint64

	// isClient says which half of the protocol this association is. It is what
	// stream ids are built from and what tells an incoming stream id apart from an
	// outgoing one.
	isClient bool

	// ownsConn says whether closing the association closes the socket. A client
	// owns the socket it dialled on; a server association writes on the socket
	// its listener accepts on.
	ownsConn bool

	onClose   func()
	closeOnce sync.Once
}

func newAssociation(conn net.PacketConn, result handshakeResult, peer net.Addr, options Options, isClient, ownsConn bool) *association {
	ctx, cancel := context.WithCancelCause(context.Background())
	a := &association{
		localConnID:  result.localConnID,
		peerConnID:   result.peerConnID,
		keyID:        result.keyID,
		conn:         conn,
		options:      options.withDefaults(),
		ctx:          ctx,
		cancel:       cancel,
		sendRing:     result.send,
		recvRing:     result.recv,
		sendBuffer:   make([]byte, 0, maxPacketSize),
		streams:      make(map[uint32]*Stream),
		acceptStream: make(chan *Stream, acceptStreamBacklog),
		defragger:    newDatagramDefragger(),
		datagrams:    make(chan Datagram, datagramBacklog),
		sendCredit:   credit{limit: initialConnectionWindow},
		recvLimit:    initialConnectionWindow,
		isClient:     isClient,
		ownsConn:     ownsConn,
	}
	a.peerAddr.Store(&peer)
	a.idleTimer = time.AfterFunc(a.options.IdleTimeout, func() {
		a.shutdown(ErrIdleTimeout, true)
	})
	a.ackTimer = time.AfterFunc(maxAckDelay, a.flushAck)
	a.ptoTimer = time.AfterFunc(initialPTO, a.probe)
	a.ptoTimer.Stop()
	a.cc = newCongestionController(a.options)
	a.cc.SetRTTStatsProvider(&a.rttStats)
	a.paceTimer = time.AfterFunc(time.Hour, func() { _ = a.flush() })
	a.paceTimer.Stop()
	if a.options.KeepAlivePeriod > 0 {
		go a.keepAliveLoop()
	}
	return a
}

func (a *association) LocalAddr() net.Addr {
	return a.conn.LocalAddr()
}

func (a *association) RemoteAddr() net.Addr {
	return *a.peerAddr.Load()
}

func (a *association) Context() context.Context {
	return a.ctx
}

func (a *association) KeyID() [keyIDLen]byte {
	return a.keyID
}

func (a *association) CloseWithError(err error) error {
	a.shutdown(err, true)
	return nil
}

// shutdown ends the association once. Announcing the close to the peer is best
// effort: an association that ended is gone whether or not the peer heard.
func (a *association) shutdown(cause error, notifyPeer bool) {
	a.closeOnce.Do(func() {
		if cause == nil {
			cause = net.ErrClosed
		}
		if notifyPeer {
			_ = a.send(appendClose(nil, closeCodeOf(cause)))
		}
		a.idleTimer.Stop()
		a.ackTimer.Stop()
		a.ptoTimer.Stop()
		a.paceTimer.Stop()
		a.cancel(cause)
		a.closeStreams(cause)
		if a.ownsConn {
			_ = a.conn.Close()
		}
		if a.onClose != nil {
			a.onClose()
		}
	})
}

// send queues one encoded frame and sends what can go out now.
func (a *association) send(frame []byte) error {
	select {
	case <-a.ctx.Done():
		return context.Cause(a.ctx)
	default:
	}
	a.queueFrame(frame)
	return a.flush()
}

// queueFrame places a frame at the end of the send queue, which takes its bytes
// over. Frames queued before a flush share a packet, which is what keeps an
// acknowledgement from costing a packet next to data that is going out anyway.
func (a *association) queueFrame(frame []byte) {
	entry := outFrame{
		payload:      frame,
		ackEliciting: frameType(frame[0]) != frameTypeAck,
	}
	a.sendMu.Lock()
	if entry.ackEliciting {
		a.queue.push(entry)
	} else {
		// An acknowledgement goes ahead of what is already queued: it is what
		// lets the peer send anything at all, and data that waits one packet
		// longer costs less than an acknowledgement that waits behind a window.
		a.queue.pushFront([]outFrame{entry})
	}
	a.sendMu.Unlock()
}

// handlePacket processes a packet the demultiplexer routed to this association.
// An error means the packet was dropped, which is not the caller's business: a
// packet that does not parse or does not authenticate is indistinguishable from
// one an off-path attacker sent.
func (a *association) handlePacket(packet []byte, source net.Addr) error {
	packetHeader, err := parseHeader(packet)
	if err != nil {
		return err
	}
	if packetHeader.ConnectionID != a.localConnID {
		return errAuthentication
	}
	if packetHeader.Type == packetTypeReset {
		return a.handleReset(packet, source)
	}
	_, _, payload, err := a.recvRing.open(packet)
	if err != nil {
		return err
	}
	// The packet authenticated, so it is the peer's, wherever it came from: a
	// peer that rebinds its NAT is the same peer.
	a.peerAddr.Store(&source)
	a.resetIdle()
	ackEliciting := false
	for len(payload) > 0 {
		var f frame
		f, payload, err = nextFrame(payload)
		if err != nil {
			a.shutdown(err, true)
			return err
		}
		switch f.frameType {
		case frameTypePing:
			ackEliciting = true
		case frameTypeClose:
			a.shutdown(f.closeCode().err(), false)
			return nil
		case frameTypeAck:
			a.handleAck(f.body, time.Now())
		case frameTypeStream:
			ackEliciting = true
			err = a.handleStreamFrame(f.stream())
			if err != nil {
				a.shutdown(err, true)
				return err
			}
		case frameTypeMaxData:
			ackEliciting = true
			a.handleMaxData(binary.BigEndian.Uint64(f.body))
		case frameTypeMaxStreamData:
			ackEliciting = true
			a.handleMaxStreamData(binary.BigEndian.Uint32(f.body), binary.BigEndian.Uint64(f.body[4:]))
		case frameTypeResetStream:
			ackEliciting = true
			a.handleResetStream(f.streamReset())
		case frameTypeDatagram:
			ackEliciting = true
			err = a.handleDatagram(f.datagram())
			if err != nil {
				a.shutdown(err, true)
				return err
			}
		}
	}
	if ackEliciting {
		a.scheduleAck(packetHeader.PacketNumber, time.Now())
	}
	return nil
}

// scheduleAck records an ack-eliciting packet and acknowledges it now or after
// the delay, whichever the policy asks for.
func (a *association) scheduleAck(packetNumber uint32, now time.Time) {
	a.ackMu.Lock()
	immediate := a.ack.received(packetNumber, now)
	var acknowledgement []byte
	if immediate {
		acknowledgement = a.ack.pack(now)
	}
	a.ackMu.Unlock()
	if immediate {
		if len(acknowledgement) > 0 {
			_ = a.send(acknowledgement)
		}
		return
	}
	a.ackTimer.Reset(maxAckDelay)
}

// flushAck sends the acknowledgement the delay was waiting for.
func (a *association) flushAck() {
	a.ackMu.Lock()
	acknowledgement := a.ack.pack(time.Now())
	a.ackMu.Unlock()
	if len(acknowledgement) == 0 {
		return
	}
	_ = a.send(acknowledgement)
}

// roundTrip returns the current round trip estimate.
func (a *association) roundTrip() (time.Duration, bool) {
	a.flightMu.Lock()
	defer a.flightMu.Unlock()
	if !a.rtt.sampled {
		return 0, false
	}
	return a.rtt.smoothed, true
}

// handleReset accepts a reset packet, the one packet type that is not
// authenticated: it exists for a peer that has already dropped the keys.
//
// What keeps an off-path attacker from resetting every association is that the
// packet has to carry the connection id of an association this end knows and
// come from the address the peer is at. Both are visible to anyone on the path,
// so a reset is a signal rather than a proof, which is the trade QUIC makes as
// well.
func (a *association) handleReset(packet []byte, source net.Addr) error {
	if len(packet) != headerLen+resetLen {
		return errShortPacket
	}
	if source.String() != a.RemoteAddr().String() {
		return E.New("reset from ", source)
	}
	a.shutdown(ErrStatelessReset, false)
	return nil
}

func (a *association) resetIdle() {
	a.idleTimer.Reset(a.options.IdleTimeout)
}

func (a *association) keepAliveLoop() {
	ticker := time.NewTicker(a.options.KeepAlivePeriod)
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			err := a.send(appendPing(nil))
			if err != nil {
				return
			}
		}
	}
}

// Dial opens a client association on conn. The association owns the socket from
// then on and closes it when it ends.
func Dial(ctx context.Context, conn net.PacketConn, remote net.Addr, credential Credential, options Options) (Association, error) {
	if _, loaded := ctx.Deadline(); !loaded {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultHandshakeTimeout)
		defer cancel()
	}
	handshake, err := newClientHandshake(credential)
	if err != nil {
		return nil, err
	}
	result, err := exchangeHello(ctx, conn, remote, handshake)
	if err != nil {
		return nil, err
	}
	a := newAssociation(conn, result, remote, options, true, true)
	go a.readLoop()
	return a, nil
}

// exchangeHello sends the hello until an answer that verifies arrives.
func exchangeHello(ctx context.Context, conn net.PacketConn, remote net.Addr, handshake *clientHandshake) (handshakeResult, error) {
	buffer := make([]byte, maxPacketSize)
	hello := handshake.hello()
	for {
		_, err := conn.WriteTo(hello, remote)
		if err != nil {
			return handshakeResult{}, E.Cause(err, "write hello")
		}
		deadline := time.Now().Add(helloRetransmitInterval)
		if contextDeadline, loaded := ctx.Deadline(); loaded && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		err = conn.SetReadDeadline(deadline)
		if err != nil {
			return handshakeResult{}, E.Cause(err, "set read deadline")
		}
		for {
			n, source, readErr := conn.ReadFrom(buffer)
			if readErr != nil {
				select {
				case <-ctx.Done():
					return handshakeResult{}, context.Cause(ctx)
				default:
				}
				if isTimeout(readErr) {
					break
				}
				return handshakeResult{}, E.Cause(readErr, "read hello answer")
			}
			if source.String() != remote.String() {
				continue
			}
			packetHeader, parseErr := parseHeader(buffer[:n])
			if parseErr != nil || packetHeader.Type != packetTypeHandshake {
				continue
			}
			result, handleErr := handshake.handleResponse(buffer[:n])
			if handleErr != nil {
				// An answer that does not verify is not the server's. It is
				// dropped as silently as the server drops a hello it cannot
				// verify.
				continue
			}
			err = conn.SetReadDeadline(time.Time{})
			if err != nil {
				return handshakeResult{}, E.Cause(err, "clear read deadline")
			}
			return result, nil
		}
	}
}

// readLoop is the receive side of a client association, which owns its socket.
func (a *association) readLoop() {
	buffer := make([]byte, maxPacketSize)
	for {
		n, source, err := a.conn.ReadFrom(buffer)
		if err != nil {
			if isClosed(err) {
				a.shutdown(err, false)
				return
			}
			continue
		}
		_ = a.handlePacket(buffer[:n], source)
	}
}

func isTimeout(err error) bool {
	netErr, isNetErr := err.(net.Error)
	return isNetErr && netErr.Timeout()
}

func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed)
}
