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
	"github.com/sagernet/sing-quic/udpio"

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
	// Offload reports whether this end batches in each direction: segmentation
	// on send and merged reads on receive. It is here because the batching is
	// decided by what the socket underneath is, and the decision is silent: a
	// socket wrapped in something that hides its descriptor moves one datagram
	// per call, and nothing about that is visible from anywhere else.
	Offload() (gso, gro bool)
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

	// maxReceiveSize is how much one read may take. A datagram is at most 64 KiB
	// including its headers, and a socket that merges datagrams hands up a run of
	// them in one buffer, so the buffer has to hold a whole run: one that is too
	// small truncates the last datagram of it.
	maxReceiveSize = 64 * 1024

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
	// is the default one (defaultCongestionProfile).
	Congestion congestion.Profile

	// FEC is the forward error correction applied to what this end sends. It
	// protects one direction only, so an association that should survive a lossy
	// path in both directions sets it on both ends.
	FEC FECOptions
}

// FECOptions is how a sender protects its packets with forward error correction.
//
// A group is a fixed number of packets and the redundancy that covers them, and
// the cost of it is the redundancy: what a group buys is that a lost member is
// recovered from the parity that already arrived instead of waiting a round trip
// for a retransmission. The number of members is a constant of the sender, while
// the redundancy follows the loss it sees, because a path that loses nothing has
// nothing to replace.
type FECOptions struct {
	// DataShards is how many packets a group holds. Zero disables forward error
	// correction.
	DataShards int

	// ParityShards is how many redundant packets a group gets, up to the number of
	// members. Zero leaves it to the losses the path is showing.
	ParityShards int
}

func (o Options) withDefaults() Options {
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = defaultIdleTimeout
	}
	if o.KeepAlivePeriod < 0 {
		o.KeepAlivePeriod = 0
	}
	if o.Congestion == (congestion.Profile{}) {
		o.Congestion = defaultCongestionProfile
	}
	return o
}

// associationTimers is what an association wakes up on.
//
// The four belong together because a timer that fires runs into the association
// and arms one of the others: a retransmission is paced, an acknowledgement is
// sent, a probe rearms itself. They are therefore built as one set, before any of
// them can fire, and the set is what the association hands out.
type associationTimers struct {
	// idle closes the association when it falls silent. It is reset from both
	// sides.
	idle *time.Timer
	// ack sends the acknowledgement the delay was holding back.
	ack *time.Timer
	// pto asks the peer about the oldest packet in flight.
	pto *time.Timer
	// pace wakes the send path when the pacing rate allows the next batch.
	pace *time.Timer
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

	sendMu     sync.Mutex
	sendRing   keyRing
	sendPacket uint32
	// batchIO moves the packets of one batch in as few calls as the socket
	// allows. batch is the one being filled; written carries it to the write loop
	// once it is full, and freeBatches carries it back once the socket has taken
	// it. What is written here is what is in flight, so a batch that is on its way
	// into the socket already counts against the window.
	batchIO     udpio.Conn
	batch       *batch
	written     chan *batch
	freeBatches chan *batch
	// writing counts the batches the write loop has been handed and has not
	// written yet, which is what closing waits for before it takes the socket
	// away: the close of an association is heard by its peer.
	writingMu sync.Mutex
	writing   int
	writeStop chan struct{}
	writeDone chan struct{}
	// sealNonce is the nonce of the packet being sealed, reused: twelve bytes per
	// packet is a third of what sealing one costs.
	sealNonce [nonceLen]byte
	queue     frameQueue
	// maxPayload is how many payload bytes a packet may carry, which is smaller
	// than what the MTU allows once this end protects its packets: the parity
	// shards and the description in their headers have to fit as well.
	maxPayload int
	// fecSender assembles the groups this end sends, or nil when it sends none.
	fecSender *fecSender

	recvRing keyRing
	// fec assembles the groups the peer sends. It belongs to the receive side and
	// needs no lock of its own.
	fec fecReceiver

	// timers are the timers of an association, in one place because a timer that
	// fires reads them: they are built with the association and never change, so
	// the pointer is what is shared rather than four fields being assigned one
	// after another while the first of them may already be running.
	timers atomic.Pointer[associationTimers]

	// ackMu guards the receive side's acknowledgement state, which is driven by
	// the goroutine that reads the socket and by the timer that sends a delayed
	// acknowledgement.
	ackMu sync.Mutex
	ack   ackScheduler

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
	probes int

	// ccMu is the innermost lock: the congestion controller is called with it held,
	// after the send lock or the flight lock, never around them.
	ccMu     sync.Mutex
	cc       congestion.Controller
	rttStats rttSnapshot

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
	// and what this end allows the peer to send. recvWindow is how large that
	// credit is, which starts at initialConnectionWindow and doubles while the
	// streams together are what fills it. recvLimit is the ceiling the peer was last
	// told about and recvLimitWas the one before it, for the reason a stream keeps
	// both: the peer's last packet arrives after the ceiling it knew may have been
	// replaced.
	fcMu         sync.Mutex
	sendCredit   credit
	recvLimit    uint64
	recvLimitWas uint64
	recvWindow   uint64
	windowSpent  bool
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
		batchIO:      udpio.New(conn, udpio.Options{GRO: true}),
		freeBatches:  make(chan *batch, writeBatchSlots),
		written:      make(chan *batch, writeBatchSlots),
		writeStop:    make(chan struct{}),
		writeDone:    make(chan struct{}),
		maxPayload:   maxPacketSize - headerLen - tagLen,
		fecSender:    newFECSender(options.FEC),
		fec:          newFECReceiver(),
		streams:      make(map[uint32]*Stream),
		acceptStream: make(chan *Stream, acceptStreamBacklog),
		defragger:    newDatagramDefragger(),
		datagrams:    make(chan Datagram, datagramBacklog),
		sendCredit:   credit{limit: initialConnectionWindow},
		recvLimit:    initialConnectionWindow,
		recvWindow:   initialConnectionWindow,
		isClient:     isClient,
		ownsConn:     ownsConn,
	}
	// The controller comes first: a timer that fires before it exists would send
	// through a half built association, and the idle timer is armed with the
	// configured timeout, which may be short enough to win the race.
	a.cc = newCongestionController(a.options)
	a.cc.SetRTTStatsProvider(&a.rttStats)
	if a.fecSender != nil {
		a.maxPayload = a.fecSender.payloadBudget()
		a.fecSender.timer = time.AfterFunc(time.Hour, a.flushFECGroup)
		a.fecSender.timer.Stop()
	}
	a.peerAddr.Store(&peer)
	// The batches come before the loop that uses them, and the loop comes last: a
	// timer that fired before the association was complete would hand over a batch
	// nothing is there to write.
	for range writeBatchSlots {
		a.freeBatches <- newBatch()
	}
	a.batch = <-a.freeBatches
	// Every timer starts out a hour away and is armed once the pointer to the set
	// is in place: a timer whose callback runs before the association has finished
	// building itself would read fields that nothing has written yet.
	timers := &associationTimers{
		idle: time.AfterFunc(time.Hour, func() { a.shutdown(ErrIdleTimeout, true) }),
		ack:  time.AfterFunc(time.Hour, a.flushAck),
		pto:  time.AfterFunc(time.Hour, a.probe),
		pace: time.AfterFunc(time.Hour, func() { _ = a.flush() }),
	}
	timers.ack.Stop()
	timers.pto.Stop()
	timers.pace.Stop()
	a.timers.Store(timers)
	timers.idle.Reset(a.options.IdleTimeout)
	go a.writeLoop()
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

func (a *association) Offload() (gso, gro bool) {
	return a.batchIO.Offload()
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
			// The close packet goes to the socket behind whatever was handed over
			// before it, so the socket waits for the write loop before it is taken
			// away: an association that ends is one whose peer heard why.
			a.drainWrites()
		}
		timers := a.timers.Load()
		timers.idle.Stop()
		timers.ack.Stop()
		timers.pto.Stop()
		timers.pace.Stop()
		if a.fecSender != nil {
			a.fecSender.timer.Stop()
		}
		a.cancel(cause)
		a.closeStreams(cause)
		// The write loop stops once the socket is gone: closing it is what wakes a
		// write that is waiting for room, and the loop is what a stuck write would
		// otherwise keep alive.
		close(a.writeStop)
		if a.ownsConn {
			_ = a.conn.Close()
		}
		select {
		case <-a.writeDone:
		case <-time.After(writeDrainTimeout):
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

// queueStreamFrame places a stream frame at the end of the send queue. The bytes it
// carries are the ones the application wrote, so the frame holds the piece of the
// send buffer rather than a copy of it, and the piece is what a retransmission
// sends again.
func (a *association) queueStreamFrame(frame streamFrame) {
	a.sendMu.Lock()
	a.queue.push(outFrame{
		stream:       frame,
		ackEliciting: true,
	})
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
	if packetHeader.Type == packetTypeFEC {
		return a.handleParity(packet, packetHeader, source)
	}
	if packetHeader.Type == packetTypeData && a.fec.active {
		// The packet is kept before it is opened, which is what makes it
		// recoverable: what a member is recovered as is the bytes the sender
		// wrote, and the ones in this buffer are about to be decrypted in place.
		a.fec.remember(packetHeader.PacketNumber, packet)
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
	a.timers.Load().ack.Reset(a.ackDelay())
}

// ackDelay is how long an acknowledgement waits for the packet that would reach
// the threshold: an eighth of the round trip, so that what the wait costs is a
// fraction of it.
//
// The delay is what a sender waits for when its window holds fewer packets than
// the threshold, and that wait is on top of the round trip the sender needs to
// spend the window. A constant delay is therefore a constant multiple of the
// round trip on a fast path: a millisecond path whose window holds fewer packets
// than the threshold sends that many and then idles for twenty-five round trips.
// On a path long enough for the cap to be the smaller term the delay is the cap,
// which is what the loss timer accounts for.
func (a *association) ackDelay() time.Duration {
	rtt, measured := a.roundTrip()
	if !measured {
		return maxAckDelay
	}
	return min(maxAckDelay, max(minAckDelay, rtt/8))
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

// handleParity takes one parity shard of a group the peer sent, recovers whatever
// the group is missing, and hands every recovered packet to the ordinary receive
// path.
//
// That is the whole promise of the packet number being in the clear: a recovered
// member is the bytes the sender wrote, so it authenticates, opens and is
// acknowledged like a packet that arrived on its own, and the acknowledgement is
// what tells the sender it does not have to send it again.
func (a *association) handleParity(packet []byte, packetHeader header, source net.Addr) error {
	_, description, payload, err := a.recvRing.open(packet)
	if err != nil {
		return err
	}
	if description == nil {
		return errShortPacket
	}
	a.peerAddr.Store(&source)
	a.resetIdle()
	recovered := a.fec.parity(description, payload)
	for _, member := range recovered {
		packetHeader, headerErr := parseHeader(member)
		if headerErr != nil {
			continue
		}
		if a.wasReceived(packetHeader.PacketNumber) {
			// The member did arrive, before the group was assembled and outside
			// the window the group was filled from. Delivering the recovered copy
			// would deliver the same frames a second time.
			continue
		}
		_ = a.handlePacket(member, source)
	}
	// Parity is ack-eliciting like anything else: it takes room in flight, and a
	// packet in flight that nothing acknowledges is a packet that keeps the window
	// closed until the association ends.
	a.scheduleAck(packetHeader.PacketNumber, time.Now())
	return nil
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
	a.timers.Load().idle.Reset(a.options.IdleTimeout)
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
	buffer := make([]byte, maxReceiveSize)
	for {
		packets, err := a.batchIO.ReadPackets([][]byte{buffer})
		if err != nil {
			if isClosed(err) {
				a.shutdown(err, false)
				return
			}
			continue
		}
		for _, packet := range packets {
			packet.ForEach(func(datagram []byte) {
				_ = a.handlePacket(datagram, packet.Addr)
			})
		}
	}
}

func isTimeout(err error) bool {
	netErr, isNetErr := err.(net.Error)
	return isNetErr && netErr.Timeout()
}

func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed)
}
