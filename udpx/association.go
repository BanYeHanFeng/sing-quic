package udpx

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

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
}

func (o Options) withDefaults() Options {
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = defaultIdleTimeout
	}
	if o.KeepAlivePeriod < 0 {
		o.KeepAlivePeriod = 0
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
	sendBuffer []byte

	recvRing keyRing

	// idleTimer closes the association when it falls silent. It is reset from
	// both sides.
	idleTimer *time.Timer

	// ownsConn says whether closing the association closes the socket. A client
	// owns the socket it dialled on; a server association writes on the socket
	// its listener accepts on.
	ownsConn bool

	onClose   func()
	closeOnce sync.Once
}

func newAssociation(conn net.PacketConn, result handshakeResult, peer net.Addr, options Options, ownsConn bool) *association {
	ctx, cancel := context.WithCancelCause(context.Background())
	a := &association{
		localConnID: result.localConnID,
		peerConnID:  result.peerConnID,
		conn:        conn,
		options:     options.withDefaults(),
		ctx:         ctx,
		cancel:      cancel,
		sendRing:    result.send,
		recvRing:    result.recv,
		sendBuffer:  make([]byte, 0, maxPacketSize),
		ownsConn:    ownsConn,
	}
	a.peerAddr.Store(&peer)
	a.idleTimer = time.AfterFunc(a.options.IdleTimeout, func() {
		a.shutdown(ErrIdleTimeout, true)
	})
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
			_ = a.sendPayload(appendClose(nil, closeCodeOf(cause)))
		}
		a.idleTimer.Stop()
		a.cancel(cause)
		if a.ownsConn {
			_ = a.conn.Close()
		}
		if a.onClose != nil {
			a.onClose()
		}
	})
}

// sendPayload sends payload in a packet of its own.
func (a *association) sendPayload(payload []byte) error {
	select {
	case <-a.ctx.Done():
		return context.Cause(a.ctx)
	default:
	}
	if headerLen+len(payload)+tagLen > maxPacketSize {
		return E.New("payload of ", len(payload), " bytes does not fit in a packet")
	}
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	h := header{
		ConnectionID: a.peerConnID,
		Type:         packetTypeData,
		Epoch:        a.sendRing.epoch(),
		PacketNumber: a.sendPacket,
	}
	a.sendPacket++
	packet, err := a.sendRing.seal(a.sendBuffer[:0], h, nil, payload)
	if err != nil {
		return err
	}
	a.sendBuffer = packet
	_, err = a.conn.WriteTo(packet, a.RemoteAddr())
	if err != nil {
		return E.Cause(err, "write packet")
	}
	a.resetIdle()
	return nil
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
	for len(payload) > 0 {
		var f frame
		f, payload, err = nextFrame(payload)
		if err != nil {
			a.shutdown(err, true)
			return err
		}
		switch f.frameType {
		case frameTypePing:
			// It carries nothing, and the idle timer was already reset.
		case frameTypeClose:
			a.shutdown(f.closeCode.err(), false)
		}
	}
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
			err := a.sendPayload(appendPing(nil))
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
	a := newAssociation(conn, result, remote, options, true)
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
