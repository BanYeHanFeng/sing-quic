package udpx

import (
	"bytes"
	"context"
	"net"
	"sync"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	// maxConcurrentHandshakes bounds the handshakes a listener runs at once. A
	// hello is authenticated with a deliberately expensive derivation, so an
	// unbounded number of them would be an unbounded amount of work; a hello
	// that is dropped costs the client nothing, because it sends the same one
	// again.
	maxConcurrentHandshakes = 8

	// acceptBacklog is how many associations may wait for Accept.
	acceptBacklog = 16
)

// Listener accepts associations on a socket.
//
// One socket carries every association: a packet names the association it
// belongs to in its clear header, so demultiplexing is a map lookup on the
// connection id and needs nothing of the payload.
type Listener struct {
	conn        net.PacketConn
	verifier    Verifier
	options     Options
	ctx         context.Context
	cancel      context.CancelCauseFunc
	accept      chan *association
	handshaking chan struct{}

	mu           sync.Mutex
	associations map[connectionID]*association

	closeOnce sync.Once
}

// ListenPacket accepts associations on conn and owns the socket from then on:
// closing the listener closes it.
func ListenPacket(conn net.PacketConn, verifier Verifier, options Options) *Listener {
	ctx, cancel := context.WithCancelCause(context.Background())
	l := &Listener{
		conn:         conn,
		verifier:     verifier,
		options:      options.withDefaults(),
		ctx:          ctx,
		cancel:       cancel,
		accept:       make(chan *association, acceptBacklog),
		handshaking:  make(chan struct{}, maxConcurrentHandshakes),
		associations: make(map[connectionID]*association),
	}
	go l.readLoop()
	return l
}

// Accept returns the next association a client completed a handshake for.
func (l *Listener) Accept(ctx context.Context) (Association, error) {
	select {
	case a := <-l.accept:
		return a, nil
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-l.ctx.Done():
		return nil, context.Cause(l.ctx)
	}
}

func (l *Listener) Close() error {
	l.shutdown(net.ErrClosed)
	return nil
}

func (l *Listener) shutdown(cause error) {
	l.closeOnce.Do(func() {
		l.cancel(cause)
		_ = l.conn.Close()
		l.mu.Lock()
		associations := l.associations
		l.associations = make(map[connectionID]*association)
		l.mu.Unlock()
		for _, a := range associations {
			a.shutdown(cause, false)
		}
	})
}

// readLoop reads the socket and routes every packet by its connection id. Every
// packet it cannot place is dropped without an answer.
func (l *Listener) readLoop() {
	buffer := make([]byte, maxPacketSize)
	for {
		n, source, err := l.conn.ReadFrom(buffer)
		if err != nil {
			if isClosed(err) {
				l.shutdown(err)
				return
			}
			continue
		}
		packetHeader, err := parseHeader(buffer[:n])
		if err != nil {
			continue
		}
		if packetHeader.Type == packetTypeHandshake {
			// A hello is answered by the handshake goroutine, which needs the
			// bytes after this one has been replaced in the buffer.
			l.handleHello(bytes.Clone(buffer[:n]), source)
			continue
		}
		l.dispatch(packetHeader, buffer[:n], source)
	}
}

func (l *Listener) dispatch(packetHeader header, packet []byte, source net.Addr) {
	l.mu.Lock()
	a := l.associations[packetHeader.ConnectionID]
	l.mu.Unlock()
	if a == nil {
		// A packet for a connection id this end knows nothing about is dropped
		// without an answer, which is also what a prober gets from the port.
		return
	}
	_ = a.handlePacket(packet, source)
}

func (l *Listener) handleHello(hello []byte, source net.Addr) {
	select {
	case l.handshaking <- struct{}{}:
	default:
		return
	}
	go func() {
		defer func() { <-l.handshaking }()
		l.completeHandshake(hello, source)
	}()
}

// completeHandshake verifies a hello and turns it into an association. A hello
// that does not authenticate leaves nothing behind, which is what makes a
// replay of one worthless.
func (l *Listener) completeHandshake(hello []byte, source net.Addr) {
	handshake, err := newServerHandshake(hello, l.verifier)
	if err != nil {
		return
	}
	result, err := handshake.keys()
	if err != nil {
		return
	}
	a := newAssociation(l.conn, result, source, l.options, false)
	a.onClose = func() {
		l.remove(a.localConnID)
	}
	if !l.add(a) {
		a.shutdown(net.ErrClosed, false)
		return
	}
	_, err = l.conn.WriteTo(handshake.hello(), source)
	if err != nil {
		a.shutdown(err, false)
		return
	}
	select {
	case l.accept <- a:
	default:
		a.shutdown(E.New("accept queue is full"), true)
	}
}

func (l *Listener) add(a *association) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.ctx.Done():
		return false
	default:
	}
	if _, loaded := l.associations[a.localConnID]; loaded {
		return false
	}
	l.associations[a.localConnID] = a
	return true
}

func (l *Listener) remove(connID connectionID) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if a, loaded := l.associations[connID]; loaded && a.localConnID == connID {
		delete(l.associations, connID)
	}
}
