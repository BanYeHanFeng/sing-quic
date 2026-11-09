package udpx

import (
	"bytes"
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-quic/udpio"

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

	// helloLifetime is how long the answer to a hello is kept, so that the hello a
	// client repeats while the answer is on its way costs a write rather than a
	// handshake.
	//
	// A client repeats its hello every 250 ms until it hears an answer, which is
	// what covers a lost hello or a lost answer; what it does not know is that the
	// answer is computed, not read, and that computing it is the expensive part of
	// the protocol. Measured over ten hours of a proxied phone: eight dials left a
	// hundred and seventeen associations behind, because every repetition of the
	// hello was answered with a new one, and the eight handshakes the listener runs
	// at once were all hashing the same password while the client waited. The
	// lifetime is the one the client gives up after, so an answer that arrives late
	// is still answered with the answer it was waiting for.
	helloLifetime = 10 * time.Second
)

// Listener accepts associations on a socket.
//
// One socket carries every association: a packet names the association it
// belongs to in its clear header, so demultiplexing is a map lookup on the
// connection id and needs nothing of the payload.
type Listener struct {
	conn        net.PacketConn
	batchIO     udpio.Conn
	verifier    Verifier
	options     Options
	ctx         context.Context
	cancel      context.CancelCauseFunc
	accept      chan *association
	handshaking chan struct{}

	mu           sync.Mutex
	associations map[connectionID]*association
	// hellos is the answer each client's hello was answered with, by the client's
	// own connection id, which is the one thing a repeated hello carries that the
	// first one did too. An entry whose answer is nil is a handshake still being
	// computed: the repetitions that arrive meanwhile are dropped rather than
	// hashed again, because the answer being computed is the answer for all of
	// them.
	hellos map[connectionID]*helloAnswer

	closeOnce sync.Once
}

// helloAnswer is what a client hello was answered with, and when that was.
type helloAnswer struct {
	packet []byte
	at     time.Time
}

// ListenPacket accepts associations on conn and owns the socket from then on:
// closing the listener closes it.
func ListenPacket(conn net.PacketConn, verifier Verifier, options Options) *Listener {
	ctx, cancel := context.WithCancelCause(context.Background())
	l := &Listener{
		conn:         conn,
		batchIO:      udpio.New(conn, udpio.Options{GRO: true}),
		verifier:     verifier,
		options:      options.withDefaults(),
		ctx:          ctx,
		cancel:       cancel,
		accept:       make(chan *association, acceptBacklog),
		handshaking:  make(chan struct{}, maxConcurrentHandshakes),
		associations: make(map[connectionID]*association),
		hellos:       make(map[connectionID]*helloAnswer),
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
		l.hellos = make(map[connectionID]*helloAnswer)
		l.mu.Unlock()
		for _, a := range associations {
			a.shutdown(cause, false)
		}
	})
}

// readLoop reads the socket and routes every packet by its connection id. Every
// packet it cannot place is dropped without an answer.
func (l *Listener) readLoop() {
	buffer := make([]byte, maxReceiveSize)
	for {
		packets, err := l.batchIO.ReadPackets([][]byte{buffer})
		if err != nil {
			if isClosed(err) {
				l.shutdown(err)
				return
			}
			continue
		}
		for _, packet := range packets {
			packet.ForEach(func(datagram []byte) {
				packetHeader, err := parseHeader(datagram)
				if err != nil {
					return
				}
				if packetHeader.Type == packetTypeHandshake {
					// A hello is answered by the handshake goroutine, which needs the
					// bytes after this one has been replaced in the buffer.
					l.handleHello(packetHeader.ConnectionID, bytes.Clone(datagram), packet.Addr)
					return
				}
				l.dispatch(packetHeader, datagram, packet.Addr)
			})
		}
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

// handleHello answers a hello, or the same hello again.
//
// The client's connection id is what tells the two apart: a client repeats the
// hello it already sent, byte for byte, so the id it carries is the id of the
// handshake that is already running or already answered. One that is running is
// dropped — the answer being computed is the answer for this copy too — and one
// that was answered is answered with the same bytes, which the client verifies
// against the hello it sent and cannot tell from the first answer.
func (l *Listener) handleHello(clientConnID connectionID, hello []byte, source net.Addr) {
	now := time.Now()
	l.mu.Lock()
	answer, loaded := l.hellos[clientConnID]
	if loaded && now.Sub(answer.at) < helloLifetime {
		l.mu.Unlock()
		if answer.packet != nil {
			_, _ = l.conn.WriteTo(answer.packet, source)
		}
		return
	}
	answer = &helloAnswer{at: now}
	l.hellos[clientConnID] = answer
	l.mu.Unlock()
	select {
	case l.handshaking <- struct{}{}:
	default:
		l.forgetHello(clientConnID, answer)
		return
	}
	go func() {
		defer func() { <-l.handshaking }()
		l.completeHandshake(clientConnID, answer, hello, source)
	}()
}

// forgetHello drops what a hello left behind when the handshake did not produce an
// answer to keep.
func (l *Listener) forgetHello(clientConnID connectionID, answer *helloAnswer) {
	l.mu.Lock()
	if l.hellos[clientConnID] == answer {
		delete(l.hellos, clientConnID)
	}
	l.mu.Unlock()
}

// keepHello records the answer a hello was answered with, so that a repetition of
// that hello costs a write. The entry is dropped when it is older than the client
// would still be waiting for it.
func (l *Listener) keepHello(clientConnID connectionID, answer *helloAnswer, packet []byte) {
	l.mu.Lock()
	if l.hellos[clientConnID] != answer {
		l.mu.Unlock()
		return
	}
	answer.packet = packet
	answer.at = time.Now()
	l.mu.Unlock()
	time.AfterFunc(helloLifetime, func() {
		l.forgetHello(clientConnID, answer)
	})
}

// completeHandshake verifies a hello and turns it into an association. A hello
// that does not authenticate leaves nothing behind, which is what makes a
// replay of one worthless.
func (l *Listener) completeHandshake(clientConnID connectionID, answer *helloAnswer, hello []byte, source net.Addr) {
	handshake, err := newServerHandshake(hello, l.verifier)
	if err != nil {
		l.forgetHello(clientConnID, answer)
		return
	}
	result, err := handshake.keys()
	if err != nil {
		l.forgetHello(clientConnID, answer)
		return
	}
	a := newAssociation(l.conn, result, source, l.options, false, false)
	a.start()
	a.onClose = func() {
		l.remove(a.localConnID)
	}
	if !l.add(a) {
		a.shutdown(net.ErrClosed, false)
		l.forgetHello(clientConnID, answer)
		return
	}
	serverHello := bytes.Clone(handshake.hello())
	_, err = l.conn.WriteTo(serverHello, source)
	if err != nil {
		a.shutdown(err, false)
		l.forgetHello(clientConnID, answer)
		return
	}
	l.keepHello(clientConnID, answer, serverHello)
	go a.startMTUProbe()
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
