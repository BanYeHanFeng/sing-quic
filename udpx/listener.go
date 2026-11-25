package udpx

import (
	"bytes"
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-quic/udpx/internal/udpio"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	maxConcurrentHandshakes = 8

	acceptBacklog = 16

	helloLifetime = 10 * time.Second

	helloSweepInterval = time.Second
)

type Listener struct {
	socket      net.PacketConn
	io          udpio.Conn
	verifier    Verifier
	options     Options
	ctx         context.Context
	cancel      context.CancelCauseFunc
	accept      chan *Conn
	handshaking chan struct{}

	mu      sync.Mutex
	conns   map[connectionID]*Conn
	hellos  map[connectionID]*helloAnswer
	sweptAt time.Time

	closeOnce sync.Once
}

type helloAnswer struct {
	packet []byte
	at     time.Time
}

func Listen(conn net.PacketConn, verifier Verifier, options Options) *Listener {
	ctx, cancel := context.WithCancelCause(context.Background())
	l := &Listener{
		socket:      conn,
		io:          udpio.New(conn, udpio.Options{GRO: true}),
		verifier:    verifier,
		options:     options.withDefaults(),
		ctx:         ctx,
		cancel:      cancel,
		accept:      make(chan *Conn, acceptBacklog),
		handshaking: make(chan struct{}, maxConcurrentHandshakes),
		conns:       make(map[connectionID]*Conn),
		hellos:      make(map[connectionID]*helloAnswer),
	}
	go l.readLoop()
	return l
}

func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	select {
	case c := <-l.accept:
		return c, nil
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
		_ = l.socket.SetReadDeadline(time.Now())
		l.mu.Lock()
		conns := l.conns
		l.conns = make(map[connectionID]*Conn)
		l.hellos = make(map[connectionID]*helloAnswer)
		l.mu.Unlock()
		for _, c := range conns {
			c.shutdown(cause, false)
		}
	})
}

func (l *Listener) readLoop() {
	buffer := make([]byte, maxReceiveSize)
	for {
		packets, err := l.io.ReadPackets([][]byte{buffer})
		if err != nil {
			if l.ctx.Err() != nil {
				return
			}
			if isClosed(err) {
				l.shutdown(err)
				return
			}
			continue
		}
		l.sweepHellos(time.Now())
		for _, packet := range packets {
			packet.ForEach(func(datagram []byte) {
				packetHeader, parseErr := parseHeader(datagram)
				if parseErr != nil {
					return
				}
				if packetHeader.Type == packetTypeHandshake {
					l.handleHello(packetHeader.ConnectionID, bytes.Clone(datagram), packet.Addr)
					return
				}
				l.dispatch(packetHeader, datagram, packet.Addr)
			})
		}
	}
}

func (l *Listener) sweepHellos(now time.Time) {
	l.mu.Lock()
	if now.Sub(l.sweptAt) < helloSweepInterval {
		l.mu.Unlock()
		return
	}
	l.sweptAt = now
	for connID, answer := range l.hellos {
		if now.Sub(answer.at) >= helloLifetime {
			delete(l.hellos, connID)
		}
	}
	l.mu.Unlock()
}

func (l *Listener) dispatch(packetHeader header, packet []byte, source net.Addr) {
	l.mu.Lock()
	c := l.conns[packetHeader.ConnectionID]
	l.mu.Unlock()
	if c == nil {
		return
	}
	_ = c.handlePacket(packet, source)
}

func (l *Listener) handleHello(clientConnID connectionID, hello []byte, source net.Addr) {
	now := time.Now()
	l.mu.Lock()
	answer, loaded := l.hellos[clientConnID]
	if loaded && now.Sub(answer.at) < helloLifetime {
		l.mu.Unlock()
		if answer.packet != nil {
			_, _ = l.socket.WriteTo(answer.packet, source)
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

func (l *Listener) forgetHello(clientConnID connectionID, answer *helloAnswer) {
	l.mu.Lock()
	if l.hellos[clientConnID] == answer {
		delete(l.hellos, clientConnID)
	}
	l.mu.Unlock()
}

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
	c := newConn(l.socket, l.io, result, source, l.options, false)
	c.onClose = func() {
		l.remove(c.localID)
	}
	c.start()
	if !l.add(c) {
		c.shutdown(net.ErrClosed, false)
		l.forgetHello(clientConnID, answer)
		return
	}
	serverHello := bytes.Clone(handshake.hello())
	_, err = l.socket.WriteTo(serverHello, source)
	if err != nil {
		c.shutdown(err, false)
		l.forgetHello(clientConnID, answer)
		return
	}
	l.mu.Lock()
	if l.hellos[clientConnID] == answer {
		answer.packet = serverHello
		answer.at = time.Now()
	}
	l.mu.Unlock()
	select {
	case l.accept <- c:
	default:
		c.shutdown(E.New("accept queue is full"), true)
	}
}

func (l *Listener) add(c *Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.ctx.Done():
		return false
	default:
	}
	if _, loaded := l.conns[c.localID]; loaded {
		return false
	}
	l.conns[c.localID] = c
	return true
}

func (l *Listener) remove(connID connectionID) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c, loaded := l.conns[connID]; loaded && c.localID == connID {
		delete(l.conns, connID)
	}
}
