package udpx

import (
	"bytes"
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-quic/udpx/internal/udpio"

	"github.com/sagernet/sing/common/logger"
)

const (
	maxConcurrentHandshakes = 8

	maxHelloCache = 1024

	helloLifetime = 10 * time.Second

	helloSweepInterval = time.Second
)

type Listener struct {
	socket      net.PacketConn
	io          udpio.Conn
	verifier    Verifier
	options     Options
	logger      logger.Logger
	ctx         context.Context
	cancel      context.CancelCauseFunc
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

// Listen 在共享的 socket 上服务连接。每条连接握手成功后在 options.NewHandler 里交给上层决定是否接受。
func Listen(socket net.PacketConn, verifier Verifier, options Options) *Listener {
	ctx, cancel := context.WithCancelCause(context.Background())
	options = options.withDefaults()
	l := &Listener{
		socket:      socket,
		io:          udpio.New(socket),
		verifier:    verifier,
		options:     options,
		logger:      options.Logger,
		ctx:         ctx,
		cancel:      cancel,
		handshaking: make(chan struct{}, maxConcurrentHandshakes),
		conns:       make(map[connectionID]*Conn),
		hellos:      make(map[connectionID]*helloAnswer),
	}
	go l.readLoop()
	return l
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
		packet, err := l.io.ReadPacket(buffer)
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
	if !loaded && len(l.hellos) >= maxHelloCache {
		l.mu.Unlock()
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
	c.handler = l.options.NewHandler(c)
	if c.handler == nil {
		l.forgetHello(clientConnID, answer)
		return
	}
	go c.sendLoop()
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
