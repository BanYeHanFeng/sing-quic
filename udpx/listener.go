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
	hellos       map[connectionID]*helloAnswer
	sweptAt      time.Time

	closeOnce sync.Once
}

type helloAnswer struct {
	packet []byte
	at     time.Time
}

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
		_ = l.conn.SetReadDeadline(time.Now())
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

func (l *Listener) readLoop() {
	buffer := make([]byte, maxReceiveSize)
	for {
		packets, err := l.batchIO.ReadPackets([][]byte{buffer})
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
	a := l.associations[packetHeader.ConnectionID]
	l.mu.Unlock()
	if a == nil {
		return
	}
	_ = a.handlePacket(packet, source)
}

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
	a := newAssociation(l.conn, l.batchIO, result, source, l.options, false)
	a.onClose = func() {
		l.remove(a.localConnID)
	}
	a.start()
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
	l.mu.Lock()
	if l.hellos[clientConnID] == answer {
		answer.packet = serverHello
		answer.at = time.Now()
	}
	l.mu.Unlock()
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
