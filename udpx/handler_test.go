package udpx

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// OnStream 每条流一个新 goroutine：一条流阻塞住，另一条照样进来。
func TestOnStreamIsConcurrent(t *testing.T) {
	credential := NewCredential("password")
	listenerConn := udpConn(t)
	entered := make(chan *Stream, 4)
	release := make(chan struct{})
	listener := Listen(listenerConn, testVerifier{credential: credential}, Options{
		MTU: mtuIPv4,
		NewHandler: func(conn *Conn) Handler {
			return &blockingStreamHandler{entered: entered, release: release}
		},
	})
	defer listener.Close()
	client := testDial(t, testContext(t, 5*time.Second), udpConn(t), listenerConn.LocalAddr(), credential, Options{MTU: mtuIPv4})
	ctx := testContext(t, 10*time.Second)
	for range 2 {
		if _, err := client.OpenStream(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("the second stream waited for the first")
		}
	}
	close(release)
}

type blockingStreamHandler struct {
	entered chan *Stream
	release chan struct{}
}

func (h *blockingStreamHandler) OnStream(conn *Conn, stream *Stream) {
	h.entered <- stream
	<-h.release
	_ = stream.Close()
}

func (h *blockingStreamHandler) OnDatagram(conn *Conn, data []byte) {}

func (h *blockingStreamHandler) OnClose(conn *Conn, cause error) {}

// OnClose 恰好一次，并且在 OnDatagram 之后。
func TestOnCloseIsDeliveredOnce(t *testing.T) {
	credential := NewCredential("password")
	listenerConn := udpConn(t)
	handler := &countingHandler{closed: make(chan error, 4)}
	listener := Listen(listenerConn, testVerifier{credential: credential}, Options{
		MTU: mtuIPv4,
		NewHandler: func(conn *Conn) Handler {
			return handler
		},
	})
	defer listener.Close()
	client := testDial(t, testContext(t, 5*time.Second), udpConn(t), listenerConn.LocalAddr(), credential, Options{MTU: mtuIPv4})
	if err := client.SendDatagram([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for handler.datagrams.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if handler.datagrams.Load() != 1 {
		t.Fatalf("%d datagrams arrived", handler.datagrams.Load())
	}
	_ = client.CloseWithError(nil)
	select {
	case <-handler.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("OnClose was not called")
	}
	time.Sleep(100 * time.Millisecond)
	if count := handler.closes.Load(); count != 1 {
		t.Fatalf("OnClose was called %d times", count)
	}
}

type countingHandler struct {
	datagrams atomic.Int32
	closes    atomic.Int32
	closed    chan error
	once      sync.Once
}

func (h *countingHandler) OnDatagram(conn *Conn, data []byte) {
	h.datagrams.Add(1)
}

func (h *countingHandler) OnStream(conn *Conn, stream *Stream) {
	_ = stream.Close()
}

func (h *countingHandler) OnClose(conn *Conn, cause error) {
	h.closes.Add(1)
	h.once.Do(func() {
		h.closed <- cause
	})
}

// 拨号方的 handler 返回 nil 时 Dial 直接失败，并且关掉自己拿到的 socket。
func TestDialRejectsWhenTheHandlerRefuses(t *testing.T) {
	credential := NewCredential("password")
	listenerConn := udpConn(t)
	listener, _ := testListen(t, listenerConn, credential, Options{MTU: mtuIPv4})
	defer listener.Close()
	socket := udpConn(t)
	_, err := Dial(testContext(t, 5*time.Second), socket, listenerConn.LocalAddr(), credential, Options{
		MTU: mtuIPv4,
		NewHandler: func(conn *Conn) Handler {
			return nil
		},
	})
	if err == nil {
		t.Fatal("Dial accepted a refused connection")
	}
	if _, writeErr := socket.WriteTo(nil, listenerConn.LocalAddr()); writeErr == nil {
		t.Fatal("the socket was left open")
	}
}

// 接听方拒绝建立连接时 Listener 不留下任何连接。
func TestListenForgetsARejectedConnection(t *testing.T) {
	credential := NewCredential("password")
	listenerConn := udpConn(t)
	listener := Listen(listenerConn, testVerifier{credential: credential}, Options{
		MTU: mtuIPv4,
		NewHandler: func(conn *Conn) Handler {
			return nil
		},
	})
	defer listener.Close()
	socket := udpConn(t)
	handshake, err := newClientHandshake(credential)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = socket.WriteTo(handshake.hello(), listenerConn.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		listener.mu.Lock()
		conns := len(listener.conns)
		hellos := len(listener.hellos)
		listener.mu.Unlock()
		if conns != 0 {
			t.Fatalf("%d connections were kept", conns)
		}
		if hellos != 0 {
			t.Fatalf("%d hello answers were cached", hellos)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
