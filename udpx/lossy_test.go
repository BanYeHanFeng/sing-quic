package udpx

import (
	"bytes"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"
)

// lossyLink is a pair of sockets that carries datagrams between a client and a
// server and drops a fraction of them in each direction. It is what makes a
// retransmission test a test of the transport rather than of a mock: the client
// and the server both run for real, and only the path between them loses packets.
type lossyLink struct {
	front     net.PacketConn
	back      net.PacketConn
	server    net.Addr
	mu        sync.Mutex
	client    net.Addr
	closeOnce sync.Once
	closing   chan struct{}
}

func newLossyLink(t *testing.T, server net.Addr, loss float64) *lossyLink {
	t.Helper()
	link := &lossyLink{
		front:   udpConn(t),
		back:    udpConn(t),
		server:  server,
		closing: make(chan struct{}),
	}
	random := rand.New(rand.NewSource(1))
	var randomMu sync.Mutex
	drop := func() bool {
		randomMu.Lock()
		defer randomMu.Unlock()
		return random.Float64() < loss
	}
	t.Cleanup(link.close)
	go link.forward(link.front, link.back, func() net.Addr { return link.server }, drop)
	go link.forward(link.back, link.front, func() net.Addr {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.client
	}, drop)
	return link
}

// forward copies datagrams from one socket to the other, dropping some of them and
// remembering where the client is.
func (l *lossyLink) forward(from, to net.PacketConn, destination func() net.Addr, drop func() bool) {
	buffer := make([]byte, maxPacketSize)
	for {
		n, source, err := from.ReadFrom(buffer)
		if err != nil {
			return
		}
		if from == l.front {
			l.mu.Lock()
			l.client = source
			l.mu.Unlock()
		}
		if drop() {
			continue
		}
		target := destination()
		if target == nil {
			continue
		}
		_, _ = to.WriteTo(buffer[:n], target)
	}
}

func (l *lossyLink) clientAddr() net.Addr {
	return l.front.LocalAddr()
}

func (l *lossyLink) close() {
	l.closeOnce.Do(func() {
		close(l.closing)
		_ = l.front.Close()
		_ = l.back.Close()
	})
}

// TestTransferUnderLoss requires a stream to be delivered intact over a path that
// loses packets, which is what retransmission, acknowledgement and the windows
// have to add up to.
func TestTransferUnderLoss(t *testing.T) {
	for _, loss := range []float64{0.01, 0.05, 0.20} {
		t.Run(testName(loss), func(t *testing.T) {
			password := NewPassword("password")
			listenerConn := udpConn(t)
			listener := ListenPacket(listenerConn, testVerifier{password}, Options{})
			defer listener.Close()
			link := newLossyLink(t, listenerConn.LocalAddr(), loss)

			ctx := testContext(t, 60*time.Second)
			client, err := Dial(ctx, udpConn(t), link.clientAddr(), password, Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseWithError(nil)
			server, err := listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}

			payload := testPayload(256 * 1024)
			stream, err := client.OpenStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				if _, writeErr := stream.Write(payload); writeErr != nil {
					t.Errorf("write: %v", writeErr)
					return
				}
				if closeErr := stream.CloseWrite(); closeErr != nil {
					t.Errorf("close write: %v", closeErr)
				}
			}()

			accepted, err := server.AcceptStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			read := make([]byte, 0, len(payload))
			buffer := make([]byte, 32*1024)
			for len(read) < len(payload) {
				n, readErr := accepted.Read(buffer)
				if readErr != nil {
					t.Fatalf("read %d of %d bytes: %v", len(read), len(payload), readErr)
				}
				read = append(read, buffer[:n]...)
			}
			if !bytes.Equal(read, payload) {
				t.Fatal("the payload changed on the way")
			}
			// Memory may not grow with the number of losses: what is in flight and
			// what is queued are both bounded by the windows.
			serverAssociation := server.(*association)
			serverAssociation.flightMu.Lock()
			inFlight := serverAssociation.inFlight.len()
			serverAssociation.flightMu.Unlock()
			if inFlight > 2*maxStreams {
				t.Fatalf("%d packets in flight after the transfer", inFlight)
			}
		})
	}
}

func testName(loss float64) string {
	switch loss {
	case 0.01:
		return "loss-1%"
	case 0.05:
		return "loss-5%"
	default:
		return "loss-20%"
	}
}
