package udpx

import (
	"bytes"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"
)

// simulatedLink is a pair of sockets that carries datagrams between a client and a
// server along a path that loses, delays, reorders and duplicates them. It is what
// makes a retransmission test a test of the transport rather than of a mock: the
// client and the server both run for real, and only the path between them behaves
// like a path.
//
// Everything the path decides comes from one seeded source, so a failure is a
// failure that happens again. The delay is applied per packet and independently in
// each direction, which is what turns a fixed delay plus a jitter into reordering
// without a separate rule for it.
type simulatedLink struct {
	front   net.PacketConn
	back    net.PacketConn
	server  net.Addr
	options linkOptions

	randomMu sync.Mutex
	random   *rand.Rand

	mu        sync.Mutex
	client    net.Addr
	closeOnce sync.Once
	closing   chan struct{}
}

// linkOptions is what the path between the two ends does to a datagram.
type linkOptions struct {
	// loss is the fraction of datagrams that never arrive.
	loss float64
	// duplicate is the fraction of datagrams that arrive twice.
	duplicate float64
	// delay is how long a datagram spends on the way, each direction.
	delay time.Duration
	// jitter is how much shorter or longer than delay a datagram may spend, which
	// is what reorders them.
	jitter time.Duration
}

func newSimulatedLink(t *testing.T, server net.Addr, options linkOptions) *simulatedLink {
	t.Helper()
	link := &simulatedLink{
		front:   udpConn(t),
		back:    udpConn(t),
		server:  server,
		options: options,
		random:  rand.New(rand.NewSource(1)),
		closing: make(chan struct{}),
	}
	t.Cleanup(link.close)
	go link.forward(link.front, link.back, func() net.Addr { return link.server })
	go link.forward(link.back, link.front, func() net.Addr {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.client
	})
	return link
}

// forward copies datagrams from one socket to the other, handing each of them to
// the path and remembering where the client is.
func (l *simulatedLink) forward(from, to net.PacketConn, destination func() net.Addr) {
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
		// The buffer is reused for the next datagram, so what the path decided to
		// keep has to be its own copy.
		packet := append([]byte(nil), buffer[:n]...)
		l.send(packet, to, destination)
		if l.roll(l.options.duplicate) {
			l.send(packet, to, destination)
		}
	}
}

// send puts one datagram on the path, which either drops it or arrives after the
// delay the path picked for it.
func (l *simulatedLink) send(packet []byte, to net.PacketConn, destination func() net.Addr) {
	if l.roll(l.options.loss) {
		return
	}
	delay := l.options.delay
	if l.options.jitter > 0 {
		jitter := l.options.jitter
		// A delay below zero is not a delay: a datagram never overtakes the
		// decision to send it.
		delay += time.Duration(l.randomValue()*2-1) * jitter
		if delay < 0 {
			delay = 0
		}
	}
	if delay == 0 {
		l.write(packet, to, destination)
		return
	}
	time.AfterFunc(delay, func() {
		l.write(packet, to, destination)
	})
}

// write hands one datagram to the socket, unless the link was closed meanwhile.
func (l *simulatedLink) write(packet []byte, to net.PacketConn, destination func() net.Addr) {
	select {
	case <-l.closing:
		return
	default:
	}
	target := destination()
	if target == nil {
		return
	}
	_, _ = to.WriteTo(packet, target)
}

// roll reports whether something that happens with the given probability happens.
func (l *simulatedLink) roll(probability float64) bool {
	if probability <= 0 {
		return false
	}
	return l.randomValue() < probability
}

func (l *simulatedLink) randomValue() float64 {
	l.randomMu.Lock()
	defer l.randomMu.Unlock()
	return l.random.Float64()
}

func (l *simulatedLink) clientAddr() net.Addr {
	return l.front.LocalAddr()
}

func (l *simulatedLink) close() {
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
			link := newSimulatedLink(t, listenerConn.LocalAddr(), linkOptions{loss: loss})

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
