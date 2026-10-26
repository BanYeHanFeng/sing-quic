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
	// rate is how many bytes per second the path carries, each direction.
	//
	// Zero is a path that carries whatever it is given at once, which is a link
	// without a capacity: a measurement over one of those is a measurement of how
	// fast a window can ramp and not of what the path can carry, and a window larger
	// than the bandwidth-delay product builds a queue on a path that has one instead
	// of arriving sooner.
	rate float64
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
	// The path is one queue in each direction: free is when the datagram that
	// follows may leave.
	var free time.Time
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
		l.send(packet, to, destination, &free)
		if l.roll(l.options.duplicate) {
			l.send(packet, to, destination, &free)
		}
	}
}

// send puts one datagram on the path, which either drops it or arrives after the
// delay the path picked for it. A path with a capacity takes its time carrying one
// datagram, and the next one waits for it.
func (l *simulatedLink) send(packet []byte, to net.PacketConn, destination func() net.Addr, free *time.Time) {
	if l.roll(l.options.loss) {
		return
	}
	arrival := time.Now()
	if l.options.rate > 0 {
		if free.After(arrival) {
			arrival = *free
		}
		*free = arrival.Add(time.Duration(float64(len(packet)) / l.options.rate * float64(time.Second)))
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
	arrival = arrival.Add(delay)
	if !arrival.After(time.Now()) {
		l.write(packet, to, destination)
		return
	}
	time.AfterFunc(time.Until(arrival), func() {
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

// TestWindowGrowsOverALossyCapacityPath requires the window to grow over a path that
// has a capacity and loses packets, which is the case the growth exists for: a lost
// packet leaves a hole, the application cannot read past it, and the credit update
// that the hole delayed is a round trip the peer spends waiting. Growing the window
// is what puts that round trip back to work (on a 50 Mbit/s path of the same shape,
// 16 MiB went from 2.1 to 2.9 MiB/s; here 8 MiB went from 2.1 to 2.3–2.5 and 16 MiB
// to 3.3–3.5).
//
// Two things are pinned and only one of them is a rate. A window that never grew
// would leave the path idle after every hole, which is what the first check is for
// and what fails without the growth; the rate is a floor against a collapse and not a
// measurement, because most of the distance to the capacity is the congestion
// controller's startup and not the window.
func TestWindowGrowsOverALossyCapacityPath(t *testing.T) {
	if testing.Short() {
		t.Skip("a path with a capacity takes its time")
	}
	const capacity = 12.5 * 1024 * 1024
	password := NewPassword("password")
	listenerConn := udpConn(t)
	listener := ListenPacket(listenerConn, testVerifier{password}, Options{})
	defer listener.Close()
	link := newSimulatedLink(t, listenerConn.LocalAddr(), linkOptions{
		loss:   0.05,
		delay:  100 * time.Millisecond,
		jitter: 2 * time.Millisecond,
		rate:   capacity,
	})

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
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Several times the window the peer starts with, so the one it has is filled and
	// the reads after that double it, without spending seconds on a path this slow.
	payload := testPayload(4 * initialStreamWindow)
	start := time.Now()
	go func() {
		if _, writeErr := stream.Write(payload); writeErr != nil {
			t.Errorf("write: %v", writeErr)
		}
	}()
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	read := make([]byte, 0, len(payload))
	buffer := make([]byte, 64*1024)
	for len(read) < len(payload) {
		n, readErr := accepted.Read(buffer)
		if readErr != nil {
			t.Fatalf("read %d of %d bytes: %v", len(read), len(payload), readErr)
		}
		read = append(read, buffer[:n]...)
	}
	elapsed := time.Since(start)
	if granted := grantedTo(t, server, accepted.ID()); granted.window <= initialStreamWindow {
		t.Fatalf("the window stayed at %d bytes over a path that loses packets", granted.window)
	}
	if window, _, _ := associationWindowOf(t, server); window <= initialConnectionWindow {
		t.Fatalf("the association window stayed at %d bytes", window)
	}
	if rate := float64(len(payload)) / elapsed.Seconds(); rate < capacity/8 {
		t.Fatalf("%.2f MiB/s over a path of %.2f MiB/s", rate/1024/1024, capacity/1024/1024)
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
