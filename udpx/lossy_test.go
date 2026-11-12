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
	// loss is the fraction of datagrams that never arrive on the way to the
	// server, and lossReturn the fraction that never arrive on the way back. The
	// two are separate because a path that drops one direction and not the other
	// is what a mobile uplink looks like, and what it costs the transport differs
	// by direction: a data packet that never arrives is data the peer has to be
	// sent again, while an acknowledgement that never arrives is one the sender
	// mistakes for a loss it has to recover from.
	loss       float64
	lossReturn float64
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
	// queueLimit is how many bytes the path holds for a capacity before it starts
	// dropping, which is what a buffer in front of a narrow link is. Zero is a
	// queue that never fills, which is the shape of a link that carries everything
	// it is handed: a window above the bandwidth-delay product then builds a queue
	// instead of losing anything, and the sender is never told that it asked for
	// more than the path carries.
	queueLimit float64
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
	queue := make(chan simulatedPacket, 1<<14)
	go l.deliver(queue)
	buffer := make([]byte, maxPacketSize)
	// The path is one queue in each direction: free is when the datagram that
	// follows may leave.
	var free time.Time
	for {
		n, source, err := from.ReadFrom(buffer)
		if err != nil {
			close(queue)
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
		loss := l.options.loss
		if from == l.back {
			loss = l.options.lossReturn
		}
		l.send(queue, packet, to, destination, &free, loss)
		if l.roll(l.options.duplicate) {
			l.send(queue, packet, to, destination, &free, loss)
		}
	}
}

// send puts one datagram on the path, which either drops it or arrives after the
// delay the path picked for it. A path with a capacity takes its time carrying one
// datagram, and the next one waits for it.
func (l *simulatedLink) send(queue chan<- simulatedPacket, packet []byte, to net.PacketConn, destination func() net.Addr, free *time.Time, loss float64) {
	if l.roll(loss) {
		return
	}
	arrival := time.Now()
	if l.options.rate > 0 {
		if free.After(arrival) {
			if l.options.queueLimit > 0 &&
				float64(free.Sub(arrival).Seconds())*l.options.rate+float64(len(packet)) > l.options.queueLimit {
				// The buffer in front of the link is full, so the datagram is
				// dropped here rather than queued: what a path with a buffer does
				// to a sender that asks for more than it carries.
				return
			}
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
	queue <- simulatedPacket{arrival: arrival, data: packet, to: to, destination: destination}
}

// simulatedPacket is one datagram on its way, with the moment it should arrive.
type simulatedPacket struct {
	arrival     time.Time
	data        []byte
	to          net.PacketConn
	destination func() net.Addr
}

// deliver writes the datagrams of one direction in arrival order.
//
// It is one goroutine with the packets sorted, not a timer per packet. A timer per
// packet runs every callback in a goroutine of its own, so two datagrams scheduled a
// tenth of a millisecond apart leave in whatever order the scheduler picks: a path
// that was asked for a fixed delay would reorder by dozens of packets, and the
// transport answers that with a retransmission because three packets past a hole is
// what it calls lost. What the path does has to be what the options say it does.
func (l *simulatedLink) deliver(queue <-chan simulatedPacket) {
	var pending []simulatedPacket
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		wait := time.Hour
		if len(pending) > 0 {
			wait = time.Until(pending[0].arrival)
			if wait < 0 {
				wait = 0
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)
		select {
		case packet, ok := <-queue:
			if !ok {
				return
			}
			index := len(pending)
			for index > 0 && pending[index-1].arrival.After(packet.arrival) {
				index--
			}
			pending = append(pending, simulatedPacket{})
			copy(pending[index+1:], pending[index:])
			pending[index] = packet
		case <-timer.C:
			now := time.Now()
			for len(pending) > 0 && !pending[0].arrival.After(now) {
				l.write(pending[0].data, pending[0].to, pending[0].destination)
				pending = pending[1:]
			}
		case <-l.closing:
			return
		}
	}
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
			listener := ListenPacket(listenerConn, testVerifier{password}, Options{MTU: mtuIPv4})
			defer listener.Close()
			link := newSimulatedLink(t, listenerConn.LocalAddr(), linkOptions{loss: loss, lossReturn: loss})

			ctx := testContext(t, 60*time.Second)
			client, err := Dial(ctx, udpConn(t), link.clientAddr(), password, Options{MTU: mtuIPv4})
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
			if inFlight > 2*initialStreams {
				t.Fatalf("%d packets in flight after the transfer", inFlight)
			}
		})
	}
}

// TestStreamOverALossyCapacityPath requires a transfer to keep moving over a path that
// has a capacity and loses packets: a lost packet leaves a hole, the application cannot
// read past it, and the credit the peer is given has to be enough that the path does
// not go idle for the round trip the hole costs.
//
// The rate is a floor against a collapse and not a measurement: most of the distance to
// the capacity is the congestion controller's ramp and not the window.
func TestStreamOverALossyCapacityPath(t *testing.T) {
	if testing.Short() {
		t.Skip("a path with a capacity takes its time")
	}
	const capacity = 12.5 * 1024 * 1024
	password := NewPassword("password")
	listenerConn := udpConn(t)
	listener := ListenPacket(listenerConn, testVerifier{password}, Options{MTU: mtuIPv4})
	defer listener.Close()
	link := newSimulatedLink(t, listenerConn.LocalAddr(), linkOptions{
		loss:       0.05,
		lossReturn: 0.05,
		delay:      100 * time.Millisecond,
		jitter:     2 * time.Millisecond,
		rate:       capacity,
	})

	ctx := testContext(t, 60*time.Second)
	client, err := Dial(ctx, udpConn(t), link.clientAddr(), password, Options{MTU: mtuIPv4})
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
	// More than the credit a stream is granted, so the transfer runs on the window
	// moving forward rather than on what one announcement gave it.
	payload := testPayload(2*streamWindow + 4096)
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

// TestDownloadOverUplinkLoss requires a transfer whose data travels in the
// direction that loses nothing to complete while its acknowledgements travel in
// the one that loses most of them. That is what a mobile uplink is: the downlink
// carries the transfer, the uplink carries the answers to it.
//
// A lost acknowledgement is not a lost packet, and a sender that cannot tell the
// two apart has nothing to go on but the packet numbers an acknowledgement did
// not name: it declares everything behind the largest one lost and sends its
// window again. The path then carries duplicates until the window collapses, and
// the transfer stops even though no data was missing. What separates the two is
// the range limit: an acknowledgement that names every range it has is telling
// the sender what it holds, and one that ran out of room is not.
func TestDownloadOverUplinkLoss(t *testing.T) {
	if testing.Short() {
		t.Skip("a path that loses most of one direction takes its time")
	}
	const payloadSize = 256 * 1024
	password := NewPassword("password")
	listenerConn := udpConn(t)
	listener := ListenPacket(listenerConn, testVerifier{password}, Options{MTU: mtuIPv4})
	defer listener.Close()
	link := newSimulatedLink(t, listenerConn.LocalAddr(), linkOptions{
		loss:       0.4,
		lossReturn: 0,
		delay:      100 * time.Millisecond,
	})

	ctx := testContext(t, 120*time.Second)
	client, err := Dial(ctx, udpConn(t), link.clientAddr(), password, Options{MTU: mtuIPv4})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseWithError(nil)
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.CloseWithError(nil)

	payload := testPayload(payloadSize)
	go func() {
		stream, openErr := server.OpenStream(ctx)
		if openErr != nil {
			t.Errorf("open the download: %v", openErr)
			return
		}
		if _, writeErr := stream.Write(payload); writeErr != nil {
			t.Errorf("download: %v", writeErr)
			return
		}
		if closeErr := stream.CloseWrite(); closeErr != nil {
			t.Errorf("close the download: %v", closeErr)
		}
	}()
	start := time.Now()
	stream, err := client.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	read, err := readToEnd(stream, len(payload))
	if err != nil {
		t.Fatalf("the download stopped after %d of %d bytes: %v", len(read), len(payload), err)
	}
	if !bytes.Equal(read, payload) {
		t.Fatal("the download changed on the way")
	}
	elapsed := time.Since(start)
	t.Logf("%d KiB in %v", payloadSize/1024, elapsed.Round(time.Millisecond))
}

// TestStreamOverABufferedPath requires a transfer to keep moving over a path that
// has a capacity and a buffer in front of it, which is the shape a mobile downlink
// has: what the sender asks for beyond the capacity is not queued forever, it is
// dropped when the buffer is full, and the drops are the path telling the sender
// what it asked for.
//
// A controller that reads the peak it once managed as the capacity keeps asking for
// it: the buffer overflows again, the loss is answered by sending it again, and the
// share of the path that arrives falls with every round. What this pins is the rate
// against a collapse and the loss against a path that spends itself on duplicates.
func TestStreamOverABufferedPath(t *testing.T) {
	if testing.Short() {
		t.Skip("a path with a buffer takes its time")
	}
	const capacity = 400 * 1024
	const payloadSize = 2 * 1024 * 1024
	password := NewPassword("password")
	listenerConn := udpConn(t)
	listener := ListenPacket(listenerConn, testVerifier{password}, Options{MTU: mtuIPv4})
	defer listener.Close()
	link := newSimulatedLink(t, listenerConn.LocalAddr(), linkOptions{
		loss:       0.006,
		lossReturn: 0.006,
		delay:      33 * time.Millisecond,
		jitter:     2 * time.Millisecond,
		rate:       capacity,
		queueLimit: 25 * 1024,
	})
	ctx := testContext(t, 300*time.Second)
	client, err := Dial(ctx, udpConn(t), link.clientAddr(), password, Options{MTU: mtuIPv4})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseWithError(nil)
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := server.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload(payloadSize)
	start := time.Now()
	go func() {
		if _, writeErr := stream.Write(payload); writeErr != nil {
			t.Errorf("write: %v", writeErr)
		}
	}()
	accepted, err := client.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	read := 0
	buffer := make([]byte, 64*1024)
	for read < len(payload) {
		n, readErr := accepted.Read(buffer)
		if readErr != nil {
			t.Fatalf("read %d of %d bytes: %v", read, len(payload), readErr)
		}
		read += n
	}
	elapsed := time.Since(start)
	rate := float64(len(payload)) / elapsed.Seconds()
	if rate < capacity/2 {
		t.Fatalf("%.2f KiB/s over a path of %d KiB/s", rate/1024, capacity/1024)
	}
	serverAssociation := server.(*association)
	stats := serverAssociation.snapshot()
	if stats.sentPackets > 0 && stats.lostPackets*2 > stats.sentPackets {
		t.Fatalf("%d of %d packets declared lost", stats.lostPackets, stats.sentPackets)
	}
	t.Logf("%.2f KiB/s, %d of %d packets lost, %d sent again", rate/1024, stats.lostPackets, stats.sentPackets, stats.retransmits)
}
