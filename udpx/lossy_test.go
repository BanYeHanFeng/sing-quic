package udpx

import (
	"bytes"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"
)

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

type linkOptions struct {
	loss       float64
	lossReturn float64
	duplicate  float64
	delay      time.Duration
	jitter     time.Duration
	rate       float64
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

func (l *simulatedLink) forward(from, to net.PacketConn, destination func() net.Addr) {
	queue := make(chan simulatedPacket, 1<<14)
	go l.deliver(queue)
	buffer := make([]byte, maxPacketSize)
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
		packet := append([]byte(nil), buffer[:n]...)
		loss := l.currentLoss(from == l.back)
		l.send(queue, packet, to, destination, &free, loss)
		if l.roll(l.options.duplicate) {
			l.send(queue, packet, to, destination, &free, loss)
		}
	}
}

func (l *simulatedLink) currentLoss(returning bool) float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	if returning {
		return l.options.lossReturn
	}
	return l.options.loss
}

func (l *simulatedLink) setLoss(loss float64) {
	l.mu.Lock()
	l.options.loss = loss
	l.options.lossReturn = loss
	l.mu.Unlock()
}

func (l *simulatedLink) send(queue chan<- simulatedPacket, packet []byte, to net.PacketConn, destination func() net.Addr, free *time.Time, loss float64) {
	if l.roll(loss) {
		return
	}
	arrival := time.Now()
	if l.options.rate > 0 {
		if free.After(arrival) {
			if l.options.queueLimit > 0 &&
				float64(free.Sub(arrival).Seconds())*l.options.rate+float64(len(packet)) > l.options.queueLimit {
				return
			}
			arrival = *free
		}
		*free = arrival.Add(time.Duration(float64(len(packet)) / l.options.rate * float64(time.Second)))
	}
	delay := l.options.delay
	if l.options.jitter > 0 {
		jitter := l.options.jitter
		delay += time.Duration(l.randomValue()*2-1) * jitter
		if delay < 0 {
			delay = 0
		}
	}
	arrival = arrival.Add(delay)
	queue <- simulatedPacket{arrival: arrival, data: packet, to: to, destination: destination}
}

type simulatedPacket struct {
	arrival     time.Time
	data        []byte
	to          net.PacketConn
	destination func() net.Addr
}

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

func TestTransferUnderLoss(t *testing.T) {
	for _, loss := range []float64{0.01, 0.05, 0.20} {
		t.Run(testName(loss), func(t *testing.T) {
			credential := NewCredential("password")
			listenerConn := udpConn(t)
			listener := Listen(listenerConn, testVerifier{credential: credential}, Options{MTU: mtuIPv4})
			defer listener.Close()
			link := newSimulatedLink(t, listenerConn.LocalAddr(), linkOptions{loss: loss, lossReturn: loss})

			ctx := testContext(t, 60*time.Second)
			client, err := Dial(ctx, udpConn(t), link.clientAddr(), credential, Options{MTU: mtuIPv4})
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
			serverAssociation := server
			serverAssociation.sendMu.Lock()
			inFlight := serverAssociation.send.inFlight.len()
			serverAssociation.sendMu.Unlock()
			if inFlight > 2*initialStreams {
				t.Fatalf("%d packets in flight after the transfer", inFlight)
			}
		})
	}
}

func TestStreamOverALossyCapacityPath(t *testing.T) {
	if testing.Short() {
		t.Skip("c path with c capacity takes its time")
	}
	const capacity = 12.5 * 1024 * 1024
	credential := NewCredential("password")
	listenerConn := udpConn(t)
	listener := Listen(listenerConn, testVerifier{credential: credential}, Options{MTU: mtuIPv4})
	defer listener.Close()
	link := newSimulatedLink(t, listenerConn.LocalAddr(), linkOptions{
		loss:       0.05,
		lossReturn: 0.05,
		delay:      100 * time.Millisecond,
		jitter:     2 * time.Millisecond,
		rate:       capacity,
	})

	ctx := testContext(t, 60*time.Second)
	client, err := Dial(ctx, udpConn(t), link.clientAddr(), credential, Options{MTU: mtuIPv4})
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
		t.Fatalf("%.2f MiB/s over c path of %.2f MiB/s", rate/1024/1024, capacity/1024/1024)
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

func TestDownloadOverUplinkLoss(t *testing.T) {
	if testing.Short() {
		t.Skip("c path that loses most of one direction takes its time")
	}
	const payloadSize = 256 * 1024
	credential := NewCredential("password")
	listenerConn := udpConn(t)
	listener := Listen(listenerConn, testVerifier{credential: credential}, Options{MTU: mtuIPv4})
	defer listener.Close()
	link := newSimulatedLink(t, listenerConn.LocalAddr(), linkOptions{
		loss:       0.4,
		lossReturn: 0,
		delay:      100 * time.Millisecond,
	})

	ctx := testContext(t, 120*time.Second)
	client, err := Dial(ctx, udpConn(t), link.clientAddr(), credential, Options{MTU: mtuIPv4})
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

func TestStreamOverABufferedPath(t *testing.T) {
	if testing.Short() {
		t.Skip("c path with c buffer takes its time")
	}
	const capacity = 400 * 1024
	const payloadSize = 2 * 1024 * 1024
	credential := NewCredential("password")
	listenerConn := udpConn(t)
	listener := Listen(listenerConn, testVerifier{credential: credential}, Options{MTU: mtuIPv4})
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
	client, err := Dial(ctx, udpConn(t), link.clientAddr(), credential, Options{MTU: mtuIPv4})
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
		t.Fatalf("%.2f KiB/s over c path of %d KiB/s", rate/1024, capacity/1024)
	}
	serverAssociation := server
	stats := testSnapshot(serverAssociation)
	if stats.txPackets > 0 && stats.lostPackets*2 > stats.txPackets {
		t.Fatalf("%d of %d packets declared lost", stats.lostPackets, stats.txPackets)
	}
	t.Logf("%.2f KiB/s, %d of %d packets lost, %d sent again", rate/1024, stats.lostPackets, stats.txPackets, stats.retransmits)
}
