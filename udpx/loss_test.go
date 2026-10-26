package udpx

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeConn is a socket that records what was written to it and answers nothing.
// It lets the send path be driven directly: what a test needs to know is which
// packets left, which is what it can see.
type fakeConn struct {
	local   net.Addr
	mu      sync.Mutex
	packets [][]byte
	closed  bool
}

func newFakeConn() *fakeConn {
	return &fakeConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}}
}

func (c *fakeConn) WriteTo(packet []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.packets = append(c.packets, bytes.Clone(packet))
	return len(packet), nil
}

func (c *fakeConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *fakeConn) LocalAddr() net.Addr              { return c.local }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

func (c *fakeConn) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.packets)
}

// payloads returns the payload of every packet written so far, in order.
func (c *fakeConn) payloads(t *testing.T, ring *keyRing) [][]byte {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	payloads := make([][]byte, 0, len(c.packets))
	for _, packet := range c.packets {
		_, _, payload, err := ring.open(packet)
		if err != nil {
			t.Fatalf("open written packet: %v", err)
		}
		payloads = append(payloads, bytes.Clone(payload))
	}
	return payloads
}

// newTestAssociation builds an association whose socket is a fake, so a test can
// drive the send path without a peer.
func newTestAssociation(t *testing.T, conn net.PacketConn) *association {
	t.Helper()
	recvAEAD, err := newAEAD(testKey(0x22))
	if err != nil {
		t.Fatal(err)
	}
	a := newAssociation(conn, handshakeResult{
		send: newKeyRing(0, mustAEAD(t, testKey(0x11))),
		recv: newKeyRing(0, recvAEAD),
	}, conn.LocalAddr(), Options{IdleTimeout: time.Minute}, false, false)
	t.Cleanup(func() {
		a.shutdown(net.ErrClosed, false)
	})
	return a
}

// testAck builds the body of an acknowledgement frame that covers the given
// ranges, the newest first.
func testAck(largest uint32, ranges ...pnRange) []byte {
	built := ack{
		largest: largest,
		count:   len(ranges),
	}
	copy(built.ranges[:], ranges)
	return built.appendTo(nil)[1:]
}

// drainWrites waits for the socket to have taken what the send path handed to it.
// Writing is the work of the association's own goroutine, so a test that reads what
// the socket got waits for it first.
func drainWrites(t *testing.T, a *association) {
	t.Helper()
	a.drainWrites()
}

// queueStream queues one stream frame of size bytes and sends it.
func queueStream(t *testing.T, a *association, offset uint64, size int) []byte {
	t.Helper()
	frame := appendStream(nil, 1, offset, false, bytes.Repeat([]byte{byte(offset)}, size))
	a.queueFrame(frame)
	err := a.flush()
	if err != nil {
		t.Fatal(err)
	}
	drainWrites(t, a)
	return frame
}

func TestRetransmittableFrames(t *testing.T) {
	var inFlight sentPackets
	inFlight.append(&sentPacket{packetNumber: 0, frames: []outFrame{
		{payload: appendPing(nil), ackEliciting: true},
		{payload: testAck(0, pnRange{start: 0, end: 0})},
	}})
	inFlight.append(&sentPacket{packetNumber: 1, frames: []outFrame{
		{payload: appendStream(nil, 1, 0, false, []byte("data")), ackEliciting: true},
		{payload: appendClose(nil, closeCodeNormal)},
	}})
	frames := retransmittableFrames(inFlight.packets)
	if len(frames) != 1 {
		t.Fatalf("%d frames to send again", len(frames))
	}
	if frames[0].frameType() != frameTypeStream {
		t.Fatalf("frame of type %d", frames[0].frameType())
	}
}

// TestLossByPacketThreshold requires the packets far enough behind what the peer
// acknowledged to be sent again, in the order they were first sent, and nothing
// else to be touched.
func TestLossByPacketThreshold(t *testing.T) {
	conn := newFakeConn()
	a := newTestAssociation(t, conn)
	frames := make([][]byte, 5)
	for index := range frames {
		frames[index] = queueStream(t, a, uint64(index)*1000, 1000)
	}
	if conn.len() != 5 {
		t.Fatalf("%d packets for five large frames", conn.len())
	}

	a.handleAck(testAck(4, pnRange{start: 4, end: 4}), time.Now())
	drainWrites(t, a)

	payloads := conn.payloads(t, &a.sendRing)
	if len(payloads) != 7 {
		t.Fatalf("%d packets written", len(payloads))
	}
	// Packets 0 and 1 are three or more behind the acknowledged packet 4.
	if !bytes.Equal(payloads[5], frames[0]) {
		t.Fatal("the first lost frame was not sent again first")
	}
	if !bytes.Equal(payloads[6], frames[1]) {
		t.Fatal("the second lost frame was not sent again")
	}
	a.flightMu.Lock()
	remaining := a.inFlight.len()
	a.flightMu.Unlock()
	// What the peer acknowledged is gone, what was lost is out again, and what
	// was in between was never touched.
	if remaining != 4 {
		t.Fatalf("%d packets in flight", remaining)
	}
}

// TestLossByTimeThreshold requires a packet that has been in flight for longer
// than the round trip to be sent again once something behind it was acknowledged,
// and requires a packet the peer acknowledged nothing behind to be left alone: its
// answer may be exactly what is on the way.
func TestLossByTimeThreshold(t *testing.T) {
	conn := newFakeConn()
	a := newTestAssociation(t, conn)
	frames := make([][]byte, 3)
	for index := range frames {
		frames[index] = queueStream(t, a, uint64(index)*1000, 1000)
	}
	now := time.Now()
	// Packet 2 was acknowledged, and not enough packets came after 0 for the
	// packet number threshold to be what finds it.
	a.handleAck(testAck(2, pnRange{start: 2, end: 2}), now)
	drainWrites(t, a)
	if written := conn.len(); written != 3 {
		t.Fatalf("%d packets written before the delay passed", written)
	}
	// The packets that are still in flight have been for longer than a round trip.
	a.handleAck(testAck(2, pnRange{start: 2, end: 2}), now.Add(time.Second))
	drainWrites(t, a)
	payloads := conn.payloads(t, &a.sendRing)
	if len(payloads) != 5 {
		t.Fatalf("%d packets written", len(payloads))
	}
	if !bytes.Equal(payloads[3], frames[0]) {
		t.Fatal("the first lost frame was not sent again first")
	}
	if !bytes.Equal(payloads[4], frames[1]) {
		t.Fatal("the second lost frame was not sent again")
	}
	a.flightMu.Lock()
	remaining := a.inFlight.len()
	a.flightMu.Unlock()
	if remaining != 2 {
		t.Fatalf("%d packets in flight", remaining)
	}
}

// TestNoLossWithoutEvidence requires a packet that nothing was acknowledged behind
// to stay in flight however long it has been out: on a path with a long round trip
// every packet is older than the threshold by the time its answer could arrive, so
// judging it by time alone is a retransmission of everything, forever.
func TestNoLossWithoutEvidence(t *testing.T) {
	conn := newFakeConn()
	a := newTestAssociation(t, conn)
	frames := make([][]byte, 2)
	for index := range frames {
		frames[index] = queueStream(t, a, uint64(index)*1000, 1000)
	}
	now := time.Now()
	a.handleAck(testAck(0, pnRange{start: 0, end: 0}), now)
	for index := 1; index < 5; index++ {
		a.handleAck(testAck(0, pnRange{start: 0, end: 0}), now.Add(time.Duration(index)*time.Second))
	}
	drainWrites(t, a)
	payloads := conn.payloads(t, &a.sendRing)
	if len(payloads) != 2 {
		t.Fatalf("%d packets written", len(payloads))
	}
	if !bytes.Equal(payloads[1], frames[1]) {
		t.Fatal("the packet that left was not the frame that was queued")
	}
	a.flightMu.Lock()
	remaining := a.inFlight.len()
	a.flightMu.Unlock()
	if remaining != 1 {
		t.Fatalf("%d packets in flight", remaining)
	}
}

// TestProbe requires a silent path to be probed by sending the oldest packet
// again, and requires the probe count to grow so the wait between probes can.
func TestProbe(t *testing.T) {
	conn := newFakeConn()
	a := newTestAssociation(t, conn)
	frame := queueStream(t, a, 0, 1000)
	a.probe()
	drainWrites(t, a)
	if conn.len() != 2 {
		t.Fatalf("%d packets written", conn.len())
	}
	payloads := conn.payloads(t, &a.sendRing)
	if !bytes.Equal(payloads[1], frame) {
		t.Fatal("the probe did not carry the frame that was in flight")
	}
	a.flightMu.Lock()
	probes := a.probes
	inFlight := a.inFlight.len()
	a.flightMu.Unlock()
	if probes != 1 {
		t.Fatalf("%d probes counted", probes)
	}
	if inFlight != 1 {
		t.Fatalf("%d packets in flight after a probe", inFlight)
	}
}

// TestProbeWithoutData requires a probe to ask a silent peer for an answer even
// when nothing in flight has to be sent again.
func TestProbeWithoutData(t *testing.T) {
	conn := newFakeConn()
	a := newTestAssociation(t, conn)
	err := a.send(appendPing(nil))
	if err != nil {
		t.Fatal(err)
	}
	a.probe()
	drainWrites(t, a)
	payloads := conn.payloads(t, &a.sendRing)
	if len(payloads) != 2 {
		t.Fatalf("%d packets written", len(payloads))
	}
	if !bytes.Equal(payloads[1], appendPing(nil)) {
		t.Fatal("the probe was not a ping")
	}
}

// TestProbingIsBounded requires probing a peer that never answers to cost one
// packet per probe: memory and the queue must not grow with the number of
// probes.
func TestProbingIsBounded(t *testing.T) {
	conn := newFakeConn()
	a := newTestAssociation(t, conn)
	queueStream(t, a, 0, 1000)
	for range 100 {
		a.probe()
	}
	a.sendMu.Lock()
	queued := a.queue.len()
	a.sendMu.Unlock()
	a.flightMu.Lock()
	inFlight := a.inFlight.len()
	a.flightMu.Unlock()
	// The frame is either queued or in one packet, however many probes went out:
	// probing neither loses it nor multiplies it, and the congestion window is what
	// stops the probes from filling the path.
	if queued+inFlight != 1 {
		t.Fatalf("%d frames queued and %d packets in flight after a hundred probes", queued, inFlight)
	}
}

func TestLossDelay(t *testing.T) {
	var estimator rttEstimator
	// A path nobody measured is assumed to have a round trip rather than none,
	// so that a first window is not declared lost before it could be answered.
	if delay := lossDelay(estimator); delay != time.Duration(float64(initialRTT)*timeThreshold)+maxAckDelay {
		t.Fatalf("delay without a sample: %v", delay)
	}
	if timeout := estimator.rto(); timeout != initialRTT {
		t.Fatalf("timeout without a sample: %v", timeout)
	}
	estimator.sample(100 * time.Millisecond)
	// The round trip an estimate is built from has the delay of an acknowledgement
	// taken out of it, so the delay is added back here: a packet is not late while
	// the peer is still allowed to be holding its answer.
	if delay := lossDelay(estimator); delay != 112500*time.Microsecond+maxAckDelay {
		t.Fatalf("delay for a 100ms round trip: %v", delay)
	}
	// The larger of the smoothed and the latest round trip is what counts, so a
	// path that just got slower is not declared to be losing packets.
	estimator.sample(400 * time.Millisecond)
	if delay := lossDelay(estimator); delay < 400*time.Millisecond {
		t.Fatalf("delay after a slow sample: %v", delay)
	}
}
