package udpx

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

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

func (c *fakeConn) payloads(t *testing.T, cipher *packetCipher) [][]byte {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	payloads := make([][]byte, 0, len(c.packets))
	for _, packet := range c.packets {
		_, payload, err := cipher.open(packet)
		if err != nil {
			t.Fatalf("open written packet: %v", err)
		}
		payloads = append(payloads, bytes.Clone(payload))
	}
	return payloads
}

func newTestAssociation(t *testing.T, conn net.PacketConn) *association {
	t.Helper()
	a := newAssociation(conn, handshakeResult{
		send: packetCipher{aead: mustAEAD(t, testKey(0x11))},
		recv: packetCipher{aead: mustAEAD(t, testKey(0x22))},
	}, conn.LocalAddr(), Options{IdleTimeout: time.Minute}, false, false)
	t.Cleanup(func() {
		a.shutdown(net.ErrClosed, false)
	})
	return a
}

func testAck(largest uint32, ranges ...pnRange) []byte {
	built := ack{
		largest: largest,
		count:   len(ranges),
	}
	copy(built.ranges[:], ranges)
	return built.appendTo(nil)[1:]
}

func queueStream(t *testing.T, a *association, offset uint64, size int) []byte {
	t.Helper()
	frame := appendStream(nil, 1, offset, false, bytes.Repeat([]byte{byte(offset)}, size))
	a.queueFrame(frame)
	err := a.flush()
	if err != nil {
		t.Fatal(err)
	}
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
	if err := a.flush(); err != nil {
		t.Fatal(err)
	}

	payloads := conn.payloads(t, &a.sendCipher)
	if len(payloads) != 7 {
		t.Fatalf("%d packets written", len(payloads))
	}
	if !bytes.Equal(payloads[5], frames[0]) {
		t.Fatal("the first lost frame was not sent again first")
	}
	if !bytes.Equal(payloads[6], frames[1]) {
		t.Fatal("the second lost frame was not sent again")
	}
	a.flightMu.Lock()
	remaining := a.inFlight.len()
	a.flightMu.Unlock()
	if remaining != 4 {
		t.Fatalf("%d packets in flight", remaining)
	}
}

func TestLossWithTruncatedAck(t *testing.T) {
	packet := &sentPacket{packetNumber: 10, sentAt: time.Now()}
	lossDelay := time.Second
	if !isLost(packet, time.Now(), 20, lossDelay, false) {
		t.Fatal("a packet three behind the largest acknowledged is not lost")
	}
	if isLost(packet, time.Now(), 20, lossDelay, true) {
		t.Fatal("a packet the acknowledgement had no room to name is lost")
	}
	if !isLost(packet, time.Now().Add(2*lossDelay), 20, lossDelay, true) {
		t.Fatal("a packet in flight for longer than the round trip is not lost")
	}
}

func TestLossByTimeThreshold(t *testing.T) {
	conn := newFakeConn()
	a := newTestAssociation(t, conn)
	frames := make([][]byte, 3)
	for index := range frames {
		frames[index] = queueStream(t, a, uint64(index)*1000, 1000)
	}
	now := time.Now()
	a.handleAck(testAck(2, pnRange{start: 2, end: 2}), now)
	if err := a.flush(); err != nil {
		t.Fatal(err)
	}
	if written := conn.len(); written != 3 {
		t.Fatalf("%d packets written before the delay passed", written)
	}
	a.handleAck(testAck(2, pnRange{start: 2, end: 2}), now.Add(time.Second))
	if err := a.flush(); err != nil {
		t.Fatal(err)
	}
	payloads := conn.payloads(t, &a.sendCipher)
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
	if err := a.flush(); err != nil {
		t.Fatal(err)
	}
	payloads := conn.payloads(t, &a.sendCipher)
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

func TestProbe(t *testing.T) {
	conn := newFakeConn()
	a := newTestAssociation(t, conn)
	frame := queueStream(t, a, 0, 1000)
	a.probe()
	if err := a.flush(); err != nil {
		t.Fatal(err)
	}
	if conn.len() != 2 {
		t.Fatalf("%d packets written", conn.len())
	}
	payloads := conn.payloads(t, &a.sendCipher)
	if !bytes.Equal(payloads[1], appendPing(nil)) {
		t.Fatal("the probe was not a ping")
	}
	if bytes.Equal(payloads[1], frame) {
		t.Fatal("the probe carried the frame that was in flight")
	}
	a.flightMu.Lock()
	probes := a.probes
	inFlight := a.inFlight.len()
	a.flightMu.Unlock()
	if probes != 1 {
		t.Fatalf("%d probes counted", probes)
	}
	if inFlight != 2 {
		t.Fatalf("%d packets in flight after a probe", inFlight)
	}
}

func TestProbeWithoutData(t *testing.T) {
	conn := newFakeConn()
	a := newTestAssociation(t, conn)
	err := a.send(appendPing(nil))
	if err != nil {
		t.Fatal(err)
	}
	if err = a.flush(); err != nil {
		t.Fatal(err)
	}
	a.probe()
	if err = a.flush(); err != nil {
		t.Fatal(err)
	}
	payloads := conn.payloads(t, &a.sendCipher)
	if len(payloads) != 2 {
		t.Fatalf("%d packets written", len(payloads))
	}
	if !bytes.Equal(payloads[1], appendPing(nil)) {
		t.Fatal("the probe was not a ping")
	}
}

func TestProbingIsBounded(t *testing.T) {
	conn := newFakeConn()
	a := newTestAssociation(t, conn)
	queueStream(t, a, 0, 1000)
	for range 100 {
		a.probe()
	}
	if err := a.flush(); err != nil {
		t.Fatal(err)
	}
	a.flightMu.Lock()
	carried := 0
	pings := 0
	for _, packet := range a.inFlight.packets {
		if packet.removed {
			continue
		}
		for _, frame := range packet.frames {
			switch frame.frameType() {
			case frameTypeStream:
				carried++
			case frameTypePing:
				pings++
			}
		}
	}
	a.flightMu.Unlock()
	if carried != 1 || pings != 100 {
		t.Fatalf("the frame is in flight %d times with %d pings after a hundred probes", carried, pings)
	}
}

func TestLossDelay(t *testing.T) {
	var estimator rttEstimator
	if delay := lossDelay(estimator); delay != time.Duration(float64(initialRTT)*timeThreshold)+maxAckDelay {
		t.Fatalf("delay without a sample: %v", delay)
	}
	if timeout := estimator.rto(); timeout != initialRTT {
		t.Fatalf("timeout without a sample: %v", timeout)
	}
	estimator.sample(100 * time.Millisecond)
	if delay := lossDelay(estimator); delay != 112500*time.Microsecond+maxAckDelay {
		t.Fatalf("delay for a 100ms round trip: %v", delay)
	}
	estimator.sample(400 * time.Millisecond)
	if delay := lossDelay(estimator); delay < 400*time.Millisecond {
		t.Fatalf("delay after a slow sample: %v", delay)
	}
}

func TestReachable(t *testing.T) {
	conn := newFakeConn()
	a := newTestAssociation(t, conn)
	if !a.Reachable() {
		t.Fatal("an association that has asked nothing is not reachable")
	}
	queueStream(t, a, 0, 1000)
	a.probe()
	if !a.Reachable() {
		t.Fatal("a path that was just asked is not reachable")
	}
	a.flightMu.Lock()
	a.probeSince = time.Now().Add(-quietPathBudget)
	a.flightMu.Unlock()
	if a.Reachable() {
		t.Fatal("a path that has been asked for the whole budget is still reachable")
	}
	a.handleAck(testAck(0, pnRange{start: 0, end: 0}), time.Now())
	if !a.Reachable() {
		t.Fatal("a path that answered is not reachable")
	}
}

func TestProbeTimeout(t *testing.T) {
	conn := newFakeConn()
	a := newTestAssociation(t, conn)
	queueStream(t, a, 0, 1000)
	a.flightMu.Lock()
	a.probes = 1
	a.probeSince = time.Now().Add(-maxProbeSilence)
	a.flightMu.Unlock()
	a.probe()
	select {
	case <-a.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the association outlived a peer that answered nothing")
	}
	if cause := context.Cause(a.Context()); !errors.Is(cause, ErrProbeTimeout) {
		t.Fatalf("the association ended with %v", cause)
	}
}

func TestProbeSurvivesAnAnswer(t *testing.T) {
	conn := newFakeConn()
	a := newTestAssociation(t, conn)
	queueStream(t, a, 0, 1000)
	a.flightMu.Lock()
	a.probes = 3
	a.probeSince = time.Now().Add(-maxProbeSilence / 2)
	a.flightMu.Unlock()
	a.handleAck(testAck(0, pnRange{start: 0, end: 0}), time.Now())
	a.flightMu.Lock()
	probes := a.probes
	since := a.probeSince
	a.flightMu.Unlock()
	if probes != 0 {
		t.Fatalf("%d probes after an answer", probes)
	}
	if !since.IsZero() {
		t.Fatalf("probe start %v after an answer", since)
	}
}

func TestProbeSurvivesAnAnswerThatSettlesNothing(t *testing.T) {
	conn := newFakeConn()
	a := newTestAssociation(t, conn)
	queueStream(t, a, 0, 1000)
	a.handleAck(testAck(0, pnRange{start: 0, end: 0}), time.Now())
	if err := a.flush(); err != nil {
		t.Fatal(err)
	}
	a.flightMu.Lock()
	a.probes = 3
	a.probeSince = time.Now().Add(-maxProbeSilence / 2)
	a.flightMu.Unlock()
	a.handleAck(testAck(0, pnRange{start: 0, end: 0}), time.Now())
	a.flightMu.Lock()
	probes := a.probes
	since := a.probeSince
	a.flightMu.Unlock()
	if probes != 0 {
		t.Fatalf("%d probes after an answer that settled nothing", probes)
	}
	if !since.IsZero() {
		t.Fatalf("probe start %v after an answer that settled nothing", since)
	}
}
