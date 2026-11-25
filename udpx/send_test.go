package udpx

import (
	"testing"
	"time"
)

func testSentPacket(packetNumber uint32, size int) *sentPacket {
	return &sentPacket{
		sentAt:       time.Now(),
		packetNumber: packetNumber,
		size:         size,
		ackEliciting: true,
	}
}

func TestInFlightAcked(t *testing.T) {
	var flight inFlight
	for index := range 4 {
		flight.append(testSentPacket(uint32(index), 100))
	}
	acked := flight.ack([]pnRange{{start: 1, end: 2}})
	if len(acked) != 2 || acked[0].packetNumber != 1 || acked[1].packetNumber != 2 {
		t.Fatalf("acked %d packets", len(acked))
	}
	if flight.len() != 2 || flight.bytes != 200 {
		t.Fatalf("%d packets, %d bytes are in flight", flight.len(), flight.bytes)
	}
}

func TestInFlightLostByPacketThreshold(t *testing.T) {
	var flight inFlight
	for index := range 6 {
		flight.append(testSentPacket(uint32(index), 100))
	}
	lost := flight.lost(time.Now(), 5, time.Hour, false)
	if len(lost) != 3 {
		t.Fatalf("%d packets were declared lost", len(lost))
	}
	if flight.len() != 3 {
		t.Fatalf("%d packets are in flight", flight.len())
	}
}

func TestInFlightLostByTime(t *testing.T) {
	var flight inFlight
	old := testSentPacket(0, 100)
	old.sentAt = time.Now().Add(-time.Hour)
	flight.append(old)
	fresh := testSentPacket(1, 100)
	flight.append(fresh)
	lost := flight.lost(time.Now(), 1, 100*time.Millisecond, true)
	if len(lost) != 1 || lost[0].packetNumber != 0 {
		t.Fatalf("%d packets were declared lost", len(lost))
	}
	if flight.len() != 1 {
		t.Fatalf("%d packets are in flight", flight.len())
	}
}

func TestInFlightKeepsUnacknowledged(t *testing.T) {
	var flight inFlight
	flight.append(testSentPacket(5, 100))
	if lost := flight.lost(time.Now(), 4, time.Millisecond, false); lost != nil {
		t.Fatal("c packet was declared lost without evidence")
	}
}

func TestTakePrefixStopsAtTheBudget(t *testing.T) {
	queue := []outFrame{
		{payload: appendPingFrame(nil), ackEliciting: true},
		{payload: append(appendStreamHeader(nil, 1, 0, false, 10), make([]byte, 10)...), ackEliciting: true},
	}
	taken := takePrefix(&queue, 28, true)
	if len(taken) != 2 {
		t.Fatalf("%d frames fit", len(taken))
	}
	if len(queue) != 0 {
		t.Fatalf("%d frames are left", len(queue))
	}
}

func TestTakePrefixHonoursOnePacket(t *testing.T) {
	queue := []outFrame{
		{payload: append(appendStreamHeader(nil, 1, 0, false, 40), make([]byte, 40)...), ackEliciting: true},
		{payload: appendPingFrame(nil), ackEliciting: true},
	}
	taken := takePrefix(&queue, 55, true)
	if len(taken) != 1 {
		t.Fatalf("%d frames were taken", len(taken))
	}
	if len(queue) != 1 {
		t.Fatalf("%d frames are left", len(queue))
	}
}

func TestTakePrefixWithoutDataTakesOnlyAcknowledgements(t *testing.T) {
	queue := []outFrame{
		{payload: append(appendStreamHeader(nil, 1, 0, false, 10), make([]byte, 10)...), ackEliciting: true},
	}
	if taken := takePrefix(&queue, maxPayload(), false); taken != nil {
		t.Fatal("data was taken while the congestion window was closed")
	}
	if len(queue) != 1 {
		t.Fatal("the queue lost c frame")
	}
}

func maxPayload() int {
	return maxPacketSize - headerLen - tagLen
}

func TestSplitHeadCutsAnOversizedFrame(t *testing.T) {
	c, _, _ := testSetup(t, Options{MTU: mtuIPv4}, Options{MTU: mtuIPv4})
	conn := c
	stream := newStream(conn, 1, initialStreamWindow)
	data := testPayload(1000)
	frame := newStreamFrame(stream, 0, true, data)
	send := &sender{conn: conn}
	send.queue = []outFrame{frame}
	send.splitHead(streamHeaderLen + 400)
	if len(send.queue) != 2 {
		t.Fatalf("%d frames after the split", len(send.queue))
	}
	first := parseStreamFrame(send.queue[0].payload[0], send.queue[0].payload[frameHeaderLen:])
	second := parseStreamFrame(send.queue[1].payload[0], send.queue[1].payload[frameHeaderLen:])
	if len(first.data) != 400 || first.fin {
		t.Fatalf("the first half has %d bytes and fin=%v", len(first.data), first.fin)
	}
	if len(second.data) != 600 || !second.fin {
		t.Fatalf("the second half has %d bytes and fin=%v", len(second.data), second.fin)
	}
	if second.offset != 400 {
		t.Fatalf("the second half starts at %d", second.offset)
	}
	combined := append(append([]byte(nil), first.data...), second.data...)
	if string(combined) != string(data) {
		t.Fatal("the halves do not add up")
	}
	releaseFrames(send.queue)
}

func TestSplitHeadLeavesFittingFramesAlone(t *testing.T) {
	c, _, _ := testSetup(t, Options{MTU: mtuIPv4}, Options{MTU: mtuIPv4})
	conn := c
	stream := newStream(conn, 1, initialStreamWindow)
	frame := newStreamFrame(stream, 0, false, testPayload(10))
	send := &sender{conn: conn}
	send.queue = []outFrame{frame}
	send.splitHead(streamHeaderLen + 100)
	if len(send.queue) != 1 {
		t.Fatalf("%d frames", len(send.queue))
	}
	releaseFrames(send.queue)
}

func TestRetransmittable(t *testing.T) {
	for _, typeNumber := range []uint8{frameTypeStream, frameTypeMaxData, frameTypeMaxStreamData, frameTypeResetStream, frameTypeMaxStreams} {
		if !retransmittable(typeNumber) {
			t.Fatalf("frame %d is not retransmitted", typeNumber)
		}
	}
	for _, typeNumber := range []uint8{frameTypePadding, frameTypePing, frameTypeClose, frameTypeAck, frameTypeDatagram} {
		if retransmittable(typeNumber) {
			t.Fatalf("frame %d is retransmitted", typeNumber)
		}
	}
}
