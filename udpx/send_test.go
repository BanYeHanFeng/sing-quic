package udpx

import (
	"bytes"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"
)

func testFrame(size int) outFrame {
	return outFrame{payload: bytes.Repeat([]byte{byte(frameTypePing)}, size), ackEliciting: true}
}

func TestFrameQueueTake(t *testing.T) {
	var queue frameQueue
	for range 3 {
		queue.push(testFrame(10))
	}
	taken := queue.take(25)
	if len(taken) != 2 {
		t.Fatalf("%d frames taken for a budget of 25 bytes", len(taken))
	}
	if queue.len() != 1 {
		t.Fatalf("%d frames left", queue.len())
	}
	if taken = queue.take(25); len(taken) != 1 {
		t.Fatalf("%d frames taken from the rest", len(taken))
	}
	if queue.len() != 0 {
		t.Fatalf("%d frames left after everything was taken", queue.len())
	}
}

func TestFrameQueueOversized(t *testing.T) {
	var queue frameQueue
	queue.push(testFrame(maxPacketSize))
	if taken := queue.take(maxPacketSize - headerLen - tagLen); taken != nil {
		t.Fatalf("%d frames taken", len(taken))
	}
	if queue.len() != 1 {
		t.Fatal("an oversized frame left the queue")
	}
}

func TestFrameQueuePushFront(t *testing.T) {
	var queue frameQueue
	queue.push(outFrame{payload: []byte{1}, lastSent: 7})
	queue.push(outFrame{payload: []byte{2}, lastSent: 8})
	queue.pushFront([]outFrame{{payload: []byte{3}, lastSent: 5}, {payload: []byte{4}, lastSent: 6}})
	taken := queue.take(100)
	if len(taken) != 4 {
		t.Fatalf("%d frames", len(taken))
	}
	if taken[0].lastSent != 5 || taken[1].lastSent != 6 || taken[2].lastSent != 7 || taken[3].lastSent != 8 {
		t.Fatalf("order %v", []uint32{taken[0].lastSent, taken[1].lastSent, taken[2].lastSent, taken[3].lastSent})
	}
}

func TestInFlightAcked(t *testing.T) {
	var inFlight sentPackets
	for packetNumber := uint32(0); packetNumber < 6; packetNumber++ {
		inFlight.append(&sentPacket{packetNumber: packetNumber, size: 100})
	}
	if inFlight.bytes != 600 {
		t.Fatalf("%d bytes in flight", inFlight.bytes)
	}
	acked, spurious := inFlight.acked([]pnRange{{start: 3, end: 4}})
	if len(acked) != 2 {
		t.Fatalf("%d packets acknowledged", len(acked))
	}
	if spurious != 0 {
		t.Fatalf("%d packets counted as sent twice", spurious)
	}
	if inFlight.len() != 4 || inFlight.bytes != 400 {
		t.Fatalf("%d packets and %d bytes left", inFlight.len(), inFlight.bytes)
	}
	for _, packet := range inFlight.packets {
		if packet.packetNumber == 3 || packet.packetNumber == 4 {
			t.Fatalf("packet %d is still in flight", packet.packetNumber)
		}
	}
	if acked, _ = inFlight.acked([]pnRange{{start: 10, end: 20}}); len(acked) != 0 {
		t.Fatalf("%d packets acknowledged that were never sent", len(acked))
	}
}

func TestInFlightRemove(t *testing.T) {
	var inFlight sentPackets
	first := &sentPacket{packetNumber: 0, size: 100}
	inFlight.append(first)
	inFlight.append(&sentPacket{packetNumber: 1, size: 100})
	inFlight.remove(first)
	if inFlight.len() != 1 || inFlight.bytes != 100 {
		t.Fatalf("%d packets and %d bytes left", inFlight.len(), inFlight.bytes)
	}
	if inFlight.packets[0].packetNumber != 1 {
		t.Fatalf("packet %d left", inFlight.packets[0].packetNumber)
	}
}

func TestInFlightCompaction(t *testing.T) {
	var inFlight sentPackets
	for packetNumber := uint32(0); packetNumber < 100; packetNumber++ {
		inFlight.append(&sentPacket{packetNumber: packetNumber, size: 100})
	}
	acked, _ := inFlight.acked([]pnRange{{start: 0, end: 49}})
	if len(acked) != 50 {
		t.Fatalf("%d packets acknowledged", len(acked))
	}
	if inFlight.len() != 50 {
		t.Fatalf("%d packets in flight", inFlight.len())
	}
	if inFlight.bytes != 5000 {
		t.Fatalf("%d bytes in flight", inFlight.bytes)
	}
	for _, packet := range inFlight.packets {
		if packet.removed {
			t.Fatal("a packet that left the flight table is still in it")
		}
	}
	acked, _ = inFlight.acked([]pnRange{{start: 50, end: 99}})
	if len(acked) != 50 {
		t.Fatalf("%d packets acknowledged", len(acked))
	}
	if inFlight.len() != 0 || inFlight.bytes != 0 {
		t.Fatalf("%d packets and %d bytes in flight", inFlight.len(), inFlight.bytes)
	}
	if oldest := inFlight.oldest(); oldest != nil {
		t.Fatalf("an empty flight table has an oldest packet: %d", oldest.packetNumber)
	}
}

func TestFramesShareOnePacket(t *testing.T) {
	client, _, _ := testSetup(t, Options{}, Options{})
	clientAssociation, isAssociation := client.(*association)
	if !isAssociation {
		t.Fatal("client is not an association")
	}
	for range 3 {
		clientAssociation.queueFrame(appendPing(nil))
	}
	err := clientAssociation.flush()
	if err != nil {
		t.Fatal(err)
	}
	clientAssociation.flightMu.Lock()
	packets := clientAssociation.inFlight.len()
	clientAssociation.flightMu.Unlock()
	if packets != 1 {
		t.Fatalf("three pings left in %d packets", packets)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		clientAssociation.flightMu.Lock()
		packets = clientAssociation.inFlight.len()
		clientAssociation.flightMu.Unlock()
		if packets == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d packets still in flight after an acknowledgement", packets)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestStreamFrameSize(t *testing.T) {
	data := bytes.Repeat([]byte{0x5a}, 100)
	for _, fin := range []bool{false, true} {
		frame := outFrame{
			streamFrame:  streamFrame{carried: true, stream: &Stream{id: 3}, data: data, offset: 7, fin: fin},
			ackEliciting: true,
		}
		encoded := frame.appendTo(nil)
		if len(encoded) != frame.size() {
			t.Fatalf("a stream frame of %d bytes says it takes %d", len(encoded), frame.size())
		}
		if !bytes.Equal(encoded, appendStream(nil, 3, 7, fin, data)) {
			t.Fatalf("a stream frame with fin %v is not the frame it would be", fin)
		}
		if frame.frameType() != frameTypeStream {
			t.Fatalf("a stream frame is of type %d", frame.frameType())
		}
	}
}

func TestStreamWriteAllocatesPerWrite(t *testing.T) {
	client, _, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 30*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	err = stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload(1 << 20)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	written, err := stream.Write(payload)
	runtime.ReadMemStats(&after)
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write: %v", err)
	}
	if written == 0 {
		t.Fatal("a write of 1 MiB wrote nothing")
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	allocations := after.Mallocs - before.Mallocs
	t.Logf("a write of %d bytes allocated %d bytes in %d allocations", written, allocated, allocations)
	if allocated > uint64(written)+uint64(written)*3/4 {
		t.Fatalf("a write of %d bytes allocated %d bytes", written, allocated)
	}
}
