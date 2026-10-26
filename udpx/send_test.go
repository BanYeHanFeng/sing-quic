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
	// The rest goes out in the next packet.
	if taken = queue.take(25); len(taken) != 1 {
		t.Fatalf("%d frames taken from the rest", len(taken))
	}
	if queue.len() != 0 {
		t.Fatalf("%d frames left after everything was taken", queue.len())
	}
}

// TestFrameQueueOversized requires a frame that cannot fit in a packet on its own
// to stay in the queue rather than being split or dropped: the caller sees it and
// can complain.
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
	// Retransmissions go out first, and the oldest of them goes out first of all.
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
	acked := inFlight.acked([]pnRange{{start: 3, end: 4}})
	if len(acked) != 2 {
		t.Fatalf("%d packets acknowledged", len(acked))
	}
	if inFlight.len() != 4 || inFlight.bytes != 400 {
		t.Fatalf("%d packets and %d bytes left", inFlight.len(), inFlight.bytes)
	}
	// What was acknowledged is gone, and what was not is still there.
	for _, packet := range inFlight.packets {
		if packet.packetNumber == 3 || packet.packetNumber == 4 {
			t.Fatalf("packet %d is still in flight", packet.packetNumber)
		}
	}
	if acked = inFlight.acked([]pnRange{{start: 10, end: 20}}); len(acked) != 0 {
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

// TestInFlightCompaction requires the flight table to drop what left it and to
// count only what is still in flight, which is what keeps an acknowledgement from
// costing a pass over the whole table.
func TestInFlightCompaction(t *testing.T) {
	var inFlight sentPackets
	for packetNumber := uint32(0); packetNumber < 100; packetNumber++ {
		inFlight.append(&sentPacket{packetNumber: packetNumber, size: 100})
	}
	acked := inFlight.acked([]pnRange{{start: 0, end: 49}})
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
	acked = inFlight.acked([]pnRange{{start: 50, end: 99}})
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

// TestFramesShareOnePacket requires small frames queued together to be packed
// into one packet instead of each costing a packet, and the acknowledgement that
// follows to take the packet back out of flight.
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

	// The peer acknowledges the packet, and it leaves the flight table.
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

// TestStreamFrameSize requires the bytes a stream frame says it takes to be the
// bytes it encodes. A stream frame is the one frame that is measured before it is
// encoded — the queue has to know what fits in a packet — so a size that disagrees
// with the encoding would put either more or less in a packet than the packet
// holds.
func TestStreamFrameSize(t *testing.T) {
	data := bytes.Repeat([]byte{0x5a}, 100)
	for _, fin := range []bool{false, true} {
		frame := outFrame{
			stream:       streamFrame{carried: true, data: data, offset: 7, streamID: 3, fin: fin},
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

// TestStreamWriteAllocatesPerWrite requires writing to a stream to cost the write
// and not the frames it becomes. A stream frame carries a piece of the write, so
// encoding it when it is queued copies every byte of the transfer once more and
// turns one allocation per write into one per 1.4 KB of it, which is what made the
// send path allocate twice the payload. The peer reads none of this, so what is
// counted here is the send path alone.
func TestStreamWriteAllocatesPerWrite(t *testing.T) {
	client, _, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 30*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The write stops when it has filled the windows, which is what keeps this
	// measurement independent of how large they are: what it wrote is what it
	// allocated for.
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
	allocations := after.Mallocs - before.Mallocs
	t.Logf("a write of %d bytes allocated %d bytes in %d allocations", written, after.TotalAlloc-before.TotalAlloc, allocations)
	// One allocation per 64 KiB of payload is generous for the chunks a write
	// becomes, and it is an order of magnitude below the one per frame this test
	// exists to catch.
	if allocations > 128+uint64(written)/(64<<10) {
		t.Fatalf("a write of %d bytes took %d allocations", written, allocations)
	}
}
