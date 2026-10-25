package udpx

import (
	"bytes"
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

func TestContainsPacketNumber(t *testing.T) {
	ranges := []pnRange{{start: 10, end: 12}, {start: 4, end: 5}}
	for _, test := range []struct {
		packetNumber uint32
		contained    bool
	}{
		{12, true}, {10, true}, {11, true},
		{9, false}, {13, false}, {5, true}, {4, true}, {3, false}, {0, false},
	} {
		if containsPacketNumber(ranges, test.packetNumber) != test.contained {
			t.Fatalf("packet %d: contained %v", test.packetNumber, !test.contained)
		}
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
