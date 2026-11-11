package udpx

import (
	"io"
	"testing"
	"time"
)

// TestTakeSplitsAFrameThatNoLongerFits requires a frame cut for a packet larger
// than the one the association now sends with to still leave: what a packet
// carries falls when the path refuses a larger size and moves when the redundancy
// is turned on or off, and a frame that never fits is a queue that never hands out
// its head.
func TestTakeSplitsAFrameThatNoLongerFits(t *testing.T) {
	stream := &Stream{sendPending: 1}
	data := make([]byte, 1000)
	var queue frameQueue
	queue.push(outFrame{
		streamFrame:  streamFrame{carried: true, stream: stream, data: data, offset: 40},
		ackEliciting: true,
	})
	head := queue.take(400)
	if len(head) != 1 {
		t.Fatalf("%d frames were taken for one packet", len(head))
	}
	if head[0].size() != 400 {
		t.Fatalf("the head frame is %d bytes in a packet of 400", head[0].size())
	}
	if head[0].streamFrame.offset != 40 {
		t.Fatalf("the head frame starts at %d", head[0].streamFrame.offset)
	}
	tail := queue.take(4000)
	if len(tail) != 1 {
		t.Fatalf("%d frames were left behind the head", len(tail))
	}
	if tail[0].streamFrame.offset != 40+400-streamFixedLen {
		t.Fatalf("the rest of the frame starts at %d", tail[0].streamFrame.offset)
	}
	if len(tail[0].streamFrame.data) != 1000-(400-streamFixedLen) {
		t.Fatalf("the rest of the frame is %d bytes", len(tail[0].streamFrame.data))
	}
	if stream.sendPending != 2 {
		t.Fatalf("the split frame is counted %d times", stream.sendPending)
	}
}

// TestStreamSurvivesPacketSizeDrop requires a transfer to keep going when the size
// a packet carries falls under a queue that was cut for the larger one, which is
// what a path that refuses a size and a redundancy that turns itself back on both
// do in the middle of a transfer.
func TestStreamSurvivesPacketSizeDrop(t *testing.T) {
	packetSizeDropTransfer(t, FECOptions{})
}

// TestStreamSurvivesPacketSizeDropWithFEC is the same transfer with the packets
// protected, where the size a packet carries is the smaller of the two: a member
// gives up the room the description of its group needs.
func TestStreamSurvivesPacketSizeDropWithFEC(t *testing.T) {
	packetSizeDropTransfer(t, FECOptions{DataShards: 32, ParityShards: 2})
}

func packetSizeDropTransfer(t *testing.T, fec FECOptions) {
	t.Helper()
	client, server, _ := testSetup(t, Options{}, Options{FEC: fec})
	stream, err := client.OpenStream(testContext(t, 10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	_, err = stream.Write([]byte("ping"))
	if err != nil {
		t.Fatal(err)
	}
	serverStream, err := server.AcceptStream(testContext(t, 10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	request := make([]byte, 4)
	_, err = io.ReadFull(serverStream, request)
	if err != nil {
		t.Fatal(err)
	}
	const chunkSize = 16 << 10
	const chunks = 64
	writeDone := make(chan error, 1)
	go func() {
		for index := 0; index < chunks; index++ {
			if _, writeErr := serverStream.Write(make([]byte, chunkSize)); writeErr != nil {
				writeDone <- writeErr
				return
			}
			if index == 4 {
				// The queue holds what the window did not let out, cut for the
				// size the association was sending with.
				association := server.(*association)
				association.sendMu.Lock()
				association.mtu = 1232
				association.updatePayloadLocked()
				association.sendMu.Unlock()
			}
		}
		writeDone <- nil
	}()
	read := make([]byte, chunkSize*chunks)
	done := make(chan error, 1)
	go func() {
		_, readErr := io.ReadFull(stream, read)
		done <- readErr
	}()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the transfer stopped when the packet size fell")
	}
	if err = <-writeDone; err != nil {
		t.Fatal(err)
	}
}
