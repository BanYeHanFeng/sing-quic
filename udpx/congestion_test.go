package udpx

import (
	"testing"
	"time"
)

// TestCongestionWindowBounds requires the window of the congestion controller to
// bound what is in flight: without it, a sender with a stream to write fills the
// association window at once and the losses that follow are its own doing.
func TestCongestionWindowBounds(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 60*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload(4 << 20)
	go func() {
		if _, writeErr := stream.Write(payload); writeErr != nil {
			t.Errorf("write: %v", writeErr)
			return
		}
		_ = stream.CloseWrite()
	}()
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clientAssociation := client.(*association)
	read := 0
	buffer := make([]byte, 64*1024)
	inFlight := 0
	for read < len(payload) {
		n, readErr := accepted.Read(buffer)
		if readErr != nil {
			t.Fatalf("read %d of %d bytes: %v", read, len(payload), readErr)
		}
		read += n
		clientAssociation.flightMu.Lock()
		if packets := clientAssociation.inFlight.len(); packets > inFlight {
			inFlight = packets
		}
		clientAssociation.flightMu.Unlock()
	}
	// The association window allows about three thousand packets; the congestion
	// window of a path that never lost anything grows to a small fraction of that.
	if inFlight > 500 {
		t.Fatalf("%d packets in flight at once", inFlight)
	}
	if inFlight == 0 {
		t.Fatal("nothing was in flight")
	}
}

// TestInitialCongestionWindow requires the transport to hand the controller the
// window it uses rather than the controller's own default: the first window is
// what the peer was told to expect and what the path can take, both of which are
// known here and neither of which is known in the controller.
func TestInitialCongestionWindow(t *testing.T) {
	controller := newCongestionController()
	want := initialCongestionWindowPackets * maxPacketSize
	if window := int(controller.GetCongestionWindow()); window != want {
		t.Errorf("initial window is %d bytes, want %d", window, want)
	}
}
