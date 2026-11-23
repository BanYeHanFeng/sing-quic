package udpx

import (
	"testing"
	"time"
)

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
	if inFlight > 500 {
		t.Fatalf("%d packets in flight at once", inFlight)
	}
	if inFlight == 0 {
		t.Fatal("nothing was in flight")
	}
}

func TestInitialCongestionWindow(t *testing.T) {
	controller := newCongestionController()
	want := initialCongestionWindowPackets * maxPacketSize
	if window := int(controller.GetCongestionWindow()); window != want {
		t.Errorf("initial window is %d bytes, want %d", window, want)
	}
}
