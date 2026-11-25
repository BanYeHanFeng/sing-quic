package udpx

import (
	"io"
	"net"
	"testing"
	"time"
)

func testMTUState(candidates ...int) mtuState {
	return mtuState{candidates: candidates}
}

func TestMTUNext(t *testing.T) {
	state := testMTUState(1452, 1352, 1232, 1200)
	candidate, loaded := state.next(1200)
	if !loaded || candidate != 1452 {
		t.Fatalf("candidate %d", candidate)
	}
	state.dropValue(1452)
	if candidate, loaded = state.next(1200); !loaded || candidate != 1352 {
		t.Fatalf("candidate %d", candidate)
	}
}

func TestMTUStepDown(t *testing.T) {
	state := testMTUState(1452, 1352, 1232, 1200)
	next, loaded := state.nextBelow(1452)
	if !loaded || next != 1352 {
		t.Fatalf("next %d", next)
	}
	if _, loaded = state.nextBelow(1200); loaded {
		t.Fatal("stepped below the smallest candidate")
	}
}

func TestMTUFixed(t *testing.T) {
	var state mtuState
	state.init(1200, 1280, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if _, loaded := state.next(1200); loaded {
		t.Fatal("a fixed mtu was probed")
	}
}

func TestMTUCandidatesForTheAddressFamily(t *testing.T) {
	if candidates := mtuCandidatesFor(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}); candidates[0] != mtuIPv4 {
		t.Fatalf("IPv4 starts at %d", candidates[0])
	}
	if candidates := mtuCandidatesFor(&net.UDPAddr{IP: net.ParseIP("::1")}); candidates[0] != mtuIPv6 {
		t.Fatalf("IPv6 starts at %d", candidates[0])
	}
}

func TestMTUProbeRaisesTheSize(t *testing.T) {
	credential := NewCredential("password")
	listenerConn := udpConn(t)
	listener := Listen(listenerConn, testVerifier{credential: credential}, Options{})
	defer listener.Close()
	link := newSimulatedLink(t, listenerConn.LocalAddr(), linkOptions{})
	ctx := testContext(t, 20*time.Second)
	client, err := Dial(ctx, udpConn(t), link.clientAddr(), credential, Options{})
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
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			if _, writeErr := stream.Write(testPayload(64 * 1024)); writeErr != nil {
				return
			}
		}
	}()
	go func() {
		_, _ = io.Copy(io.Discard, stream)
	}()
	go func() {
		for {
			if _, writeErr := accepted.Write(testPayload(64 * 1024)); writeErr != nil {
				return
			}
		}
	}()
	go func() {
		_, _ = io.Copy(io.Discard, accepted)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if link.largestFromClient() == mtuIPv4 && link.largestFromServer() == mtuIPv4 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("largest packets: %d from the client, %d from the server", link.largestFromClient(), link.largestFromServer())
}
