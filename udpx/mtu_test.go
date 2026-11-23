package udpx

import (
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
	state.init(1280, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
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
	client, server, _ := testSetup(t, Options{}, Options{})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if client.(*association).mtuSize() == mtuIPv4 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if size := client.(*association).mtuSize(); size != mtuIPv4 {
		t.Fatalf("the client settled on %d", size)
	}
	if size := server.(*association).mtuSize(); size != mtuIPv4 {
		t.Fatalf("the server settled on %d", size)
	}
}

func TestMTUProbeIsSentAlone(t *testing.T) {
	client, _, _ := testSetup(t, Options{MTU: 0}, Options{})
	a := client.(*association)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		a.txMu.Lock()
		probing := a.tx.mtu.active || len(a.tx.mtu.candidates) > 0
		a.txMu.Unlock()
		if !probing {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the mtu probe never finished")
}

func TestMTUProbeTimeoutSkipsTheCandidate(t *testing.T) {
	state := testMTUState(1452, 1352)
	state.start(1452, 3, time.Now().Add(-time.Second))
	if !state.active || state.candidate != 1452 {
		t.Fatal("the probe did not start")
	}
	state.dropCandidate()
	if state.active {
		t.Fatal("the probe is still active")
	}
	if candidate, loaded := state.next(1200); !loaded || candidate != 1352 {
		t.Fatalf("candidate %d", candidate)
	}
}
