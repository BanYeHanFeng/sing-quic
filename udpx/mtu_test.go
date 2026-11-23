package udpx

import (
	"testing"
)

func TestMTUProbeRetriesALostProbe(t *testing.T) {
	conn := newFakeConn()
	a := newTestAssociation(t, conn)
	a.startMTUProbe()
	a.sendMu.Lock()
	if !a.mtuProbe.active {
		a.sendMu.Unlock()
		t.Fatal("no probe after the search started")
	}
	candidate := a.mtuProbe.candidate
	packetNumber := a.mtuProbe.packetNumber
	a.sendMu.Unlock()
	if candidate != mtuIPv4 {
		t.Fatalf("probe of %d bytes, want %d", candidate, mtuIPv4)
	}
	for attempt := 1; attempt < mtuProbeAttempts; attempt++ {
		a.mtuProbeTimeout(packetNumber)
		a.sendMu.Lock()
		if !a.mtuProbe.active || a.mtuProbe.candidate != candidate {
			a.sendMu.Unlock()
			t.Fatalf("size %d was ruled out after %d unanswered probes", candidate, attempt)
		}
		if a.mtuProbe.attempts != attempt {
			attempts := a.mtuProbe.attempts
			a.sendMu.Unlock()
			t.Fatalf("probe %d of %d is attempt %d, want %d", attempts, candidate, attempts, attempt)
		}
		packetNumber = a.mtuProbe.packetNumber
		a.sendMu.Unlock()
	}
	a.mtuProbeTimeout(packetNumber)
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	for _, known := range a.mtuCandidates {
		if known == candidate {
			t.Fatalf("size %d is still a candidate after %d unanswered probes", candidate, mtuProbeAttempts)
		}
	}
	if a.mtuProbe.active && a.mtuProbe.candidate == candidate {
		t.Fatalf("size %d is still being probed", candidate)
	}
}

func TestMTUProbeStaysOutOfFlight(t *testing.T) {
	conn := newFakeConn()
	a := newTestAssociation(t, conn)
	a.startMTUProbe()
	if conn.len() != 1 {
		t.Fatalf("%d packets written, want the probe", conn.len())
	}
	a.flightMu.Lock()
	inFlight := a.inFlight.len()
	flightBytes := a.inFlight.bytes
	a.flightMu.Unlock()
	if inFlight != 0 || flightBytes != 0 {
		t.Fatalf("%d packets of %d bytes in flight after an mtu probe, want none", inFlight, flightBytes)
	}
	if charged := a.congestionCharged(); charged != 0 {
		t.Fatalf("an mtu probe charged %d bytes to the window", charged)
	}
}

func TestMTUProbeRaisesTheSize(t *testing.T) {
	conn := newFakeConn()
	a := newTestAssociation(t, conn)
	a.startMTUProbe()
	a.sendMu.Lock()
	packetNumber := a.mtuProbe.packetNumber
	candidate := a.mtuProbe.candidate
	a.sendMu.Unlock()
	confirmation := ack{largest: packetNumber, count: 1}
	confirmation.ranges[0] = pnRange{start: packetNumber, end: packetNumber}
	if !a.mtuProbeConfirmed(confirmation) {
		t.Fatal("the probe was not confirmed")
	}
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	if a.mtu != candidate {
		t.Fatalf("mtu %d after confirmation, want %d", a.mtu, candidate)
	}
	if a.maxPayload != a.mtu-headerLen-tagLen {
		t.Fatalf("payload of %d bytes, want %d", a.maxPayload, a.mtu-headerLen-tagLen)
	}
}
