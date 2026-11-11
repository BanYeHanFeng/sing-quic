package udpx

import (
	"testing"
)

// TestMTUProbeRetriesALostProbe requires a size that went unanswered to be asked
// about again before it is ruled out. A probe lost to a path that drops packets
// says nothing about the size it asked about, and a search that reads the loss as
// an answer sends with the smallest size every path carries for the length of the
// session.
func TestMTUProbeRetriesALostProbe(t *testing.T) {
	conn := newFakeConn()
	a := newTestAssociation(t, conn)
	a.timers.Load().pto.Stop()
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
	// The last attempt is what rules it out, and the next size down is what the
	// search asks about instead.
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

// TestMTUProbeRaisesTheSize requires the size a probe confirmed to be the size the
// association sends with, and the payload budget to follow it.
func TestMTUProbeRaisesTheSize(t *testing.T) {
	conn := newFakeConn()
	a := newTestAssociation(t, conn)
	a.timers.Load().pto.Stop()
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
