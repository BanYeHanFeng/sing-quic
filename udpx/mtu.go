package udpx

import (
	"net"
	"slices"
	"time"
)

const (
	mtuIPv4 = 1452
	mtuIPv6 = 1232

	mtuMin = 1200

	mtuProbeTimeout = time.Second
)

var (
	mtuCandidatesIPv4 = []int{mtuIPv4, 1352, 1232, mtuMin}
	mtuCandidatesIPv6 = []int{mtuIPv6, mtuMin}
)

func mtuCandidatesFor(remote net.Addr) []int {
	if udpAddr, isUDPAddr := remote.(*net.UDPAddr); isUDPAddr && udpAddr.IP.To4() == nil {
		return slices.Clone(mtuCandidatesIPv6)
	}
	return slices.Clone(mtuCandidatesIPv4)
}

type mtuState struct {
	candidates []int

	active    bool
	packet    uint32
	candidate int
	deadline  time.Time
}

func (m *mtuState) init(fixedMTU int, remote net.Addr) {
	if fixedMTU > 0 {
		return
	}
	m.candidates = mtuCandidatesFor(remote)
}

func (m *mtuState) next(current int) (int, bool) {
	for _, candidate := range m.candidates {
		if candidate > current {
			return candidate, true
		}
	}
	return 0, false
}

func (m *mtuState) nextBelow(current int) (int, bool) {
	next := 0
	for _, candidate := range m.candidates {
		if candidate < current && candidate > next {
			next = candidate
		}
	}
	if next == 0 {
		return 0, false
	}
	m.dropFrom(next)
	return next, true
}

func (m *mtuState) start(candidate int, packetNumber uint32, now time.Time) {
	m.active = true
	m.candidate = candidate
	m.packet = packetNumber
	m.deadline = now.Add(mtuProbeTimeout)
}

func (m *mtuState) confirm() {
	m.dropValue(m.candidate)
}

func (m *mtuState) dropCandidate() {
	m.dropValue(m.candidate)
}

func (m *mtuState) dropValue(value int) {
	kept := m.candidates[:0]
	for _, candidate := range m.candidates {
		if candidate == value {
			continue
		}
		kept = append(kept, candidate)
	}
	m.candidates = kept
	m.active = false
}

func (m *mtuState) dropFrom(value int) {
	kept := m.candidates[:0]
	for _, candidate := range m.candidates {
		if candidate >= value {
			continue
		}
		kept = append(kept, candidate)
	}
	m.candidates = kept
}
