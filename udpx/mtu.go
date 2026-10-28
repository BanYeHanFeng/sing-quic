package udpx

// Path MTU discovery
//
// A packet that is larger than the smallest link between the two ends is a packet
// that does not arrive, and the transport has no way to learn that from the
// acknowledgement that never comes: it looks exactly like loss. So the size a
// packet may be is discovered rather than assumed, by sending a packet of the size
// in question and waiting to see whether it is answered.
//
// The search starts at what the address family allows and walks down a short list
// of sizes that matter in practice: an IPv4 path is 1500 unless something between
// the ends tunnels it, an IPv6 path is never less than 1280, and 1200 is what every
// path in the world carries. A size that is answered is the size the association
// uses; a size that is not is the next one down, and the probe is sent again. Four
// probes at most, once per association.
//
// A probe is not a packet in flight: nothing acknowledges it on behalf of data, it
// is not retransmitted and it does not count against the window. It is a question,
// and the answer is either an acknowledgement or the timer.

import (
	"errors"
	"net"
	"slices"
	"syscall"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	// mtuIPv4 and mtuIPv6 are what the address family itself allows: 1500 minus
	// the IPv4 and UDP headers, and 1280 minus the IPv6 and UDP headers.
	mtuIPv4 = 1452
	mtuIPv6 = 1232

	// mtuMin is what every path has to carry, so the search never goes below it.
	mtuMin = 1200

	// mtuProbeTimeout is how long a probe waits for an answer. It is not a round
	// trip: the probe is the first packet of a size the path may not carry, and a
	// path that drops it says nothing, so the wait is a fixed one that no path is
	// faster than.
	mtuProbeTimeout = time.Second
)

// mtuCandidates is the sizes an address family is searched through, largest
// first. The steps are where paths actually are: a tunnel takes an IPv4 path to
// 1400, a VPN to 1280, and everything carries 1200.
var (
	// The steps are what a path is: 1500 bytes of IP is the ordinary Ethernet
	// path, 1400 is what an overlay hands out, 1280 is the IPv6 minimum, and 1200
	// is what everything carries. Each is the UDP payload that fits, so each is
	// the path size minus the IP and UDP headers rather than the path size itself:
	// a candidate that is 1400 bytes of payload does not fit a 1400 byte path.
	mtuCandidatesIPv4 = []int{mtuIPv4, 1352, 1232, mtuMin}
	mtuCandidatesIPv6 = []int{mtuIPv6, mtuMin}
)

// defaultMTU is the size the association starts with, and the list it walks down.
func mtuCandidatesFor(remote net.Addr) []int {
	// The list is a copy: a probe that a path refuses is taken out of this end's
	// list, and the list it came from is shared by every association.
	if udpAddr, isUDPAddr := remote.(*net.UDPAddr); isUDPAddr && udpAddr.IP.To4() == nil {
		return slices.Clone(mtuCandidatesIPv6)
	}
	return slices.Clone(mtuCandidatesIPv4)
}

// mtuProbeState is the probe in flight, if any, and the size it is asking about.
// The size the association sends with is not the size being probed: it is the
// smallest one that is known to work, and a probe that is answered raises it. A
// probe that is not answered costs a packet, not the data that was sent at a size
// the path does not carry.
type mtuProbeState struct {
	packetNumber uint32
	candidate    int
	active       bool
}

// startMTUProbe sends one probe of the size the association is using and arms the
// timer that gives up on it. It runs once when the association is built and again
// after every size that did not work.
func (a *association) startMTUProbe() {
	if a.options.MTU > 0 {
		return
	}
	for {
		a.pumpMu.Lock()
		if err := a.pump(); err != nil {
			a.pumpMu.Unlock()
			return
		}
		a.sendMu.Lock()
		if a.mtuProbe.active {
			a.sendMu.Unlock()
			a.pumpMu.Unlock()
			return
		}
		candidate := a.nextMTUCandidateLocked()
		if candidate <= a.mtu {
			a.sendMu.Unlock()
			a.pumpMu.Unlock()
			return
		}
		// A group that is open is closed before the probe is numbered: a group is a
		// run of consecutive packet numbers, and a probe is not one of its members.
		if a.fecSender != nil && a.fecSender.open() {
			if err := a.closeGroupLocked(); err != nil {
				a.sendMu.Unlock()
				a.pumpMu.Unlock()
				return
			}
		}
		packetNumber, err := a.planProbeLocked(candidate)
		if err != nil {
			a.sendMu.Unlock()
			a.pumpMu.Unlock()
			a.logDebug("mtu probe of ", a.mtu, " not sent: ", err)
			return
		}
		a.mtuProbe = mtuProbeState{packetNumber: packetNumber, candidate: candidate, active: true}
		a.sendMu.Unlock()
		a.writingProbe.Store(true)
		writeErr := a.writeBatch()
		a.writingProbe.Store(false)
		a.pumpMu.Unlock()
		if writeErr != nil {
			return
		}
		if a.probeRefused.Swap(false) {
			// The socket refused the size, so the next one down is what to ask
			// about. The probe is retried here rather than from the write: the
			// write happens under the pump lock, and a probe started from there
			// would wait for the lock it is already holding.
			continue
		}
		time.AfterFunc(mtuProbeTimeout, func() {
			a.mtuProbeTimeout(packetNumber)
		})
		return
	}
}

// nextMTUCandidateLocked is the largest size that has not been ruled out, or the
// size the association already uses when nothing larger is left. The caller holds
// sendMu.
func (a *association) nextMTUCandidateLocked() int {
	for _, candidate := range a.mtuCandidates {
		if candidate > a.mtu {
			return candidate
		}
	}
	return a.mtu
}

// planProbeLocked puts one packet of exactly the size being asked about into the
// batch. It carries a ping and padding, because what is in it does not matter: what
// matters is that the peer answers it, and that the path carried it.
func (a *association) planProbeLocked(candidate int) (uint32, error) {
	payloadLen := candidate - headerLen - tagLen
	frame := appendPing(nil)
	paddingLen := payloadLen - len(frame) - paddingFixedLen
	if paddingLen < 0 {
		return 0, E.New("mtu of ", candidate, " leaves no room for a probe")
	}
	frame = appendPadding(frame, paddingLen)
	h := header{
		ConnectionID: a.peerConnID,
		Type:         packetTypeData,
		Epoch:        a.sendRing.epoch(),
		PacketNumber: a.sendPacket,
	}
	packet, payloadStart, err := a.reserveLocked(h, nil, len(frame))
	if err != nil {
		return 0, err
	}
	copy(packet[payloadStart:], frame)
	a.sendPacket++
	a.batch.pending = append(a.batch.pending, pendingPacket{
		sent: &sentPacket{
			packetNumber: h.PacketNumber,
			size:         len(packet),
			ackEliciting: true,
			mtuProbe:     true,
		},
		packet:       packet,
		payloadStart: payloadStart,
	})
	return h.PacketNumber, nil
}

// mtuProbeConfirmed reports whether an acknowledgement covers the probe, and if it
// does, the size it was sent with is the size the association uses.
func (a *association) mtuProbeConfirmed(acknowledgement ack) bool {
	a.sendMu.Lock()
	if !a.mtuProbe.active || !acknowledgement.covers(a.mtuProbe.packetNumber) {
		a.sendMu.Unlock()
		return false
	}
	packetNumber := a.mtuProbe.packetNumber
	candidate := a.mtuProbe.candidate
	a.mtuProbe.active = false
	if candidate > a.mtu {
		a.mtu = candidate
		a.updatePayloadLocked()
	}
	a.sendMu.Unlock()
	a.logInfo("mtu confirmed ", candidate, " by packet ", packetNumber)
	return true
}

// mtuProbeTimeout is what a probe that nothing answered means: the path does not
// carry that size, so the next one down is tried.
func (a *association) mtuProbeTimeout(packetNumber uint32) {
	a.sendMu.Lock()
	if !a.mtuProbe.active || a.mtuProbe.packetNumber != packetNumber {
		a.sendMu.Unlock()
		return
	}
	candidate := a.mtuProbe.candidate
	a.mtuProbe.active = false
	// The size is ruled out for the rest of the association: a path that did not
	// carry it once is not a path to keep asking about.
	for index, known := range a.mtuCandidates {
		if known == candidate {
			a.mtuCandidates = append(a.mtuCandidates[:index], a.mtuCandidates[index+1:]...)
			break
		}
	}
	a.sendMu.Unlock()
	a.logInfo("mtu probe of ", candidate, " unanswered, mtu stays ", a.mtu)
	a.startMTUProbe()
}

// mtuProbeFailed is what a write that the socket refused for being too long means.
// The probe is not going to arrive, so the next size down is what the next probe
// asks about. It does not start that probe: it runs under the pump lock, and a
// probe started from there would wait for the lock it is already holding.
func (a *association) mtuProbeFailed() {
	a.sendMu.Lock()
	if !a.mtuProbe.active {
		a.sendMu.Unlock()
		return
	}
	candidate := a.mtuProbe.candidate
	a.mtuProbe.active = false
	for index, known := range a.mtuCandidates {
		if known == candidate {
			a.mtuCandidates = append(a.mtuCandidates[:index], a.mtuCandidates[index+1:]...)
			break
		}
	}
	a.sendMu.Unlock()
	a.probeRefused.Store(true)
	a.logInfo("mtu ", candidate, " too large for the path")
}

// updatePayloadLocked recomputes how many payload bytes a packet may carry. The
// caller holds sendMu.
func (a *association) updatePayloadLocked() {
	if a.fecSender != nil {
		a.maxPayload = a.fecSender.payloadBudget(a.mtu)
		return
	}
	a.maxPayload = a.mtu - headerLen - tagLen
}

// isMessageTooLong reports whether a write failed because the packet is larger
// than the path allows.
func isMessageTooLong(err error) bool {
	return errors.Is(err, syscall.EMSGSIZE)
}

// covers reports whether the acknowledgement names the packet number.
func (a ack) covers(packetNumber uint32) bool {
	for index := 0; index < a.count; index++ {
		if packetNumber >= a.ranges[index].start && packetNumber <= a.ranges[index].end {
			return true
		}
	}
	return false
}
