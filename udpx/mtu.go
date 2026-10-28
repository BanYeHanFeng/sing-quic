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
	mtuCandidatesIPv4 = []int{mtuIPv4, 1400, 1280, mtuMin}
	mtuCandidatesIPv6 = []int{mtuIPv6, mtuMin}
)

// defaultMTU is the size the association starts with, and the list it walks down.
func defaultMTU(remote net.Addr) (int, []int) {
	if udpAddr, isUDPAddr := remote.(*net.UDPAddr); isUDPAddr && udpAddr.IP.To4() == nil {
		return mtuCandidatesIPv6[0], mtuCandidatesIPv6
	}
	return mtuCandidatesIPv4[0], mtuCandidatesIPv4
}

// nextMTU is the size below current, or current itself when there is none.
func nextMTU(candidates []int, current int) int {
	for index, candidate := range candidates {
		if candidate != current {
			continue
		}
		if index+1 < len(candidates) {
			return candidates[index+1]
		}
		return current
	}
	// A size that is not on the list came from a path that reported it: walk down
	// to the largest candidate below it.
	for _, candidate := range candidates {
		if candidate < current {
			return candidate
		}
	}
	return current
}

// mtuProbeState is the probe in flight, if any.
type mtuProbeState struct {
	packetNumber uint32
	active       bool
}

// startMTUProbe sends one probe of the size the association is using and arms the
// timer that gives up on it. It runs once when the association is built and again
// after every size that did not work.
func (a *association) startMTUProbe() {
	if a.options.MTU > 0 {
		return
	}
	a.pumpMu.Lock()
	defer a.pumpMu.Unlock()
	if err := a.pump(); err != nil {
		return
	}
	a.sendMu.Lock()
	if a.mtuProbe.active || a.mtu <= mtuMin {
		a.sendMu.Unlock()
		return
	}
	packetNumber, err := a.planProbeLocked()
	if err != nil {
		a.sendMu.Unlock()
		a.logDebug("mtu probe of ", a.mtu, " not sent: ", err)
		return
	}
	a.mtuProbe = mtuProbeState{packetNumber: packetNumber, active: true}
	a.sendMu.Unlock()
	a.writingProbe.Store(true)
	writeErr := a.writeBatch()
	a.writingProbe.Store(false)
	if writeErr != nil {
		return
	}
	time.AfterFunc(mtuProbeTimeout, func() {
		a.mtuProbeTimeout(packetNumber)
	})
}

// planProbeLocked puts one packet of exactly the current size into the batch. It
// carries a ping and padding, because what is in it does not matter: what matters
// is that the peer answers it, and that the path carried it.
func (a *association) planProbeLocked() (uint32, error) {
	payloadLen := a.mtu - headerLen - tagLen
	frame := appendPing(nil)
	paddingLen := payloadLen - len(frame) - paddingFixedLen
	if paddingLen < 0 {
		return 0, E.New("mtu of ", a.mtu, " leaves no room for a probe")
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
	a.mtuProbe.active = false
	a.sendMu.Unlock()
	a.logInfo("mtu confirmed ", a.mtu, " by packet ", packetNumber)
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
	a.mtuProbe.active = false
	next := nextMTU(a.mtuCandidates, a.mtu)
	if next >= a.mtu {
		a.sendMu.Unlock()
		return
	}
	a.mtu = next
	a.updatePayloadLocked()
	a.sendMu.Unlock()
	a.logInfo("mtu probe of ", packetNumber, " unanswered, mtu now ", a.mtu)
	a.startMTUProbe()
}

// mtuProbeFailed is what a write that the socket refused for being too long means.
// The probe is not going to arrive, so the next size down is tried.
func (a *association) mtuProbeFailed() {
	a.sendMu.Lock()
	if !a.mtuProbe.active {
		a.sendMu.Unlock()
		return
	}
	a.mtuProbe.active = false
	next := nextMTU(a.mtuCandidates, a.mtu)
	if next >= a.mtu {
		a.sendMu.Unlock()
		return
	}
	a.mtu = next
	a.updatePayloadLocked()
	a.sendMu.Unlock()
	a.logInfo("mtu too large for the path, mtu now ", a.mtu)
	a.startMTUProbe()
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
