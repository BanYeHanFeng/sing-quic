package udpx

import (
	"errors"
	"net"
	"slices"
	"syscall"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	mtuIPv4 = 1452
	mtuIPv6 = 1232

	mtuMin = 1200

	mtuProbeTimeout = time.Second

	mtuProbeAttempts = 3
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

type mtuProbeState struct {
	packetNumber uint32
	candidate    int
	attempts     int
	active       bool
}

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
		packetNumber, err := a.planProbeLocked(candidate)
		if err != nil {
			a.sendMu.Unlock()
			a.pumpMu.Unlock()
			a.logDebug("mtu probe of ", a.mtu, " not sent: ", err)
			return
		}
		attempts := 0
		if a.mtuProbe.candidate == candidate {
			attempts = a.mtuProbe.attempts
		}
		a.mtuProbe = mtuProbeState{packetNumber: packetNumber, candidate: candidate, attempts: attempts, active: true}
		a.sendMu.Unlock()
		a.writingProbe.Store(true)
		writeErr := a.writeBatch()
		a.writingProbe.Store(false)
		a.pumpMu.Unlock()
		if writeErr != nil {
			return
		}
		if a.probeRefused.Swap(false) {
			continue
		}
		time.AfterFunc(mtuProbeTimeout, func() {
			a.mtuProbeTimeout(packetNumber)
		})
		return
	}
}

func (a *association) nextMTUCandidateLocked() int {
	for _, candidate := range a.mtuCandidates {
		if candidate > a.mtu {
			return candidate
		}
	}
	return a.mtu
}

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
		PacketNumber: a.sendPacket,
	}
	packet, payloadStart, err := a.reserveLocked(h, len(frame))
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

func (a *association) mtuProbeConfirmed(acknowledgement ack) bool {
	a.sendMu.Lock()
	if !a.mtuProbe.active || !acknowledgement.covers(a.mtuProbe.packetNumber) {
		a.sendMu.Unlock()
		return false
	}
	packetNumber := a.mtuProbe.packetNumber
	candidate := a.mtuProbe.candidate
	a.mtuProbe = mtuProbeState{}
	if candidate > a.mtu {
		a.mtu = candidate
		a.updatePayloadLocked()
	}
	a.sendMu.Unlock()
	a.logInfo("mtu confirmed ", candidate, " by packet ", packetNumber)
	return true
}

func (a *association) mtuProbeTimeout(packetNumber uint32) {
	a.sendMu.Lock()
	if !a.mtuProbe.active || a.mtuProbe.packetNumber != packetNumber {
		a.sendMu.Unlock()
		return
	}
	candidate := a.mtuProbe.candidate
	attempts := a.mtuProbe.attempts + 1
	if attempts < mtuProbeAttempts {
		a.mtuProbe = mtuProbeState{candidate: candidate, attempts: attempts}
		a.sendMu.Unlock()
		a.logDebug("mtu probe of ", candidate, " unanswered ", attempts, " times, asking again")
		a.startMTUProbe()
		return
	}
	a.mtuProbe = mtuProbeState{}
	for index, known := range a.mtuCandidates {
		if known == candidate {
			a.mtuCandidates = append(a.mtuCandidates[:index], a.mtuCandidates[index+1:]...)
			break
		}
	}
	mtu := a.mtu
	a.sendMu.Unlock()
	a.logInfo("mtu probe of ", candidate, " unanswered ", attempts, " times, mtu stays ", mtu)
	a.startMTUProbe()
}

func (a *association) mtuProbeFailed() {
	a.sendMu.Lock()
	if !a.mtuProbe.active {
		a.sendMu.Unlock()
		return
	}
	candidate := a.mtuProbe.candidate
	a.mtuProbe = mtuProbeState{}
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

func (a *association) mtuStepDownLocked() bool {
	if a.options.MTU > 0 {
		return false
	}
	refused := a.mtu
	next := 0
	for _, candidate := range a.mtuCandidates {
		if candidate < refused && candidate > next {
			next = candidate
		}
	}
	if next == 0 {
		return false
	}
	for index, candidate := range a.mtuCandidates {
		if candidate == refused {
			a.mtuCandidates = append(a.mtuCandidates[:index], a.mtuCandidates[index+1:]...)
			break
		}
	}
	a.mtu = next
	a.updatePayloadLocked()
	return true
}

func (a *association) updatePayloadLocked() {
	a.maxPayload = a.mtu - headerLen - tagLen
}

func isMessageTooLong(err error) bool {
	return errors.Is(err, syscall.EMSGSIZE)
}

func (a ack) covers(packetNumber uint32) bool {
	for index := 0; index < a.count; index++ {
		if packetNumber >= a.ranges[index].start && packetNumber <= a.ranges[index].end {
			return true
		}
	}
	return false
}
