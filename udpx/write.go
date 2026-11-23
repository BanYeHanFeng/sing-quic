package udpx

import (
	"errors"
	"syscall"
	"time"

	"github.com/sagernet/sing-quic/udpx/internal/udpio"

	E "github.com/sagernet/sing/common/exceptions"
)

type txOutcome struct {
	packets  []udpio.Packet
	snapshot *statsSnapshot
	cause    error
}

func (a *association) txStep(now time.Time) txOutcome {
	a.txMu.Lock()
	defer a.txMu.Unlock()
	t := &a.tx
	var outcome txOutcome
	if cause := t.runTimers(now); cause != nil {
		outcome.cause = cause
		return outcome
	}
	t.batch.reset()
	maxPayload := int(a.maxPayload.Load())
	t.planProbe()
	if t.shouldPack(now) {
		t.pack(now, maxPayload)
	}
	outcome.snapshot = t.snapshotIfDue(now)
	t.batch.packets = t.batch.packets[:0]
	remote := *a.peerAddr.Load()
	for _, sent := range t.batch.sent {
		t.batch.packets = append(t.batch.packets, udpio.Packet{Data: sent.data, Addr: remote})
	}
	outcome.packets = t.batch.packets
	return outcome
}

func (a *association) writeLoop() {
	defer close(a.txDone)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		outcome := a.txStep(time.Now())
		if len(outcome.packets) > 0 {
			err := a.batchIO.WritePackets(outcome.packets)
			if err != nil {
				if a.txWriteFailed(err) {
					continue
				}
				a.shutdown(E.Cause(err, "write packets"), false)
				return
			}
		}
		if outcome.snapshot != nil {
			a.logStats(outcome.snapshot)
		}
		if outcome.cause != nil {
			a.shutdown(outcome.cause, true)
			return
		}
		if a.txIdle() {
			return
		}
		timer.Reset(a.txWait())
		select {
		case <-a.txWake:
		case <-timer.C:
		case <-a.ctx.Done():
			return
		}
	}
}

func (a *association) txWait() time.Duration {
	a.txMu.Lock()
	deadline := a.tx.nextDeadline(time.Now())
	a.txMu.Unlock()
	wait := time.Until(deadline)
	if wait < 0 {
		return 0
	}
	return wait
}

func (a *association) txWriteFailed(err error) bool {
	if !isMessageTooLong(err) {
		return false
	}
	a.txMu.Lock()
	defer a.txMu.Unlock()
	t := &a.tx
	failed := append([]*sentPacket(nil), t.batch.sent...)
	var probed bool
	for _, sent := range failed {
		probed = probed || sent.probe
	}
	if probed {
		candidate := t.mtu.candidate
		t.mtu.dropCandidate()
		a.logInfo("mtu ", candidate, " too large for the path")
		a.releaseFailed(failed)
		return true
	}
	if !t.stepDown() {
		a.logInfo("mtu ", a.mtuSize(), " refused by the socket and no candidate is left")
		return false
	}
	a.logInfo("mtu refused by the socket, mtu now ", a.mtuSize())
	a.releaseFailed(failed)
	return true
}

func (a *association) releaseFailed(failed []*sentPacket) {
	t := &a.tx
	var retransmit []outFrame
	for _, sent := range failed {
		t.inFlight.remove(sent)
		for index := range sent.frames {
			frame := sent.frames[index]
			if frame.probe {
				frame.release()
				continue
			}
			retransmit = append(retransmit, frame)
		}
	}
	if len(retransmit) > 0 {
		t.queue = append(retransmit, t.queue...)
	}
}

func isMessageTooLong(err error) bool {
	return errors.Is(err, syscall.EMSGSIZE)
}

func (a *association) queueControl(payload []byte, ackEliciting bool) {
	a.txMu.Lock()
	if a.tx.closing {
		a.txMu.Unlock()
		return
	}
	a.tx.pushControl(payload, ackEliciting)
	a.txMu.Unlock()
	a.wake()
}

func (a *association) queueStreamFrame(frame outFrame) {
	a.txMu.Lock()
	if a.tx.closing {
		a.txMu.Unlock()
		frame.release()
		return
	}
	a.tx.queue = append(a.tx.queue, frame)
	a.txMu.Unlock()
	a.wake()
}

func (a *association) txIdle() bool {
	a.txMu.Lock()
	defer a.txMu.Unlock()
	return a.tx.idle()
}
