package congestion

import (
	"time"
)

const burstWindow = 200 * time.Microsecond

const burstPackets = 16

type pacer struct {
	budgetAtLastSent int64

	maxDatagramSize ByteCount
	lastSentTime    time.Time

	getBandwidth func() ByteCount
}

func newPacer(initialMaxDatagramSize ByteCount, getBandwidth func() ByteCount) *pacer {
	return &pacer{
		maxDatagramSize: initialMaxDatagramSize,
		getBandwidth:    getBandwidth,
	}
}

func (p *pacer) sentPacket(sendTime time.Time, size ByteCount) {
	p.budgetAtLastSent = p.budget(sendTime) - int64(size)
	p.lastSentTime = sendTime
}

func (p *pacer) budget(now time.Time) int64 {
	if p.lastSentTime.IsZero() {
		return p.maxBurstSize()
	}
	budget := float64(p.budgetAtLastSent) + float64(p.getBandwidth())*now.Sub(p.lastSentTime).Seconds()
	if budget > float64(p.maxBurstSize()) {
		return p.maxBurstSize()
	}
	return int64(budget)
}

func (p *pacer) wait(now time.Time) time.Duration {
	debt := -p.budget(now)
	if debt <= 0 {
		return 0
	}
	return p.timeFor(debt)
}

func (p *pacer) maxBurstSize() int64 {
	return max(
		int64(p.getBandwidth())*burstWindow.Nanoseconds()/1e9,
		burstPackets*int64(p.maxDatagramSize),
	)
}

func (p *pacer) timeFor(bytes int64) time.Duration {
	return time.Duration(float64(bytes) * 1e9 / float64(p.getBandwidth()))
}
