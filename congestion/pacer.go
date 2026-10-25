package congestion

import (
	"math"
	"time"
)

const (
	maxBurstPackets = 10
)

// Pacer implements a token bucket pacing algorithm.
type Pacer struct {
	budgetAtLastSent ByteCount
	maxDatagramSize  ByteCount
	lastSentTime     time.Time
	getBandwidth     func() ByteCount // in bytes/s
}

func NewPacer(initialMaxDatagramSize ByteCount, getBandwidth func() ByteCount) *Pacer {
	p := &Pacer{
		budgetAtLastSent: maxBurstPackets * initialMaxDatagramSize,
		maxDatagramSize:  initialMaxDatagramSize,
		getBandwidth:     getBandwidth,
	}
	return p
}

func (p *Pacer) SentPacket(sendTime time.Time, size ByteCount) {
	budget := p.Budget(sendTime)
	if size > budget {
		p.budgetAtLastSent = 0
	} else {
		p.budgetAtLastSent = budget - size
	}
	p.lastSentTime = sendTime
}

func (p *Pacer) Budget(now time.Time) ByteCount {
	if p.lastSentTime.IsZero() {
		return p.maxBurstSize()
	}
	budget := p.budgetAtLastSent + (p.getBandwidth()*ByteCount(now.Sub(p.lastSentTime).Nanoseconds()))/1e9
	if budget < 0 { // protect against overflows
		budget = ByteCount(1<<62 - 1)
	}
	return Min(p.maxBurstSize(), budget)
}

func (p *Pacer) maxBurstSize() ByteCount {
	return Max(
		ByteCount((MinPacingDelay+time.Millisecond).Nanoseconds())*p.getBandwidth()/1e9,
		maxBurstPackets*p.maxDatagramSize,
	)
}

// TimeUntilSend returns when the next packet should be sent.
// It returns the zero value of time.Time if a packet can be sent immediately.
func (p *Pacer) TimeUntilSend() time.Time {
	if p.budgetAtLastSent >= p.maxDatagramSize {
		return time.Time{}
	}
	return p.lastSentTime.Add(Max(
		MinPacingDelay,
		time.Duration(math.Ceil(float64(p.maxDatagramSize-p.budgetAtLastSent)*1e9/
			float64(p.getBandwidth())))*time.Nanosecond,
	))
}

func (p *Pacer) SetMaxDatagramSize(s ByteCount) {
	p.maxDatagramSize = s
}
