package congestion

import (
	"time"
)

const (
	// burstWindow is how much time a bucket that owes nothing may hold, and it is
	// what lets the send path reach the rate it was given at all: a wait is handed
	// to a timer, and a timer on a Linux host rounds anything under a millisecond up
	// to about 1.07 of them, so one batch per wait is 21 MiB/s whatever the rate
	// says. What the bucket keeps is the part of the interval the timer swallowed,
	// and that is also what a sender that had nothing to say arrives with: one
	// burst, not everything it did not send while it was quiet.
	//
	// The two are the same knob, and it is a trade rather than a tuning: the burst
	// the path sees is a rate times this window, so a path that carries 400 Mbit/s
	// through a 25 KB buffer loses the tail of every burst of 24 packets or more
	// (measured: 16 packets 2.3 percent, 24 15 percent, 32 34 percent). Taking the
	// window down to a few packets does remove the loss — a 64 MiB transfer goes
	// from 106 MB on the wire and 35 percent of it declared lost to 70 MB and 1.5
	// percent — and it also removes the throughput, because the rate the pacer asks
	// for is then never reached and the bandwidth estimate follows it down: the same
	// change takes a 256 MiB transfer from 27 MiB/s to 7.3. What has to change to
	// have both is the clock the wait is handed to, not this window.
	burstWindow = 2 * time.Millisecond

	// burstPackets is the floor of that, because a path that says it is slow still
	// has to be able to send a run of packets in one write.
	burstPackets = 10
)

// Pacer is the token bucket that turns a pacing rate into a time to wait.
//
// Bytes accrue at the rate the controller asked for, and every packet that leaves
// takes its bytes out. The bucket may go into debt: the transport hands a batch of
// packets to the socket in one write, so a batch is spent before the tokens for it
// have accrued, and the next batch waits until the debt is paid. That is what makes
// the rate on the wire the rate the controller asked for at the granularity the
// socket works in, instead of one packet's worth of tokens buying a whole batch.
type Pacer struct {
	// budgetAtLastSent is what the bucket held when the last packet left. A
	// negative number is the debt of a batch that spent more than it had.
	budgetAtLastSent int64

	maxDatagramSize ByteCount
	lastSentTime    time.Time

	// getBandwidth is the rate the bucket fills at, in bytes per second. It is
	// never zero: a rate of zero would be a bucket that never fills.
	getBandwidth func() ByteCount
}

func NewPacer(initialMaxDatagramSize ByteCount, getBandwidth func() ByteCount) *Pacer {
	return &Pacer{
		maxDatagramSize: initialMaxDatagramSize,
		getBandwidth:    getBandwidth,
	}
}

// SentPacket records a packet that left at sendTime, taking its bytes out of the
// bucket.
func (p *Pacer) SentPacket(sendTime time.Time, size ByteCount) {
	p.budgetAtLastSent = p.Budget(sendTime) - int64(size)
	p.lastSentTime = sendTime
}

// Budget is what the bucket holds at now: what accrued since the last packet left,
// on top of what was left over, and no more than a sender that was quiet may arrive
// with. It is negative when the batch that went out last is still owed for.
func (p *Pacer) Budget(now time.Time) int64 {
	if p.lastSentTime.IsZero() {
		return p.maxBurstSize()
	}
	// A batch spends more than the bucket holds, so the debt is repaid by accrual
	// alone and the arithmetic has to stay exact for as long as that takes. What
	// keeps it inside an int64 is the float: a product of a rate and a duration
	// overflows one long before the cap it is on its way to.
	budget := float64(p.budgetAtLastSent) + float64(p.getBandwidth())*now.Sub(p.lastSentTime).Seconds()
	if budget > float64(p.maxBurstSize()) {
		return p.maxBurstSize()
	}
	return int64(budget)
}

// Wait is how long the next batch has to wait for the bucket to be out of debt, or
// zero when it may leave now.
func (p *Pacer) Wait(now time.Time) time.Duration {
	debt := -p.Budget(now)
	if debt <= 0 {
		return 0
	}
	return p.timeFor(debt)
}

// maxBurstSize is the most the bucket may hold: what accrues in a burst window, and
// at least a run of packets for a path whose rate is below that.
func (p *Pacer) maxBurstSize() int64 {
	return Max(
		int64(p.getBandwidth())*burstWindow.Nanoseconds()/1e9,
		burstPackets*int64(p.maxDatagramSize),
	)
}

// timeFor is how long it takes to accrue bytes at the current rate.
func (p *Pacer) timeFor(bytes int64) time.Duration {
	return time.Duration(float64(bytes) * 1e9 / float64(p.getBandwidth()))
}
