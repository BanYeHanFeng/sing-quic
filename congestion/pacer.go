package congestion

import (
	"time"
)

// burstWindow is how far behind the clock the bucket may be: it holds the bytes that
// accrue while a wait is being served late, and nothing else.
//
// It used to be two milliseconds, because the send path handed its waits to a timer
// and a timer on Linux serves anything under a millisecond as 1.07 of them. The
// bucket was then the only way to reach the rate the controller asked for — a batch
// of sixteen packets per wait is 21 MiB/s whatever the rate says — and what it held
// was also the burst the path saw, which on a path whose queue is 25 KB is the loss:
// 35 percent of a 64 MiB transfer went out and never arrived.
//
// The send path now sleeps with a clock that is late by about sixty microseconds, so
// the window is that: enough to keep the rate exact at any rate the path can carry,
// small enough that the burst is the batch and not a multiple of it.
const burstWindow = 200 * time.Microsecond

// burstPackets is the floor of that, and it is one write: the transport hands the
// socket a run of packets at a time, and the bucket has to be able to hold the first
// of those without the wait being a lie. It is what lets an association send before
// it has measured anything — the rate it starts at is a guess, and a guess is not a
// reason to make the first batch wait for it.
const burstPackets = 16

// pacer is the token bucket that turns a pacing rate into a time to wait.
//
// Bytes accrue at the rate the controller asked for, and every packet that leaves
// takes its bytes out. The bucket may go into debt: the transport hands a batch of
// packets to the socket in one write, so a batch is spent before the tokens for it
// have accrued, and the next batch waits until the debt is paid. That is what makes
// the rate on the wire the rate the controller asked for at the granularity the
// socket works in, instead of one packet's worth of tokens buying a whole batch.
type pacer struct {
	// budgetAtLastSent is what the bucket held when the last packet left. A
	// negative number is the debt of a batch that spent more than it had.
	budgetAtLastSent int64

	maxDatagramSize ByteCount
	lastSentTime    time.Time

	// getBandwidth is the rate the bucket fills at, in bytes per second. It is
	// never zero: a rate of zero would be a bucket that never fills.
	getBandwidth func() ByteCount
}

func newPacer(initialMaxDatagramSize ByteCount, getBandwidth func() ByteCount) *pacer {
	return &pacer{
		maxDatagramSize: initialMaxDatagramSize,
		getBandwidth:    getBandwidth,
	}
}

// sentPacket records a packet that left at sendTime, taking its bytes out of the
// bucket.
func (p *pacer) sentPacket(sendTime time.Time, size ByteCount) {
	p.budgetAtLastSent = p.budget(sendTime) - int64(size)
	p.lastSentTime = sendTime
}

// budget is what the bucket holds at now: what accrued since the last packet left,
// on top of what was left over, and no more than a sender that was quiet may arrive
// with. It is negative when the batch that went out last is still owed for.
func (p *pacer) budget(now time.Time) int64 {
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

// wait is how long the next batch has to wait for the bucket to be out of debt, or
// zero when it may leave now.
func (p *pacer) wait(now time.Time) time.Duration {
	debt := -p.budget(now)
	if debt <= 0 {
		return 0
	}
	return p.timeFor(debt)
}

// maxBurstSize is the most the bucket may hold: what accrues while the clock is
// being late, and at least one write.
func (p *pacer) maxBurstSize() int64 {
	return max(
		int64(p.getBandwidth())*burstWindow.Nanoseconds()/1e9,
		burstPackets*int64(p.maxDatagramSize),
	)
}

// timeFor is how long it takes to accrue bytes at the current rate.
func (p *pacer) timeFor(bytes int64) time.Duration {
	return time.Duration(float64(bytes) * 1e9 / float64(p.getBandwidth()))
}
