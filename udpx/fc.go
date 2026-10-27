package udpx

import "time"

// Flow control
//
// A window is credit, not a rate: the receiver says how much more data the peer
// may send, and the sender stops when it is used up until the receiver moves the
// window forward. There are two levels, and both are needed:
//
//   - per stream, so that one stream cannot starve the others of the memory the
//     receiver spends holding data that the application has not read yet;
//   - per association, so that a hundred streams that are each inside their own
//     window cannot add up to more memory than the association may use.
//
// The windows are moved forward as data arrives, which is what keeps the peer sending
// on a path that loses packets: what the application can read is what arrived in
// order, and one hole stops the read while everything behind the hole is already
// here. A window that followed the read would wait for the retransmission that fills
// the hole before moving at all, so the peer would spend every round trip waiting for
// a window the receiver is holding for a hole. What bounds the memory instead is the
// read: a window never goes further than two windows past it, one for what the peer
// may have in flight and one for what arrived behind a hole and is waiting.
//
// A window also grows, because half of a window that is too small for the path is
// still too small. The evidence a receiver has is the peer spending the whole window
// and nothing coming after it: what stopped the peer was this window and not the
// path, which stops a peer wherever it happens to be. The window is then doubled
// unless it is already larger than the path, and a stream window that grew takes the
// association window with it.
//
// Whether the window is larger than the path is answered by the rate the application
// read at: a window that is what limits the peer doubles that rate when it doubles,
// because the peer sends one window per round trip; a window larger than the path
// leaves the rate where the path put it, and what the doubling adds is memory the peer
// may fill before the application reads. The rate the peer sent at would answer the
// wrong question — it follows the window by itself, so it says a window twice as large
// is twice as good on every path. The window is therefore doubled only when the read
// rate grew with it, and the test is asked again at every move, so a path that gets
// faster later takes a larger window with it and nothing here is remembered as a
// ceiling.
//
// What is compared is the ceiling the peer was told about, not the one this end holds:
// the window moves as data arrives, so by the time the packet that reached a ceiling
// arrives, that ceiling has usually been replaced by a larger one, and a peer whose
// data always arrives one round trip behind would then never be seen to reach any
// ceiling at all. A peer that fills the window it was given is the same evidence
// whether or not the limit has moved since.
const (
	// initialStreamWindow is where the window of one stream starts: how much data
	// it may have in flight before the receiver has to raise the window.
	//
	// A path that takes 200 ms per round trip carries one window per round trip, so
	// 2 MiB is a little over 3 MiB/s for one stream and 40 MiB/s for a path of
	// 50 ms. A smaller window is what kept a single stream at 0.6 MiB/s on that
	// path; a path that loses packets needs more than 2 MiB even when its round trip
	// is short, and that is what the growth is for.
	initialStreamWindow = 2 * 1024 * 1024

	// initialConnectionWindow is how much data all streams together may have in
	// flight.
	//
	// This is where the number that bounds the memory one association costs starts:
	// what arrived and was not read yet on one side, and what was sent and not
	// acknowledged yet on the other. Four streams of the stream window fill it.
	initialConnectionWindow = 8 * 1024 * 1024

	// maxStreams is how many streams an association may have open at once. It is
	// a constant of the protocol rather than a number to negotiate: the number is
	// what the receiver is willing to remember, and the sender has to stay inside
	// it, not the other way around.
	maxStreams = 256

	// acceptStreamBacklog is how many streams opened by the peer may wait for
	// AcceptStream.
	acceptStreamBacklog = 64
)

// windowGrows reports whether a window the peer filled is worth doubling, given the
// rate the peer delivered at with it and the rate it delivered at with the window
// before.
//
// A rate that grew by half is the evidence that the window was still what limited the
// peer. The half is slack for the path's own variation and for a loss that cost a
// retransmission to fill the window: a window that is half the size of the path still
// doubles the rate, and one that is twice the size of the path leaves it alone, so
// what the test has to tell apart is a rate that moved from one that did not.
func windowGrows(rate, previous uint64) bool {
	if rate == 0 {
		// An application that reads nothing is not evidence of anything, and a
		// window that grew on that answer would keep growing.
		return false
	}
	return previous == 0 || 2*rate >= 3*previous
}

// deliveryRate is how many bytes per second the peer delivered over elapsed.
func deliveryRate(delivered uint64, elapsed time.Duration) uint64 {
	if elapsed <= 0 {
		return 0
	}
	return delivered * uint64(time.Second) / uint64(elapsed)
}

// credit is a send-side window: how much data may still be sent.
type credit struct {
	limit uint64
	used  uint64
}

func (c *credit) available() uint64 {
	if c.used >= c.limit {
		return 0
	}
	return c.limit - c.used
}

// take consumes up to n bytes of credit and returns how much was available.
func (c *credit) take(n uint64) uint64 {
	available := c.available()
	if n > available {
		n = available
	}
	c.used += n
	return n
}

// give moves the limit forward and reports whether it moved.
func (c *credit) give(limit uint64) bool {
	if limit <= c.limit {
		return false
	}
	c.limit = limit
	return true
}
