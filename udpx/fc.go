package udpx

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
// The windows are moved forward as the application reads, which is what keeps the
// memory a receiver holds bounded by the windows rather than by how fast the peer
// sends. A window is only moved when half of it has been read, so the two ends
// exchange one update per half window instead of one per read.
const (
	// initialStreamWindow is how much data one stream may have in flight before
	// the receiver has to raise the window.
	//
	// The size is the ceiling a single stream cannot pass: a path that takes
	// 200 ms per round trip carries one window per round trip, so 2 MiB is a
	// little over 3 MiB/s for one stream and 40 MiB/s for a path of 50 ms. A
	// smaller window is what kept a single stream at 0.6 MiB/s on that path, and
	// the memory a larger one would cost is spent on nothing: what a receiver may
	// hold in total is the association window below, whichever stream it belongs
	// to.
	initialStreamWindow = 2 * 1024 * 1024

	// initialConnectionWindow is how much data all streams together may have in
	// flight.
	//
	// This is the number that bounds the memory one association costs on either
	// end: what arrived and was not read yet on one side, and what was sent and
	// not acknowledged yet on the other. Four streams of the stream window fill
	// it.
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
