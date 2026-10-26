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
//
// A window also grows, because half of a window that is too small for the path is
// still too small. The evidence a receiver has is the peer spending the whole window
// and nothing coming after it: what stopped the peer was this window and not the
// path, which stops a peer wherever it happens to be. The window is then doubled, up
// to a ceiling, and a stream window that grew takes the association window with it —
// a receiver that moved its window forward by reading is the only one that can tell,
// since moving it forward on arrival instead would let the memory grow with the peer's
// speed rather than with the application's.
//
// What is compared is the ceiling the peer was told about, not the one this end holds:
// a window moves forward on the read, so by the time the packet that reached a ceiling
// arrives, that ceiling has usually been replaced by a larger one, and a peer whose
// data always arrives one round trip behind the read would then never be seen to reach
// any ceiling at all. A peer that fills the window it was given is the same evidence
// whether or not the read has moved the limit since.
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
	// This is the number that bounds the memory one association costs on either
	// end: what arrived and was not read yet on one side, and what was sent and
	// not acknowledged yet on the other. Four streams of the stream window fill
	// it.
	initialConnectionWindow = 8 * 1024 * 1024

	// maxStreamWindow is how far the window of one stream may grow.
	//
	// Growth stops here because a window costs memory the peer may fill before the
	// application reads, and because the numbers on a slow path stop improving
	// before it: 8 MiB is more than six times what a 200 ms path of 50 Mbit/s
	// carries in a round trip, and the next doubling is spent on memory alone.
	maxStreamWindow = 8 * 1024 * 1024

	// maxConnectionWindow is how far the association window may grow: four stream
	// windows, the ratio the two start in. The ratio is not a matter of taste —
	// what arrived is counted against what was read plus this window, so a stream
	// window that grew past it would leave one hole able to end the association.
	maxConnectionWindow = 4 * maxStreamWindow

	// maxStreams is how many streams an association may have open at once. It is
	// a constant of the protocol rather than a number to negotiate: the number is
	// what the receiver is willing to remember, and the sender has to stay inside
	// it, not the other way around.
	maxStreams = 256

	// acceptStreamBacklog is how many streams opened by the peer may wait for
	// AcceptStream.
	acceptStreamBacklog = 64
)

// growWindow is the size a window takes when the peer filled the one it had: twice
// as large, or the ceiling. Doubling is what makes the path the limit again within a
// few windows rather than within a few dozen.
func growWindow(window, ceiling uint64) uint64 {
	if window >= ceiling {
		return window
	}
	return min(2*window, ceiling)
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
