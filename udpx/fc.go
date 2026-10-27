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
// The size of a window is a memory budget and nothing else: how much may wait on this
// side, which is a number this end picks rather than one the path teaches. What the
// path is worth is the congestion controller's question, and a receiver that doubled
// its window on a rate it measured would be running a second controller with worse
// information — the only rate a receiver sees is the one its own window allows.
//
// The windows are moved forward as data arrives, which is what keeps the peer sending
// on a path that loses packets: what the application can read is what arrived in
// order, and one hole stops the read while everything behind the hole is already
// here. A window that followed the read would wait for the retransmission that fills
// the hole before moving at all, so the peer would spend every round trip waiting for
// a window the receiver is holding for a hole. What bounds the memory instead is the
// read: a window never goes further than two budgets past it, one for what the peer
// may have in flight and one for what arrived behind a hole and is waiting.
//
// Both budgets are fixed, so the memory an association costs is bounded by a number
// known before the first packet. A window that grew to fit the path would need a bound
// of its own, and the one it had was the rate the application read at, which is the
// window judging itself: the peer's rate follows the window by construction, so every
// doubling looked justified. A path whose bandwidth-delay product was 7 MB ended up
// with a 71 MB window and 128 MB of buffer.
const (
	// initialStreamWindow is the credit a stream starts with, before this end has said
	// anything: it is the number both ends know without a frame, so it is what a sender
	// assumes and what a receiver starts out allowing. It is not the budget below — the
	// budget is announced as soon as the first bytes of a stream arrive.
	initialStreamWindow = 2 * 1024 * 1024

	// initialConnectionWindow is the same for the association.
	initialConnectionWindow = 8 * 1024 * 1024

	// streamWindow is what one stream is granted once this end has said anything: the
	// memory one stream may cost, which is two windows of buffer — one the peer may
	// have in flight and one that arrived behind a hole. Two of these at a 200 ms
	// round trip is 160 MiB/s of credit, and the congestion controller is what decides
	// whether a path is given that much.
	streamWindow = 16 * 1024 * 1024

	// connectionWindow is the same for every stream together, and it is the number
	// that bounds what one association costs: four streams of the stream window fill
	// it.
	connectionWindow = 64 * 1024 * 1024

	// initialStreams is how many streams this end may open before the peer has said
	// anything: like the windows above, it is the number both ends know without a
	// frame. It is not the budget below — the budget is announced as soon as the peer
	// opens its first stream.
	initialStreams = 256

	// streamBudget is how many streams of the peer one association may have open at
	// once, which is what this end is willing to remember: an open stream costs an
	// entry in the table (about 1 KB, measured at this many of them) and, until the
	// application takes it, a place in the accept queue, which is a channel of that
	// many pointers. Both are bounded by this number, so the memory an association
	// spends on streams is known before the first one and does not depend on how many
	// it has carried.
	//
	// The ceiling is a frame rather than a constant because the receiver is the one
	// paying: a sender that stayed inside a number it guessed would have to fail an
	// open once a busy client went past it, and a busy client does — every proxied
	// connection of a machine is a stream on one session, and a browser alone keeps
	// hundreds.
	streamBudget = 4096
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
