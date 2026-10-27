package udpx

import (
	"testing"
	"time"
)

// streamWindowState is one end's view of the credit it granted one stream.
type streamWindowState struct {
	window  uint64
	limit   uint64
	read    uint64
	highest uint64
}

// grantedTo reads what this end allows the peer to send on a stream.
func grantedTo(t *testing.T, conn Association, id uint32) streamWindowState {
	t.Helper()
	stream, loaded := conn.(*association).stream(id)
	if !loaded {
		t.Fatalf("stream %d is not open", id)
	}
	stream.recvMu.Lock()
	defer stream.recvMu.Unlock()
	return streamWindowState{
		window:  stream.recvWindow,
		limit:   stream.recvLimit,
		read:    stream.readOffset,
		highest: stream.recvHighest,
	}
}

// allowedOn reads what the peer allows this end to send on a stream.
func allowedOn(t *testing.T, conn Association, id uint32) uint64 {
	t.Helper()
	stream, loaded := conn.(*association).stream(id)
	if !loaded {
		t.Fatalf("stream %d is not open", id)
	}
	stream.sendMu.Lock()
	defer stream.sendMu.Unlock()
	return stream.sendCredit.limit
}

// associationWindowOf reads what this end allows the peer to send overall.
func associationWindowOf(t *testing.T, conn Association) (window, limit, read uint64) {
	t.Helper()
	a := conn.(*association)
	a.fcMu.Lock()
	defer a.fcMu.Unlock()
	return a.recvWindow, a.recvLimit, a.recvRead
}

// waitUntil waits for something a transfer makes true on the other end of the link,
// so that a test does not depend on how many round trips it takes.
func waitUntil(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if condition() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestStreamWindowIsABudget requires the credit a stream is granted to be a budget and
// nothing else: the credit both ends know without a frame, raised to the budget once
// the stream exists, never more than two budgets past what the application read, and
// moved by the read once the buffer is what holds it.
//
// The two budgets are what bounds the memory one stream costs, so the ceiling is what
// this pins: a window that grew would make the bound a function of the path, which is
// the congestion controller's question and not this one.
func TestStreamWindowIsABudget(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 60*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if limit := allowedOn(t, client, stream.ID()); limit != initialStreamWindow {
		t.Fatalf("a new stream starts with %d bytes of credit", limit)
	}
	// A stream exists on the peer only once something was written on it.
	if _, err = stream.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the peer to hear about the budget", func() bool {
		return allowedOn(t, client, stream.ID()) == grantedTo(t, server, stream.ID()).limit
	})
	granted := grantedTo(t, server, stream.ID())
	if granted.window != streamWindow {
		t.Fatalf("the stream window is %d bytes, expected %d", granted.window, streamWindow)
	}
	if granted.limit < streamWindow {
		t.Fatalf("the ceiling is %d bytes, expected at least the budget %d", granted.limit, streamWindow)
	}
	if window, _, _ := associationWindowOf(t, server); window != connectionWindow {
		t.Fatalf("the association window is %d bytes, expected %d", window, connectionWindow)
	}
	// Nothing is read from here on, so the peer is stopped where the read holds the
	// ceiling: two budgets past it, which is the memory this stream may cost.
	stopped := make(chan error, 1)
	go func() {
		_, writeErr := stream.Write(testPayload(int(2*streamWindow) + 4096))
		stopped <- writeErr
	}()
	waitUntil(t, "the peer to be stopped at the ceiling", func() bool {
		granted := grantedTo(t, server, stream.ID())
		return granted.limit == granted.highest
	})
	if granted := grantedTo(t, server, stream.ID()); granted.limit > granted.read+2*streamWindow {
		t.Fatalf("the ceiling is %d bytes with %d bytes read", granted.limit, granted.read)
	}
	// Reading is what moves the ceiling from there: the peer is waiting at it and has
	// nothing left to send, so an arrival is not what this can wait for.
	ceiling := allowedOn(t, client, stream.ID())
	if _, err = readExactly(accepted, 1<<20); err != nil {
		t.Fatalf("read: %v", err)
	}
	waitUntil(t, "the peer to hear about the read", func() bool {
		return allowedOn(t, client, stream.ID()) > ceiling
	})
	if granted := grantedTo(t, server, stream.ID()); granted.window != streamWindow {
		t.Fatalf("the window grew to %d bytes", granted.window)
	}
}
