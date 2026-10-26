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

// associationCreditOf reads what the peer allows this end to send overall.
func associationCreditOf(t *testing.T, conn Association) uint64 {
	t.Helper()
	a := conn.(*association)
	a.fcMu.Lock()
	defer a.fcMu.Unlock()
	return a.sendCredit.limit
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

// fillWindow has the peer write everything it is still allowed to write, and waits
// until all of it arrived. The sender ends up stopped at the credit rather than at
// the end of what it had to send, which is the difference between a window that is
// too small and one that is not.
func fillWindow(t *testing.T, sender Association, stream *Stream, receiver Association, id uint32) {
	t.Helper()
	// What the peer may write is what this end granted, which takes a frame to
	// arrive: filling before that would be filling a window that moved.
	waitUntil(t, "the peer to hear about the window", func() bool {
		return allowedOn(t, sender, id) == grantedTo(t, receiver, id).limit
	})
	stream.sendMu.Lock()
	available := int(stream.sendCredit.available())
	stream.sendMu.Unlock()
	written := make(chan error, 1)
	go func() {
		_, writeErr := stream.Write(testPayload(available))
		written <- writeErr
	}()
	waitUntil(t, "the window to be filled", func() bool {
		granted := grantedTo(t, receiver, id)
		return granted.highest == granted.limit
	})
	select {
	case err := <-written:
		if err != nil {
			t.Fatalf("write: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("writing one window did not finish")
	}
}

// TestStreamWindowGrowsWhenThePeerFillsIt requires the window a receiver grants to
// grow when the peer sends everything it was allowed to and stops there.
//
// The peer filling the window is the only evidence a receiver has: on a slow path
// the window and not the link is what the sender runs out of, and the half of the
// window that has to be read before it moves is a round trip the path spends
// waiting. The association window has to follow, in the ratio the two are accounted
// for in.
func TestStreamWindowGrowsWhenThePeerFillsIt(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 30*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// A stream exists on the peer only once something was written on it.
	if _, err = stream.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fillWindow(t, client, stream, server, accepted.ID())
	if granted := grantedTo(t, server, accepted.ID()); granted.window != initialStreamWindow {
		t.Fatalf("the window grew to %d bytes before anything was read", granted.window)
	}
	// Half of the window read is where the receiver moves it.
	if _, err = readExactly(accepted, initialStreamWindow/2); err != nil {
		t.Fatal(err)
	}
	if granted := grantedTo(t, server, accepted.ID()); granted.window != 2*initialStreamWindow {
		t.Fatalf("the window grew to %d bytes after %d of %d were read", granted.window, granted.read, initialStreamWindow)
	}
	// Four streams of the stream window fill the association window, so a stream
	// window that doubled took it along.
	window, limit, read := associationWindowOf(t, server)
	if window != 4*2*initialStreamWindow {
		t.Fatalf("the association window grew to %d bytes", window)
	}
	if limit != read+window {
		t.Fatalf("the association limit %d is not %d bytes beyond %d read", limit, window, read)
	}
	// Both ends agree on both numbers once the frames arrived.
	waitUntil(t, "the peer hearing about the windows", func() bool {
		return allowedOn(t, client, accepted.ID()) == grantedTo(t, server, accepted.ID()).limit &&
			associationCreditOf(t, client) == limit
	})
}

// TestStreamWindowStaysWhenThePeerStopsShort requires a window that the peer did not
// fill to stay where it is: a peer that wrote less than it was allowed to was not
// stopped by the credit, and a window that grew anyway is memory spent on nothing.
func TestStreamWindowStaysWhenThePeerStopsShort(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 30*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload(initialStreamWindow / 2)
	if _, err = stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if read, readErr := readExactly(accepted, len(payload)); readErr != nil || len(read) != len(payload) {
		t.Fatalf("the peer read %d bytes: %v", len(read), readErr)
	}
	if granted := grantedTo(t, server, accepted.ID()); granted.window != initialStreamWindow {
		t.Fatalf("the window grew to %d bytes with %d of %d sent", granted.window, granted.read, initialStreamWindow)
	}
	if window, _, _ := associationWindowOf(t, server); window != initialConnectionWindow {
		t.Fatalf("the association window grew to %d bytes", window)
	}
	if limit := allowedOn(t, client, accepted.ID()); limit != initialStreamWindow {
		t.Fatalf("the peer was told about %d bytes", limit)
	}
}

// TestStreamWindowStopsAtTheCeiling requires the growth to stop at the ceiling: a
// window costs memory the peer may fill before the application reads, so how often
// it may double is bounded rather than whatever the path would take.
//
// Each round has the peer fill the window that was granted last, then reads half of
// it, which is the step that moves the window. The last of them fills a window of
// the size the ceiling names, and reading half of that one has to leave the window
// where it is.
func TestStreamWindowStopsAtTheCeiling(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 60*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// A stream exists on the peer only once something was written on it.
	if _, err = stream.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for window := uint64(initialStreamWindow); window <= maxStreamWindow; window *= 2 {
		fillWindow(t, client, stream, server, accepted.ID())
		if granted := grantedTo(t, server, accepted.ID()); granted.window != window {
			t.Fatalf("the window is %d bytes, expected %d", granted.window, window)
		}
		read := int(window / 2)
		if _, err = readExactly(accepted, read); err != nil {
			t.Fatalf("reading %d bytes of a window of %d: %v", read, window, err)
		}
		if granted := grantedTo(t, server, accepted.ID()); granted.window != growWindow(window, maxStreamWindow) {
			t.Fatalf("a window of %d bytes became %d", window, granted.window)
		}
	}
	if window, _, _ := associationWindowOf(t, server); window != maxConnectionWindow {
		t.Fatalf("the association window reached %d bytes of a ceiling of %d", window, maxConnectionWindow)
	}
}
