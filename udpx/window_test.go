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

// TestStreamWindowStopsGrowingOnASmallPath requires the window a receiver grants to
// stop growing when the path is smaller than it: a loopback carries a few packets per
// round trip, so two megabytes are a hundred round trips of data and doubling the
// window buys memory rather than rate.
//
// The peer filling the window is still what a window that is too small looks like, so
// what stops the doubling is the other half of the evidence — the rate did not grow
// with the window. The first doubling is the one the rate cannot answer, since there
// is no window before it to compare against, so what this pins is that the growth stops
// at the second: eight windows go through a window that stays where it is, which is the
// case that has to keep working while it does. What the peer follows is the limit
// moving forward on the read, not the window growing.
func TestStreamWindowStopsGrowingOnASmallPath(t *testing.T) {
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
	const size = 8 * initialStreamWindow
	wrote := make(chan error, 1)
	go func() {
		if _, writeErr := stream.Write(testPayload(size)); writeErr != nil {
			wrote <- writeErr
			return
		}
		wrote <- stream.CloseWrite()
	}()
	if _, err = readExactly(accepted, size); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err = <-wrote; err != nil {
		t.Fatalf("write: %v", err)
	}
	if granted := grantedTo(t, server, accepted.ID()); granted.window != 2*initialStreamWindow {
		t.Fatalf("the window grew to %d bytes after %d bytes through it", granted.window, size)
	}
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
	// What the peer hears is either the window as it started or that window moved
	// forward by the read, and which of the two depends on whether the update has
	// arrived yet. The window itself not growing is what the two checks above say;
	// this one is only about the update not carrying a larger one.
	if limit := allowedOn(t, client, accepted.ID()); limit != initialStreamWindow &&
		limit != uint64(len(payload))+initialStreamWindow {
		t.Fatalf("the peer was told about %d bytes", limit)
	}
}

// TestWindowMovedDoublesOnlyWhileThePathIsLarger requires the move of a window to
// depend on the rate the peer delivered at: a window that is what limits the peer
// doubles the rate when it doubles, and one that is larger than the path leaves the
// rate where the path put it.
func TestWindowMovedDoublesOnlyWhileThePathIsLarger(t *testing.T) {
	const megabyte = 1 << 20
	for _, test := range []struct {
		name     string
		previous uint64
		elapsed  time.Duration
		expected uint64
	}{
		{"twice the rate of the window before", 0, 100 * time.Millisecond, 2 * initialStreamWindow},
		{"half again the rate", 10 * megabyte, 60 * time.Millisecond, 2 * initialStreamWindow},
		{"the same rate", 10 * megabyte, 100 * time.Millisecond, initialStreamWindow},
		{"a rate that fell", 10 * megabyte, 400 * time.Millisecond, initialStreamWindow},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now()
			stream := newStream(&association{}, 4, initialStreamWindow)
			stream.readOffset = initialStreamWindow / 2
			stream.recvLimit = initialStreamWindow
			stream.windowSpent = true
			stream.recvRate = test.previous
			stream.recvMarked = 0
			stream.recvMarkedAt = now.Add(-test.elapsed)
			stream.recvHighest = megabyte
			_, window, moved := stream.windowMoved(now)
			if !moved {
				t.Fatal("the window did not move")
			}
			if window != test.expected {
				t.Fatalf("the window is %d bytes, expected %d", window, test.expected)
			}
		})
	}
}
