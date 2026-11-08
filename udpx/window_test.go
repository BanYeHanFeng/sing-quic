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

// spentCreditOf reads how much of the peer's window this end has used.
func spentCreditOf(t *testing.T, conn Association) uint64 {
	t.Helper()
	a := conn.(*association)
	a.fcMu.Lock()
	defer a.fcMu.Unlock()
	return a.sendCredit.used
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

// TestDataForAnEndedStreamMovesTheWindow requires what arrives for a stream this end
// is done with to be given back to the association window. The peer spent its credit
// on those bytes and nothing here will ever read them, so a window that kept them
// spent would stop every stream beside the one that ended, for as long as the
// association lived.
func TestDataForAnEndedStreamMovesTheWindow(t *testing.T) {
	const size = 64 * 1024
	t.Run("opened by the peer", func(t *testing.T) {
		_, server, _ := testSetup(t, Options{}, Options{})
		a := server.(*association)
		const streamID = 2
		a.streamsMu.Lock()
		a.endedStreams.add(streamID)
		a.streamsMu.Unlock()
		before := recvWindowOf(t, server)
		if err := a.handleStreamFrame(streamData{streamID: streamID, data: make([]byte, size)}); err != nil {
			t.Fatal(err)
		}
		after := recvWindowOf(t, server)
		if after.received-before.received != size {
			t.Fatalf("%d bytes arrived for a stream that ended, the window counted %d", size, after.received-before.received)
		}
		if after.read-before.read != size {
			t.Fatalf("%d bytes were thrown away, the read moved %d", size, after.read-before.read)
		}
		if after.limit < after.received {
			t.Fatalf("the ceiling is %d with %d bytes arrived", after.limit, after.received)
		}
	})
	t.Run("opened here", func(t *testing.T) {
		client, _, _ := testSetup(t, Options{}, Options{})
		ctx := testContext(t, 60*time.Second)
		stream, err := client.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		id := stream.ID()
		client.(*association).removeStream(id)
		before := recvWindowOf(t, client)
		if err = client.(*association).handleStreamFrame(streamData{streamID: id, data: make([]byte, size)}); err != nil {
			t.Fatal(err)
		}
		after := recvWindowOf(t, client)
		if after.received-before.received != size {
			t.Fatalf("%d bytes arrived for a stream that ended, the window counted %d", size, after.received-before.received)
		}
	})
}

// TestAClosedStreamGivesBackItsUnsentCredit requires the credit taken for bytes that
// are never sent to be given back when the stream ends. The send buffer holds what the
// application wrote before it was framed, and a stream the peer reset never frames it:
// the association window is shared, so a window still holding those bytes is every
// other stream stopped behind one connection that closed.
func TestAClosedStreamGivesBackItsUnsentCredit(t *testing.T) {
	client, _, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 60*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload(128 * 1024)
	stream.sendMu.Lock()
	stream.sendCredit.take(uint64(len(payload)))
	client.(*association).takeConnectionCredit(uint64(len(payload)))
	stream.bufferSendData(payload)
	stream.sendMu.Unlock()
	spent := spentCreditOf(t, client)
	if spent < uint64(len(payload)) {
		t.Fatalf("the write took %d bytes of credit", spent)
	}
	stream.resetFromPeer(resetCodeNormal)
	if used, owed := spentCreditOf(t, client), spent-uint64(len(payload)); used != owed {
		t.Fatalf("the window holds %d bytes after the stream ended, expected %d", used, owed)
	}
}

// recvWindowState is what one end allows the peer to send overall.
type recvWindowState struct {
	received uint64
	read     uint64
	limit    uint64
}

func recvWindowOf(t *testing.T, conn Association) recvWindowState {
	t.Helper()
	a := conn.(*association)
	a.fcMu.Lock()
	defer a.fcMu.Unlock()
	return recvWindowState{received: a.recvReceived, read: a.recvRead, limit: a.recvLimit}
}

// availableCreditOf reads how much the peer still allows this end to send.
func availableCreditOf(t *testing.T, conn Association) uint64 {
	t.Helper()
	a := conn.(*association)
	a.fcMu.Lock()
	defer a.fcMu.Unlock()
	return a.sendCredit.available()
}

// TestStreamsSurviveClosingWithDataQueued requires an association to keep carrying
// streams after some of them ended with data still queued for them, which is the shape
// a proxy gives it: a connection behind a stream closes while a transfer into it is
// still running, and what the peer already spent its window on has to come back when
// the bytes are thrown away. A window that keeps them spent stops every stream that
// opens after them, and no read ever moves it again.
func TestStreamsSurviveClosingWithDataQueued(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 120*time.Second)
	const size = 4 * 1024 * 1024
	payload := testPayload(size)
	for index := range 6 {
		closed := make(chan struct{})
		go func() {
			stream, err := server.AcceptStream(ctx)
			if err != nil {
				return
			}
			<-closed
			_ = stream.Close()
		}()
		stream, err := client.OpenStream(ctx)
		if err != nil {
			t.Fatalf("open %d: %v", index, err)
		}
		if _, err = stream.Write([]byte{0}); err != nil {
			t.Fatalf("write %d: %v", index, err)
		}
		waitUntil(t, "the peer to grant the stream window", func() bool {
			return allowedOn(t, client, stream.ID()) >= size
		})
		waitUntil(t, "the peer to grant the association window", func() bool {
			return availableCreditOf(t, client) >= size
		})
		if err = stream.SetWriteDeadline(time.Now().Add(20 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err = stream.Write(payload); err != nil {
			t.Fatalf("write %d: %v", index, err)
		}
		close(closed)
		waitUntil(t, "the stream to end", func() bool {
			return stream.isEnded()
		})
		_ = stream.Close()
		waitUntil(t, "the window the closed stream spent to come back", func() bool {
			return availableCreditOf(t, client) >= size
		})
	}
}
