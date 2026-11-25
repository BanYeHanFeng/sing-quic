package udpx

import (
	"testing"
)

func TestWindowOpensOnce(t *testing.T) {
	window := newStreamReceiveWindow()
	limit, moved := window.next()
	if !moved {
		t.Fatal("the window did not open")
	}
	if limit != streamWindow {
		t.Fatalf("limit %d", limit)
	}
	window.received = 1
	if _, moved = window.next(); moved {
		t.Fatal("the window moved again with most of it unused")
	}
}

func TestWindowKeepsEnoughRoom(t *testing.T) {
	window := newStreamReceiveWindow()
	window.next()
	window.received = 5 << 20
	limit, moved := window.next()
	if !moved {
		t.Fatal("the window did not move after half of it was consumed")
	}
	if limit != 13<<20 {
		t.Fatalf("limit %d", limit)
	}
}

func TestWindowIsCappedByRead(t *testing.T) {
	window := newStreamReceiveWindow()
	window.next()
	window.received = 100 << 20
	limit, moved := window.next()
	if !moved {
		t.Fatal("the window did not move")
	}
	if limit != 2*streamWindow {
		t.Fatalf("limit %d goes past read+2*window", limit)
	}
}

func TestWindowNeverShrinks(t *testing.T) {
	window := newStreamReceiveWindow()
	window.limit = streamWindow
	if _, moved := window.next(); moved {
		t.Fatal("the window moved past the peer")
	}
}

func TestConnectionWindowStartsOpen(t *testing.T) {
	window := newConnectionReceiveWindow()
	limit, moved := window.next()
	if !moved {
		t.Fatal("the initial window was not announced")
	}
	if limit != connectionWindow {
		t.Fatalf("limit %d", limit)
	}
}

func TestWindowObserve(t *testing.T) {
	window := newStreamReceiveWindow()
	if received := window.observe(100); received != 100 {
		t.Fatalf("%d bytes were new", received)
	}
	if received := window.observe(100); received != 0 {
		t.Fatalf("%d bytes were new for a repeated offset", received)
	}
	if received := window.observe(150); received != 50 {
		t.Fatalf("%d bytes were new", received)
	}
	window.onRead(120)
	window.received = 4000
	if limit, moved := window.next(); !moved || limit != 4000+streamWindow {
		t.Fatalf("limit %d after reading %d of %d", limit, window.read, window.received)
	}
}

func TestWindowAddRefusesOverrun(t *testing.T) {
	window := newConnectionReceiveWindow()
	if !window.add(int(initialConnectionWindow)) {
		t.Fatal("the initial window was refused")
	}
	if window.add(1) {
		t.Fatal("a byte beyond the window was accepted")
	}
}
