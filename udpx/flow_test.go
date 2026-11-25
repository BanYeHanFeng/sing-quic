package udpx

import (
	"testing"
)

func TestNextWindowOpensOnce(t *testing.T) {
	limit, moved := nextWindow(0, 0, 8<<20, initialStreamWindow)
	if !moved {
		t.Fatal("the window did not open")
	}
	if limit != 8<<20 {
		t.Fatalf("limit %d", limit)
	}
	if _, moved = nextWindow(1, 0, 8<<20, limit); moved {
		t.Fatal("the window moved again with most of it unused")
	}
}

func TestNextWindowKeepsEnoughRoom(t *testing.T) {
	limit, moved := nextWindow(5<<20, 0, 8<<20, 8<<20)
	if !moved {
		t.Fatal("the window did not move after half of it was consumed")
	}
	if limit != 13<<20 {
		t.Fatalf("limit %d", limit)
	}
}

func TestNextWindowIsCappedByRead(t *testing.T) {
	limit, moved := nextWindow(100<<20, 0, 8<<20, 8<<20)
	if !moved {
		t.Fatal("the window did not move")
	}
	if limit != 16<<20 {
		t.Fatalf("limit %d goes past read+2*window", limit)
	}
}

func TestNextWindowNeverShrinks(t *testing.T) {
	if _, moved := nextWindow(0, 0, 8<<20, 8<<20); moved {
		t.Fatal("the window moved past the peer")
	}
}

func TestFlowControlSendCredit(t *testing.T) {
	flow := newFlowControl()
	if flow.available() != initialConnectionWindow {
		t.Fatalf("%d available", flow.available())
	}
	if _, moved := flow.nextReceiveLimit(); !moved {
		t.Fatal("the initial window was not announced")
	}
	limit := flow.recvLimit
	if limit != connectionWindow {
		t.Fatalf("limit %d", limit)
	}
}
