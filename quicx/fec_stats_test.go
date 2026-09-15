package quicx

import (
	"strings"
	"testing"

	"github.com/sagernet/quic-go"
)

func TestFormatFECStats(t *testing.T) {
	// nothing happened in the window
	if line, notable := formatFECStats(quic.FECStats{Enabled: true}, quic.FECStats{Enabled: true}); line != "" || notable {
		t.Fatalf("expected no log line, got %q (notable %v)", line, notable)
	}

	// a lossy window with repairs
	previous := quic.FECStats{Enabled: true}
	current := quic.FECStats{
		Enabled:                  true,
		GroupSize:                13,
		SendOverhead:             1.0 / 13,
		LossRate:                 0.05,
		ProtectedPacketsSent:     130,
		ParityPacketsSent:        10,
		ParityBytesSent:          12000,
		ParityPacketsReceived:    9,
		RecoveredPackets:         7,
		FailedPackets:            1,
		ProtectedPacketsReceived: 40,
	}
	line, notable := formatFECStats(previous, current)
	if !notable {
		t.Fatal("expected a notable window")
	}
	for _, expected := range []string{"path loss 5.0%", "group 13", "overhead 7.7%", "repaired 7", "unrecoverable 1", "10 sent / 9 received", "11.7 KB"} {
		if !strings.Contains(line, expected) {
			t.Fatalf("expected %q in %q", expected, line)
		}
	}

	// FEC is idle on a clean path
	line, notable = formatFECStats(quic.FECStats{Enabled: true}, quic.FECStats{
		Enabled:              true,
		ProtectedPacketsSent: 130,
	})
	if notable {
		t.Fatal("a window without repairs is not notable")
	}
	if !strings.Contains(line, "idle") || !strings.Contains(line, "path loss 0.0%") {
		t.Fatalf("unexpected line for an idle FEC: %q", line)
	}

	// counters that went backwards (FEC was re-enabled) must not underflow
	line, _ = formatFECStats(quic.FECStats{Enabled: true, RecoveredPackets: 100, ParityPacketsSent: 50}, quic.FECStats{
		Enabled:              true,
		RecoveredPackets:     1,
		ParityPacketsSent:    2,
		ProtectedPacketsSent: 3,
	})
	if !strings.Contains(line, "repaired 0") || !strings.Contains(line, "parity 0 sent") {
		t.Fatalf("unexpected line after a counter reset: %q", line)
	}
}

func TestHumanBytes(t *testing.T) {
	for _, test := range []struct {
		bytes    uint64
		expected string
	}{
		{bytes: 512, expected: "512 B"},
		{bytes: 2048, expected: "2.0 KB"},
		{bytes: 3 * 1024 * 1024, expected: "3.0 MB"},
	} {
		if bytes := humanBytes(test.bytes); bytes != test.expected {
			t.Fatalf("expected %q, got %q", test.expected, bytes)
		}
	}
}
