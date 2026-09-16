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
		ParityRows:               2,
		ConfiguredOverhead:       2.0 / 13,
		LossRate:                 0.05,
		ProtectedPacketsSent:     130,
		ProtectedBytesSent:       200000,
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
	for _, expected := range []string{
		"tx loss 5.0% (peer reported)",
		"group 13 rows 2",
		"overhead 15.4% configured",
		"6.0% measured",
		"protected 130 pkts (195.3 KB)",
		"parity 10 pkts (11.7 KB)",
		"skipped 0 groups",
		"rx repaired 7, unrecoverable 1, parity 9 pkts, protected 40 pkts",
	} {
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
	if !strings.Contains(line, "idle") || !strings.Contains(line, "tx loss 0.0%") {
		t.Fatalf("unexpected line for an idle FEC: %q", line)
	}

	// a window in which the overhead cap kept FEC from sending parity has to be
	// visible on its own, otherwise the enforcement looks like FEC being idle
	line, _ = formatFECStats(quic.FECStats{Enabled: true}, quic.FECStats{
		Enabled:       true,
		GroupSize:     32,
		ParityRows:    1,
		SkippedGroups: 4,
	})
	if !strings.Contains(line, "skipped 4 groups") {
		t.Fatalf("expected the skipped groups to be reported: %q", line)
	}

	// A window that sent parity while FEC happened to be idle at the moment of the tick
	// still has to report the measured overhead: that is the number the cap applies to,
	// and the configured value alone is not available (or meaningful) when idle.
	line, _ = formatFECStats(quic.FECStats{Enabled: true}, quic.FECStats{
		Enabled:              true,
		ProtectedPacketsSent: 4,
		ProtectedBytesSent:   1000,
		ParityPacketsSent:    1,
		ParityBytesSent:      50,
	})
	if !strings.Contains(line, "idle") || !strings.Contains(line, "5.0% measured") {
		t.Fatalf("expected the measured overhead even while idle: %q", line)
	}

	// counters that went backwards (FEC was re-enabled) must not underflow
	line, _ = formatFECStats(quic.FECStats{Enabled: true, RecoveredPackets: 100, ParityPacketsSent: 50}, quic.FECStats{
		Enabled:              true,
		RecoveredPackets:     1,
		ParityPacketsSent:    2,
		ProtectedPacketsSent: 3,
	})
	if !strings.Contains(line, "repaired 0") || !strings.Contains(line, "parity 0 pkts") {
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

func TestFECLimits(t *testing.T) {
	if limits := fecLimits(nil); limits != "" {
		t.Fatalf("expected no limits for nil options, got %q", limits)
	}
	if limits := fecLimits(&FECOptions{}); limits != "" {
		t.Fatalf("expected no limits for the defaults, got %q", limits)
	}
	limits := fecLimits(&FECOptions{MaxOverheadPercent: 25, MaxGroupSize: 8, MaxParityRows: 2})
	if limits != ", max overhead 25%, max group 8, parity rows 2" {
		t.Fatalf("unexpected limits: %q", limits)
	}
}
