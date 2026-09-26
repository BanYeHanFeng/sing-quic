package congestion

import (
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go/monotime"
	"github.com/sagernet/quic-go/qlog"
	"github.com/sagernet/quic-go/qlogwriter"
)

var _ qlogwriter.Recorder = (*recordingQlogger)(nil)

// recordingQlogger collects the events a sender reports, so a test can assert
// on the qlog trace without writing a file.
type recordingQlogger struct {
	access sync.Mutex
	events []qlogwriter.Event
}

func (r *recordingQlogger) RecordEvent(event qlogwriter.Event) {
	r.access.Lock()
	defer r.access.Unlock()
	r.events = append(r.events, event)
}

func (r *recordingQlogger) Close() error { return nil }

func (r *recordingQlogger) congestionStates() []qlog.CongestionState {
	r.access.Lock()
	defer r.access.Unlock()
	states := make([]qlog.CongestionState, 0, len(r.events))
	for _, event := range r.events {
		if state, isState := event.(qlog.CongestionStateUpdated); isState {
			states = append(states, state.State)
		}
	}
	return states
}

// TestBbrSenderTracesCongestionStates covers the trace which was missing from
// the online qlog: BBR never reported its mode, so a window change could not be
// attributed to the phase which caused it. Every transition has to be reported
// once, starting with the state the sender is in when the recorder is attached.
func TestBbrSenderTracesCongestionStates(t *testing.T) {
	sender := NewBbrSenderWithProfile(1441, ProfileStandard)
	// getTargetCongestionWindow reads min_rtt through the RTT provider, which a
	// sender without a connection does not have; the test only cares about the
	// mode transitions, so it is seeded directly.
	sender.minRtt = 40 * time.Millisecond
	recorder := &recordingQlogger{}
	sender.SetQlogger(recorder)
	now := monotime.Now()

	// STARTUP -> DRAIN. Enough is in flight to keep the sender below the drain
	// target, which is otherwise left in the same call.
	sender.isAtFullBandwidth = true
	sender.bytesInFlight = 100 * sender.minCongestionWindow
	sender.maybeExitStartupOrDrain(now)
	// DRAIN -> PROBE_BW.
	sender.bytesInFlight = 0
	sender.maybeExitStartupOrDrain(now)
	// PROBE_BW -> PROBE_RTT.
	sender.maybeEnterOrExitProbeRtt(now, false, true)

	want := []qlog.CongestionState{
		qlog.CongestionStateStartup,
		qlog.CongestionStateDrain,
		qlog.CongestionStateProbeBw,
		qlog.CongestionStateProbeRtt,
	}
	assertStates(t, recorder, want)

	// PROBE_RTT -> PROBE_BW is a transition and has to be reported...
	sender.enterProbeBandwidthMode(now)
	want = append(want, qlog.CongestionStateProbeBw)
	assertStates(t, recorder, want)

	// ...but re-entering the mode the sender is already in is not. BBR passes
	// through enterProbeBandwidthMode from several paths, and a repeated event
	// would hide the real transitions.
	sender.enterProbeBandwidthMode(now)
	assertStates(t, recorder, want)
}

func assertStates(t *testing.T, recorder *recordingQlogger, want []qlog.CongestionState) {
	t.Helper()
	got := recorder.congestionStates()
	if len(got) != len(want) {
		t.Fatalf("reported congestion states %v, want %v", got, want)
	}
	for i, state := range want {
		if got[i] != state {
			t.Fatalf("reported congestion states %v, want %v", got, want)
		}
	}
}
