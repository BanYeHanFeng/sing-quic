package quicx

import (
	"testing"

	"github.com/sagernet/sing-quic/congestion"
)

// TestEmptyBBRProfileIsTheTransportsDefault requires an option nobody set to stay
// unset: the profile a client runs is the transport's choice, so a name that is not
// given must not pin one. Naming a profile still overrides it, and a name that does
// not exist is an error rather than a silent fallback.
func TestEmptyBBRProfileIsTheTransportsDefault(t *testing.T) {
	profile, err := parseBBRProfile("")
	if err != nil {
		t.Fatal(err)
	}
	if profile != (congestion.Profile{}) {
		t.Errorf("an empty profile name became %s, want the transport's default", profile.Name())
	}
	for _, name := range []congestion.Profile{
		congestion.ProfileConservative,
		congestion.ProfileStandard,
		congestion.ProfileAggressive,
	} {
		parsed, parseErr := parseBBRProfile(name.Name())
		if parseErr != nil {
			t.Fatalf("%s: %v", name.Name(), parseErr)
		}
		if parsed != name {
			t.Errorf("%s became %s", name.Name(), parsed.Name())
		}
	}
	if _, err = parseBBRProfile("bogus"); err == nil {
		t.Error("a profile that does not exist was accepted")
	}
}
