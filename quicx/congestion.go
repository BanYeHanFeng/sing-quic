package quicx

import (
	"github.com/sagernet/sing-quic/congestion"
	E "github.com/sagernet/sing/common/exceptions"
)

// parseBBRProfile turns the configured profile name into the one the transport
// runs. Congestion control belongs to the transport in this protocol, so what is
// left here is the name: the zero value is the conservative profile, which is
// also what an empty option means.
func parseBBRProfile(profile string) (congestion.Profile, error) {
	if profile == "" {
		return congestion.ProfileConservative, nil
	}
	parsed, err := congestion.ParseProfile(profile)
	if err != nil {
		return congestion.Profile{}, E.Cause(err, "parse BBR profile")
	}
	return parsed, nil
}
