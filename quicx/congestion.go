package quicx

import (
	"github.com/sagernet/sing-quic/congestion"
	E "github.com/sagernet/sing/common/exceptions"
)

// parseBBRProfile turns the configured profile name into the one the transport
// runs. Congestion control belongs to the transport in this protocol, so what is
// left here is the name: no name means the transport's own default, which is what
// an empty option means everywhere else in the options of this protocol.
func parseBBRProfile(profile string) (congestion.Profile, error) {
	if profile == "" {
		return congestion.Profile{}, nil
	}
	parsed, err := congestion.ParseProfile(profile)
	if err != nil {
		return congestion.Profile{}, E.Cause(err, "parse BBR profile")
	}
	return parsed, nil
}
