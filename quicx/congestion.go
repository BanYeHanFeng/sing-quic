package quicx

import (
	"context"
	"time"

	"github.com/sagernet/quic-go"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing/common/ntp"
)

func setCongestion(ctx context.Context, connection *quic.Conn) {
	timeFunc := ntp.TimeFuncFromContext(ctx)
	if timeFunc == nil {
		timeFunc = time.Now
	}
	connection.SetCongestionControl(congestion_meta2.NewBbrSenderWithProfile(
		congestion_meta2.DefaultClock{TimeFunc: timeFunc},
		connection.InitialPacketSize(),
		congestion_meta2.ProfileConservative,
	))
}
