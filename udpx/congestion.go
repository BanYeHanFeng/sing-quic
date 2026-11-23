package udpx

import (
	"github.com/sagernet/sing-quic/udpx/internal/congestion"
)

const initialCongestionWindowPackets = 128

func newCongestionController() congestion.Controller {
	return congestion.NewBbrController(
		congestion.ByteCount(maxPacketSize),
		int64(initialCongestionWindowPackets),
	)
}
