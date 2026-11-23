package congestion

import (
	"math"
	"time"
)

const (
	infBandwidth = Bandwidth(math.MaxUint64)
)

type Bandwidth uint64

const (
	BitsPerSecond  Bandwidth = 1
	BytesPerSecond           = 8 * BitsPerSecond
)

func bandwidthFromDelta(bytes ByteCount, delta time.Duration) Bandwidth {
	return Bandwidth(bytes) * Bandwidth(time.Second) / Bandwidth(delta) * BytesPerSecond
}
