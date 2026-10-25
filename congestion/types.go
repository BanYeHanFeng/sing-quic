// Package congestion is BBR and the pacer that goes with it, with no transport in
// it: it is told what was sent, acknowledged and given up on, and it answers how
// much may be in flight and when the next packet may leave.
//
// The types are the transport's own units — bytes, packet numbers, times — so that
// a transport can use this package without adopting another one's. Nothing here
// knows what a stream is, what a packet looks like, or how an acknowledgement
// arrives; that is what makes the same code usable over a packet number that is in
// the clear and over one that is not.
package congestion

import "time"

// ByteCount is a number of bytes.
type ByteCount uint64

// PacketNumber is the number the transport gave a packet.
type PacketNumber int64

const (
	// MinPacingDelay is the shortest wait the pacer hands out. A pacing delay below
	// the resolution of a timer would turn the send loop into a busy loop.
	MinPacingDelay = time.Millisecond

	// PacketsPerConnectionID is only used to size a window; the transport here has
	// one packet number space per association.
	PacketsPerConnectionID = 100

	// MaxPacketBufferSize bounds the number of send times kept per association.
	MaxPacketBufferSize = 1000

	// MaxCongestionWindowPackets bounds the congestion window.
	MaxCongestionWindowPackets = 20000
)

// AckedPacketInfo is what the transport tells the controller about a packet that
// was acknowledged.
type AckedPacketInfo struct {
	TimeSent     time.Time
	BytesAcked   ByteCount
	PacketNumber PacketNumber
}

// LostPacketInfo is what the transport tells the controller about a packet that
// was given up on.
type LostPacketInfo struct {
	TimeSent     time.Time
	BytesLost    ByteCount
	PacketNumber PacketNumber
}

// Controller is what a transport asks a congestion controller: it is told what
// left, what arrived and what was given up on, and it answers how much may be in
// flight and when the next packet may leave.
type Controller interface {
	OnPacketSent(sentTime time.Time, bytesInFlight ByteCount, packetNumber PacketNumber, bytes ByteCount, isRetransmittable bool)
	OnPacketAcked(packetNumber PacketNumber, ackedBytes, priorInFlight ByteCount, eventTime time.Time)
	OnPacketLost(packetNumber PacketNumber, lostBytes, priorInFlight ByteCount)
	CanSend(bytesInFlight ByteCount) bool
	TimeUntilSend(bytesInFlight ByteCount) time.Time
	HasPacingBudget(now time.Time) bool
	GetCongestionWindow() ByteCount
	SetMaxDatagramSize(maxDatagramSize ByteCount)
	SetRTTStatsProvider(provider RTTStatsProvider)
}

// RTTStatsProvider is what the controller asks about the path. The transport owns
// the estimate, because it is the one that sees the acknowledgements arrive.
type RTTStatsProvider interface {
	MinRTT() time.Duration
	SmoothedRTT() time.Duration
	LatestRTT() time.Duration
}

// NewBbrController returns a BBR controller for a transport.
func NewBbrController(initialMaxDatagramSize ByteCount, profile Profile) Controller {
	return NewBbrSenderWithProfile(initialMaxDatagramSize, profile)
}
