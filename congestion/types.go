// Package congestion is BBR and the pacer that goes with it: it is told what was
// sent, acknowledged and given up on, and it answers how much may be in flight and
// when the next packet may leave.
//
// It is the controller of the udpx transport and nothing else: the units are the
// ones that transport has, and what it asks for is what that transport reports. The
// copy of the same algorithm that quic-go's hysteria2 and tuic use stays where it
// is, in congestion_meta2, untouched by anything here.
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
//
// An acknowledgement is reported as one event with everything it covered rather
// than as one call per packet: a controller that reacts to loss needs the losses
// of the same acknowledgement together with the bytes that arrived despite them,
// and a transport cannot know which of them a controller considers one event.
type Controller interface {
	OnPacketSent(sentTime time.Time, bytesInFlight ByteCount, packetNumber PacketNumber, bytes ByteCount, isRetransmittable bool)
	// OnCongestionEvent reports what one acknowledgement settled: the packets it
	// covered and the packets that were declared lost by the same answer, with
	// what was in flight before either of them left the flight table.
	OnCongestionEvent(priorInFlight ByteCount, eventTime time.Time, ackedPackets []AckedPacketInfo, lostPackets []LostPacketInfo)
	CanSend(bytesInFlight ByteCount) bool
	TimeUntilSend(bytesInFlight ByteCount) time.Time
	HasPacingBudget(now time.Time) bool
	GetCongestionWindow() ByteCount
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

// NewBbrControllerWithInitialWindow is NewBbrController with the first window
// chosen by the transport, in packets. Zero or less asks for the default.
func NewBbrControllerWithInitialWindow(initialMaxDatagramSize ByteCount, profile Profile, initialWindowPackets int64) Controller {
	return NewBbrSenderWithInitialWindow(initialMaxDatagramSize, profile, initialWindowPackets)
}
