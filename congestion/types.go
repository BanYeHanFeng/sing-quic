package congestion

import "time"

type ByteCount uint64

type PacketNumber int64

type SendState struct {
	priorAckTime time.Time
	delivered    ByteCount
	sentTotal    ByteCount
	sendRate     Bandwidth
	appLimited   bool
}

type AckedPacketInfo struct {
	SendState
	TimeSent     time.Time
	BytesAcked   ByteCount
	PacketNumber PacketNumber
}

type LostPacketInfo struct {
	SendState
	TimeSent     time.Time
	BytesLost    ByteCount
	PacketNumber PacketNumber
}

type Controller interface {
	OnPacketSent(sentTime time.Time, bytesInFlight ByteCount, packetNumber PacketNumber, bytes ByteCount) SendState
	OnCongestionEvent(priorInFlight ByteCount, eventTime time.Time, ackedPackets []AckedPacketInfo, lostPackets []LostPacketInfo)
	CanSend(bytesInFlight ByteCount) bool
	OnAppLimited()
	PacingWait(now time.Time) time.Duration
	GetCongestionWindow() ByteCount
	SetRTTStatsProvider(provider RTTStatsProvider)
}

type Diagnostics interface {
	Describe() string
}

type RTTStatsProvider interface {
	MinRTT() time.Duration
	SmoothedRTT() time.Duration
	LatestRTT() time.Duration
}

func NewBbrController(initialMaxDatagramSize ByteCount, initialWindowPackets int64) Controller {
	return newBbrSender(initialMaxDatagramSize, initialWindowPackets)
}
