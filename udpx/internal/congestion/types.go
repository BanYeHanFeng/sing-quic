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
	// OnAppLimited 说明当前没有待发数据：此后的采样反映不了链路容量。
	OnAppLimited()
	// OnTimePassed 在没有确认事件时推进与时间相关的状态机，例如 ProbeRTT 的退出。
	OnTimePassed(now time.Time)
	CanSend(bytesInFlight ByteCount) bool
	PacingWait(now time.Time) time.Duration
	GetCongestionWindow() ByteCount
	SetMinRTTProvider(provider MinRTTProvider)
}

type MinRTTProvider interface {
	MinRTT() time.Duration
}

func NewBbrController(initialMaxDatagramSize ByteCount, initialWindowPackets int64) Controller {
	return newBbrSender(initialMaxDatagramSize, initialWindowPackets)
}
