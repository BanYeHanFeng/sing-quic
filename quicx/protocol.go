package quicx

const (
	Version = 1
)

const (
	CommandAuthenticate = iota
	CommandConnect
	CommandPacket
	CommandDissociate
	CommandHeartbeat
)

const AuthenticateLen = 2 + 16 + 32
