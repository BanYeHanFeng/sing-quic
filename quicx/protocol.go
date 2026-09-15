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
	// CommandFECAccept is sent by the server on a unidirectional stream to confirm
	// that the client's FEC capability was accepted.
	CommandFECAccept
)
