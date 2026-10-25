package quicx

// Version is the version of the protocol above the transport. It closes the
// stream and datagram headers of every session, and a peer that does not find it
// there is speaking something else: an old QUICX, or a probe.
//
// This is not the version of the transport. That one is negotiated in the
// handshake before a session exists, so a peer speaking the old QUIC-based
// protocol never reaches this code at all — the port simply does not answer it.
const Version = 2

// The command of a stream: what the connection it carries is for. There is only
// one, because a session is a set of proxied connections and nothing else.
const (
	// CommandConnect starts a proxied connection to the destination that follows.
	CommandConnect = iota
)

// The commands of a datagram: what the message it carries is. A forwarded UDP
// packet is one datagram of a channel, and a channel ends with the other command.
const (
	// CommandPacket carries one forwarded UDP packet of the channel it arrived
	// on, with the destination it goes to.
	CommandPacket = iota

	// CommandDissociate ends the channel it arrived on, which is what a client
	// sends when a packet connection it opened is done: without it the server
	// keeps the channel until the session ends or the connection times out.
	CommandDissociate
)
