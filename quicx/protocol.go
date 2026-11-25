package quicx

import (
	"encoding/binary"
	"io"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	CommandConnect = iota

	CommandPacket

	CommandDissociate
)

type udpMessage struct {
	destination M.Socksaddr
	data        []byte
}

// pack 编成数据报负载：channel u32 | command | address | data。
func (m udpMessage) pack(channel uint32) []byte {
	message := binary.BigEndian.AppendUint32(nil, channel)
	message = append(message, CommandPacket)
	message = appendAddrPort(message, m.destination)
	return append(message, m.data...)
}

// packChannel 编成只有通道与命令的负载。
func packChannel(channel uint32, command byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, channel), command)
}

func parseMessage(data []byte) (command byte, destination M.Socksaddr, payload []byte, err error) {
	if len(data) < 1 {
		return 0, M.Socksaddr{}, nil, io.ErrUnexpectedEOF
	}
	command = data[0]
	switch command {
	case CommandPacket:
		destination, length, parseErr := parseAddrPort(data[1:])
		if parseErr != nil {
			return 0, M.Socksaddr{}, nil, E.Cause(parseErr, "parse destination")
		}
		return command, destination, data[1+length:], nil
	case CommandDissociate:
		return command, M.Socksaddr{}, nil, nil
	default:
		return 0, M.Socksaddr{}, nil, E.New("unknown command ", command)
	}
}

func writeStreamRequest(dst []byte, destination M.Socksaddr) []byte {
	return appendAddrPort(append(dst, CommandConnect), destination)
}

func readStreamRequest(reader io.Reader) (M.Socksaddr, error) {
	var command [1]byte
	if _, err := io.ReadFull(reader, command[:]); err != nil {
		return M.Socksaddr{}, E.Cause(err, "read request")
	}
	if command[0] != CommandConnect {
		return M.Socksaddr{}, E.New("unknown stream command ", command[0])
	}
	return readAddrPort(reader)
}

func readAddrPort(reader io.Reader) (M.Socksaddr, error) {
	var family [1]byte
	if _, err := io.ReadFull(reader, family[:]); err != nil {
		return M.Socksaddr{}, E.Cause(err, "read address family")
	}
	switch family[0] {
	case addressFamilyEmpty:
		return M.Socksaddr{}, nil
	}
	var length []byte
	remaining := 0
	switch family[0] {
	case addressFamilyIPv4:
		remaining = 4 + 2
	case addressFamilyIPv6:
		remaining = 16 + 2
	case addressFamilyFqdn:
		var fqdnLen [1]byte
		if _, err := io.ReadFull(reader, fqdnLen[:]); err != nil {
			return M.Socksaddr{}, E.Cause(err, "read address length")
		}
		length = fqdnLen[:]
		remaining = int(fqdnLen[0]) + 2
	default:
		return M.Socksaddr{}, E.New("unknown address family ", family[0])
	}
	buffer := make([]byte, 0, 1+len(length)+remaining)
	buffer = append(buffer, family[0])
	buffer = append(buffer, length...)
	buffer = append(buffer, make([]byte, remaining)...)
	if _, err := io.ReadFull(reader, buffer[1+len(length):]); err != nil {
		return M.Socksaddr{}, E.Cause(err, "read address")
	}
	destination, _, err := parseAddrPort(buffer)
	if err != nil {
		return M.Socksaddr{}, E.Cause(err, "parse destination")
	}
	return destination, nil
}
