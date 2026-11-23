package quicx

import (
	"encoding/binary"
	"io"
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	addressFamilyIPv4 = 0x01

	addressFamilyFqdn = 0x03

	addressFamilyIPv6 = 0x04

	addressFamilyEmpty = 0xff
)

func appendAddrPort(dst []byte, destination M.Socksaddr) []byte {
	if !destination.IsValid() {
		return append(dst, addressFamilyEmpty)
	}
	if destination.IsIPv4() {
		dst = append(dst, addressFamilyIPv4)
		dst = append(dst, destination.Addr.AsSlice()...)
		return binary.BigEndian.AppendUint16(dst, destination.Port)
	}
	if destination.IsIPv6() {
		dst = append(dst, addressFamilyIPv6)
		dst = append(dst, destination.Addr.AsSlice()...)
		return binary.BigEndian.AppendUint16(dst, destination.Port)
	}
	dst = append(dst, addressFamilyFqdn, byte(len(destination.Fqdn)))
	dst = append(dst, destination.Fqdn...)
	return binary.BigEndian.AppendUint16(dst, destination.Port)
}

func parseAddrPort(data []byte) (M.Socksaddr, int, error) {
	if len(data) < 1 {
		return M.Socksaddr{}, 0, io.ErrUnexpectedEOF
	}
	switch data[0] {
	case addressFamilyIPv4:
		if len(data) < 1+4+2 {
			return M.Socksaddr{}, 0, io.ErrUnexpectedEOF
		}
		var address [4]byte
		copy(address[:], data[1:5])
		return M.Socksaddr{Addr: netip.AddrFrom4(address), Port: binary.BigEndian.Uint16(data[5:7])}, 7, nil
	case addressFamilyIPv6:
		if len(data) < 1+16+2 {
			return M.Socksaddr{}, 0, io.ErrUnexpectedEOF
		}
		var address [16]byte
		copy(address[:], data[1:17])
		return M.Socksaddr{Addr: netip.AddrFrom16(address), Port: binary.BigEndian.Uint16(data[17:19])}.Unwrap(), 19, nil
	case addressFamilyFqdn:
		if len(data) < 2 {
			return M.Socksaddr{}, 0, io.ErrUnexpectedEOF
		}
		fqdnLen := int(data[1])
		if len(data) < 2+fqdnLen+2 {
			return M.Socksaddr{}, 0, io.ErrUnexpectedEOF
		}
		fqdn := string(data[2 : 2+fqdnLen])
		port := binary.BigEndian.Uint16(data[2+fqdnLen : 4+fqdnLen])
		return M.ParseSocksaddrHostPort(fqdn, port), 4 + fqdnLen, nil
	case addressFamilyEmpty:
		return M.Socksaddr{}, 1, nil
	default:
		return M.Socksaddr{}, 0, E.New("unknown address family ", data[0])
	}
}
