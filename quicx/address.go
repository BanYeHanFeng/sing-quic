package quicx

import (
	"encoding/binary"

	M "github.com/sagernet/sing/common/metadata"
)

var AddressSerializer = M.NewSerializer(
	M.AddressFamilyByte(0x00, M.AddressFamilyFqdn),
	M.AddressFamilyByte(0x01, M.AddressFamilyIPv4),
	M.AddressFamilyByte(0x02, M.AddressFamilyIPv6),
	M.AddressFamilyByte(0xff, M.AddressFamilyEmpty),
)

// writeAddrPort writes destination into data and reports how many bytes it
// consumed. It is the counterpart of decodeAddrPort and writes exactly what
// AddressSerializer.WriteAddrPort writes: an address family byte, the address,
// and a port when the address is valid.
//
// It writes into a byte slice instead of through an io.Writer because it runs
// once per forwarded datagram, and the buffer the message is packed into is
// already at hand.
func writeAddrPort(data []byte, destination M.Socksaddr) int {
	if !destination.IsValid() {
		data[0] = addressFamilyEmpty
		return 1
	}
	if destination.IsIPv4() {
		data[0] = addressFamilyIPv4
		copy(data[1:5], destination.Addr.AsSlice())
		binary.BigEndian.PutUint16(data[5:7], destination.Port)
		return 7
	}
	if destination.IsIPv6() {
		data[0] = addressFamilyIPv6
		copy(data[1:17], destination.Addr.AsSlice())
		binary.BigEndian.PutUint16(data[17:19], destination.Port)
		return 19
	}
	data[0] = addressFamilyFqdn
	data[1] = byte(len(destination.Fqdn))
	fqdnLen := copy(data[2:], destination.Fqdn)
	binary.BigEndian.PutUint16(data[2+fqdnLen:], destination.Port)
	return 4 + fqdnLen
}
