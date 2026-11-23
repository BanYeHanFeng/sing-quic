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
