//go:build linux

package udpio

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	udpGRO = 104

	oobSize = 64

	maxSegmentTotal = 65507

	desiredReceiveBuffer = 8 * 1024 * 1024
	desiredSendBuffer    = 1 * 1024 * 1024
)

type batchedConn struct {
	net.PacketConn
	raw syscall.RawConn
	gso bool
	gro bool

	writeMu  sync.Mutex
	coalesce []byte
	cmsg     []byte
	oob      [oobSize]byte

	sendBuf  []byte
	sendOOB  []byte
	sendAddr unix.Sockaddr
	sendN    int
	sendErr  error
	writeFn  func(fd uintptr) bool
}

func newBatched(conn net.PacketConn) Conn {
	syscallConn, isSyscallConn := conn.(syscall.Conn)
	if !isSyscallConn {
		return nil
	}
	raw, err := syscallConn.SyscallConn()
	if err != nil || raw == nil {
		return nil
	}
	c := &batchedConn{PacketConn: conn, raw: raw}
	c.writeFn = c.write
	var gso, gro bool
	err = raw.Control(func(fd uintptr) {
		setBuffer(int(fd), unix.SO_RCVBUF, unix.SO_RCVBUFFORCE, desiredReceiveBuffer)
		setBuffer(int(fd), unix.SO_SNDBUF, unix.SO_SNDBUFFORCE, desiredSendBuffer)
		_, gsoErr := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
		gso = gsoErr == nil
		gro = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, udpGRO, 1) == nil
	})
	if err != nil {
		return nil
	}
	c.gso = gso
	c.gro = gro
	return c
}

func setBuffer(fd int, option int, force int, size int) {
	current, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, option)
	if err == nil && current >= size {
		return
	}
	if unix.SetsockoptInt(fd, unix.SOL_SOCKET, option, size) == nil {
		return
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, force, size)
}

func (c *batchedConn) ReadPacket(buffer []byte) (Packet, error) {
	var (
		received int
		oobLen   int
		from     unix.Sockaddr
		recvErr  error
	)
	waitErr := c.raw.Read(func(fd uintptr) bool {
		for {
			received, oobLen, _, from, recvErr = unix.Recvmsg(int(fd), buffer, c.oob[:], 0)
			if recvErr == unix.EINTR {
				continue
			}
			return recvErr != unix.EAGAIN
		}
	})
	if waitErr != nil {
		return Packet{}, waitErr
	}
	if recvErr != nil {
		return Packet{}, os.NewSyscallError("recvmsg", recvErr)
	}
	return receivedPacket(buffer[:received], c.oob[:oobLen], from), nil
}

func receivedPacket(data []byte, oob []byte, from unix.Sockaddr) Packet {
	packet := Packet{Data: data, Addr: addrOf(from), Segments: 1}
	if len(oob) == 0 {
		return packet
	}
	size, ok := segmentSizeOf(oob)
	if !ok || size <= 0 || len(data) <= size {
		return packet
	}
	packet.SegmentSize = size
	packet.Segments = (len(data) + size - 1) / size
	return packet
}

func (c *batchedConn) WritePackets(packets []Packet) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	for start := 0; start < len(packets); {
		count := c.segmentCount(packets, start)
		if count > 1 {
			err := c.writeSegments(packets[start : start+count])
			if err == nil {
				start += count
				continue
			}
			if !isGSOError(err) {
				return start, err
			}
			c.gso = false
		}
		if err := c.send(packets[start].Data, packets[start].Addr, 0); err != nil {
			return start, err
		}
		start++
	}
	return len(packets), nil
}

func (c *batchedConn) segmentCount(packets []Packet, start int) int {
	if !c.gso || start >= len(packets) {
		return 1
	}
	size := len(packets[start].Data)
	if size == 0 || size > maxSegmentTotal {
		return 1
	}
	total := size
	end := start + 1
	for end < len(packets) {
		length := len(packets[end].Data)
		if length == 0 || length > size || total+length > maxSegmentTotal {
			break
		}
		if !sameAddr(packets[start].Addr, packets[end].Addr) {
			break
		}
		total += length
		end++
		if length < size {
			break
		}
	}
	return end - start
}

func (c *batchedConn) writeSegments(packets []Packet) error {
	total := 0
	for _, packet := range packets {
		total += len(packet.Data)
	}
	if cap(c.coalesce) < total {
		c.coalesce = make([]byte, 0, total)
	}
	buffer := c.coalesce[:0]
	for _, packet := range packets {
		buffer = append(buffer, packet.Data...)
	}
	c.coalesce = buffer
	return c.send(buffer, packets[0].Addr, len(packets[0].Data))
}

func (c *batchedConn) send(data []byte, addr net.Addr, segmentSize int) error {
	sockaddr, err := addrSockaddrOf(addr)
	if err != nil {
		return err
	}
	oob := c.cmsg[:0]
	if segmentSize > 0 && len(data) > segmentSize {
		oob = appendSegmentSize(oob, uint16(segmentSize))
	}
	c.cmsg = oob
	c.sendBuf = data
	c.sendOOB = oob
	c.sendAddr = sockaddr
	c.sendN, c.sendErr = 0, nil
	waitErr := c.raw.Write(c.writeFn)
	written, sendErr := c.sendN, c.sendErr
	c.sendBuf, c.sendOOB, c.sendAddr = nil, nil, nil
	c.sendN, c.sendErr = 0, nil
	if waitErr != nil {
		return waitErr
	}
	if sendErr != nil {
		return os.NewSyscallError("sendmsg", sendErr)
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func (c *batchedConn) write(fd uintptr) bool {
	for {
		written, err := unix.SendmsgN(int(fd), c.sendBuf, c.sendOOB, c.sendAddr, 0)
		if err == unix.EINTR {
			continue
		}
		c.sendN, c.sendErr = written, err
		return err != unix.EAGAIN
	}
}

func (c *batchedConn) Offload() (bool, bool) { return c.gso, c.gro }

func addrOf(sockaddr unix.Sockaddr) net.Addr {
	switch addr := sockaddr.(type) {
	case *unix.SockaddrInet4:
		return &net.UDPAddr{IP: net.IP(addr.Addr[:]), Port: addr.Port}
	case *unix.SockaddrInet6:
		return &net.UDPAddr{IP: net.IP(addr.Addr[:]), Port: addr.Port}
	default:
		return nil
	}
}

func segmentSizeOf(oob []byte) (int, bool) {
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0, false
	}
	for _, message := range messages {
		if message.Header.Level != unix.IPPROTO_UDP || message.Header.Type != udpGRO {
			continue
		}
		if len(message.Data) < 4 {
			return 0, false
		}
		return int(binary.NativeEndian.Uint32(message.Data)), true
	}
	return 0, false
}

func sockaddrOf(addr *net.UDPAddr) (unix.Sockaddr, error) {
	if ip := addr.IP.To4(); ip != nil {
		sockaddr := &unix.SockaddrInet4{Port: addr.Port}
		copy(sockaddr.Addr[:], ip)
		return sockaddr, nil
	}
	if ip := addr.IP.To16(); ip != nil {
		sockaddr := &unix.SockaddrInet6{Port: addr.Port}
		copy(sockaddr.Addr[:], ip)
		return sockaddr, nil
	}
	return nil, errors.New("udpio: " + addr.String() + " is not an IP address")
}

func addrSockaddrOf(addr net.Addr) (unix.Sockaddr, error) {
	udpAddr, isUDPAddr := addr.(*net.UDPAddr)
	if !isUDPAddr {
		return nil, &net.OpError{Op: "write", Net: "udp", Addr: addr, Err: errors.New("unsupported address type")}
	}
	return sockaddrOf(udpAddr)
}

func sameAddr(a, b net.Addr) bool {
	if a == b {
		return true
	}
	first, isUDPAddr := a.(*net.UDPAddr)
	if !isUDPAddr {
		return false
	}
	second, isUDPAddr := b.(*net.UDPAddr)
	if !isUDPAddr {
		return false
	}
	return first.Port == second.Port && first.Zone == second.Zone && first.IP.Equal(second.IP)
}

func appendSegmentSize(oob []byte, size uint16) []byte {
	start := len(oob)
	const dataLen = 2
	oob = append(oob, make([]byte, unix.CmsgSpace(dataLen))...)
	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[start]))
	header.Level = unix.IPPROTO_UDP
	header.Type = unix.UDP_SEGMENT
	header.SetLen(unix.CmsgLen(dataLen))
	offset := start + unix.CmsgSpace(0)
	*(*uint16)(unsafe.Pointer(&oob[offset])) = size
	return oob
}

func isGSOError(err error) bool {
	var syscallErr *os.SyscallError
	if errors.As(err, &syscallErr) {
		return syscallErr.Err == unix.EIO || syscallErr.Err == unix.EINVAL || syscallErr.Err == unix.EMSGSIZE
	}
	return false
}
