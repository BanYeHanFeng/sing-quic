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
	// udpGRO is UDP_GRO from linux/udp.h: the control message that reports where
	// the segments in a merged read end. The socket option of the same name
	// turned it on; it arrived in Linux 4.18.
	udpGRO = 104

	// oobSize holds the control messages of one receive. Only the segment size
	// is asked for, so one message is all that can come back.
	oobSize = 64

	// maxSegmentTotal is as many payload bytes as one UDP datagram can carry at
	// all. A segmented send is one datagram from the kernel's point of view, so
	// the whole run is bounded by the same number. It also keeps a batch from
	// being held back by the socket's send buffer.
	maxSegmentTotal = 65507

	// desiredReceiveBuffer and desiredSendBuffer are what this package asks the
	// socket for. The receive side matches the association window the transport
	// advertises: a buffer below it turns the window into a number the peer obeys
	// and the kernel then throws away. The send side is smaller because a send
	// buffer only has to hold one batch of paced packets.
	desiredReceiveBuffer = 4 * 1024 * 1024
	desiredSendBuffer    = 1 * 1024 * 1024
)

// batchedConn is the Linux fast path: one sendmsg for a run of equal datagrams,
// one recvmsg that may hold a run of them.
type batchedConn struct {
	net.PacketConn
	raw syscall.RawConn
	gso bool
	gro bool

	// writeMu serializes senders: a listener's socket is shared by every
	// association under it, and each of them calls WritePackets whenever it has
	// something to say. The send state below lives across the poller callback,
	// so two senders must not take turns in the middle of one.
	writeMu  sync.Mutex
	coalesce []byte
	oob      [oobSize]byte

	sendBuf  []byte
	sendOOB  []byte
	sendAddr unix.Sockaddr
	sendN    int
	sendErr  error
	writeFn  func(fd uintptr) bool

	one [1]Packet
}

func newBatched(conn net.PacketConn, options Options) Conn {
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
		if !options.DisableGSO {
			// A kernel that does not know UDP_SEGMENT answers with an error,
			// which is the whole capability check.
			_, gsoErr := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
			gso = gsoErr == nil
		}
		if options.GRO {
			gro = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, udpGRO, 1) == nil
		}
	})
	if err != nil || (!gso && !gro) {
		return nil
	}
	c.gso = gso
	c.gro = gro
	return c
}

// setBuffer asks for a socket buffer large enough for the window this protocol
// advertises: a receive buffer smaller than the window is a window that cannot be
// filled, because what the peer was allowed to send does not fit and the kernel
// drops the rest. It is a request, not a promise — a host that caps its buffers
// keeps the cap, and the transport simply cannot use a window larger than it.
//
// The force variant is tried second: it is the one that works when the cap is the
// only thing in the way and this end is allowed to override it.
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

// ReadPackets reads one datagram, or one run of them when GRO merged them.
func (c *batchedConn) ReadPackets(buffers [][]byte) ([]Packet, error) {
	if len(buffers) == 0 {
		return nil, nil
	}
	buffer := buffers[0]
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
		return nil, waitErr
	}
	if recvErr != nil {
		return nil, os.NewSyscallError("recvmsg", recvErr)
	}
	c.one[0] = receivedPacket(buffer[:received], c.oob[:oobLen], from)
	return c.one[:], nil
}

// receivedPacket turns one read into a packet, splitting it when the kernel says
// it merged several datagrams into it.
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

// WritePackets sends the packets in order, as one call where it can.
func (c *batchedConn) WritePackets(packets []Packet) error {
	if len(packets) == 0 {
		return nil
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
				return err
			}
			// The interface or its driver cannot segment, however much the
			// kernel says otherwise. Everything from here on leaves one
			// datagram per call rather than failing for good.
			c.gso = false
		}
		err := c.send(packets[start].Data, packets[start].Addr, 0)
		if err != nil {
			return err
		}
		start++
	}
	return nil
}

// segmentCount is how many packets starting at start can leave as one datagram
// with a segment size. GSO requires every segment but the last to be the same
// length, so a run ends at the first packet that is longer than the first one or
// at the first shorter one, that one being allowed as the tail.
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

// writeSegments copies the run into one buffer and asks the kernel to cut it.
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

// send is one sendmsg, optionally segmented. The call is made through the
// runtime poller, so a full send buffer waits instead of failing the send.
func (c *batchedConn) send(data []byte, addr net.Addr, segmentSize int) error {
	udpAddr, isUDPAddr := addr.(*net.UDPAddr)
	if !isUDPAddr {
		return &net.OpError{Op: "write", Net: "udp", Addr: addr, Err: errors.New("unsupported address type")}
	}
	sockaddr, err := sockaddrOf(udpAddr)
	if err != nil {
		return err
	}
	oob := c.oob[:0]
	if segmentSize > 0 && len(data) > segmentSize {
		oob = appendSegmentSize(oob, uint16(segmentSize))
	}
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

// addrOf is the source address of a receive.
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

// segmentSizeOf finds the segment size a merged read reports.
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

// appendSegmentSize asks the kernel to cut the send into datagrams of size.
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

// isGSOError reports whether a send failed because the path cannot segment.
// EIO means the driver has not enabled the checksums UDP_SEGMENT requires, and
// EINVAL means this particular size or socket cannot be segmented at all.
func isGSOError(err error) bool {
	var syscallErr *os.SyscallError
	if errors.As(err, &syscallErr) {
		return syscallErr.Err == unix.EIO || syscallErr.Err == unix.EINVAL
	}
	return false
}
