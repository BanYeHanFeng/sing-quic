//go:build linux

package udpio

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
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

	// maxSendmmsg is how many datagrams one sendmmsg takes at once. The kernel
	// allows up to UIO_MAXIOV (1024) of them; a batch is a handful, so the cap is
	// only here to keep the preparation and the syscall entry bounded.
	maxSendmmsg = 64

	// desiredReceiveBuffer and desiredSendBuffer are what this package asks the
	// socket for. The receive side matches the association window the transport
	// advertises: a buffer below it turns the window into a number the peer obeys
	// and the kernel then throws away. The send side is smaller because a send
	// buffer only has to hold one batch of paced packets.
	desiredReceiveBuffer = 8 * 1024 * 1024
	desiredSendBuffer    = 1 * 1024 * 1024
)

// batchedConn is the Linux fast path: one sendmsg for a run of equal datagrams,
// one sendmmsg for a run of unequal ones, one recvmsg that may hold a run of
// them.
type batchedConn struct {
	net.PacketConn
	raw  syscall.RawConn
	gso  bool
	gro  bool
	many bool

	// writeMu serializes senders: a listener's socket is shared by every
	// association under it, and each of them calls WritePackets whenever it has
	// something to say. The send state below lives across the poller callback,
	// so two senders must not take turns in the middle of one.
	writeMu  sync.Mutex
	coalesce []byte
	// cmsg is where a send builds its control messages and oob is where a
	// receive puts the ones the kernel sent. They are separate buffers because a
	// send and a receive happen at the same time, and the two used to share one:
	// a segmented send built its segment size in the buffer a read was filling.
	cmsg []byte
	oob  [oobSize]byte

	sendBuf  []byte
	sendOOB  []byte
	sendAddr unix.Sockaddr
	sendN    int
	sendErr  error
	writeFn  func(fd uintptr) bool

	// The sendmmsg state: the headers of the run being sent, the addresses and
	// buffers their bare pointers refer to, and the index of the first message the
	// kernel has not taken yet. The addresses and the buffers are held here
	// because a header only carries an unsafe pointer to them, which the garbage
	// collector does not follow.
	messages []mmsghdr
	iovs     []unix.Iovec
	names    []byte
	next     int
	mmsgErr  error
	mmsgFn   func(fd uintptr) bool
	mmsgCall func(fd int, messages []mmsghdr) (int, error)

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
	c := &batchedConn{PacketConn: conn, raw: raw, many: true}
	c.writeFn = c.write
	c.mmsgFn = c.sendMessages
	c.mmsgCall = sendmmsg
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
	if err != nil {
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

// WritePackets sends the packets in order, in as few calls as it can: one
// sendmsg for a run of equal datagrams, one sendmmsg for a run of datagrams that
// are not equal enough to segment.
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
		count = c.sendmmsgCount(packets, start)
		if err := c.sendMany(packets[start : start+count]); err != nil {
			return err
		}
		start += count
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

// sendmmsgCount is how many packets starting at start leave in one sendmmsg: the
// run of packets that cannot be segmented, capped at maxSendmmsg. A single
// packet is a run of one, which is what a kernel without sendmmsg always gets.
func (c *batchedConn) sendmmsgCount(packets []Packet, start int) int {
	if !c.many || start >= len(packets) {
		return 1
	}
	end := start + 1
	for end < len(packets) && end-start < maxSendmmsg && c.segmentCount(packets, end) == 1 {
		end++
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

// sendMany sends several datagrams in one sendmmsg. What ends up here is what a
// batch is made uneven by — an ACK-only packet, a shorter tail, a parity packet of
// another size — and each of those used to cost a call of its own. A single
// packet is one sendmsg, which is also the way out for a kernel that has no
// sendmmsg at all.
func (c *batchedConn) sendMany(packets []Packet) error {
	if len(packets) == 1 {
		return c.send(packets[0].Data, packets[0].Addr, 0)
	}
	if cap(c.messages) < len(packets) {
		c.messages = make([]mmsghdr, len(packets))
		c.iovs = make([]unix.Iovec, len(packets))
	}
	c.messages = c.messages[:len(packets)]
	c.iovs = c.iovs[:len(packets)]
	need := len(packets) * sizeofInet6Sockaddr
	if cap(c.names) < need {
		c.names = make([]byte, need)
	}
	names := c.names[:need]
	for index, packet := range packets {
		start := index * sizeofInet6Sockaddr
		nameLen, err := writeSockaddr(names[start:], packet.Addr)
		if err != nil {
			c.messages, c.iovs = c.messages[:0], c.iovs[:0]
			return err
		}
		c.iovs[index] = unix.Iovec{Base: unsafe.SliceData(packet.Data)}
		c.iovs[index].SetLen(len(packet.Data))
		c.messages[index] = mmsghdr{header: unix.Msghdr{
			Name:    &names[start],
			Namelen: uint32(nameLen),
			Iov:     &c.iovs[index],
			Iovlen:  1,
		}}
	}
	c.next, c.mmsgErr = 0, nil
	waitErr := c.raw.Write(c.mmsgFn)
	sent, mmsgErr := c.next, c.mmsgErr
	c.messages, c.iovs = c.messages[:0], c.iovs[:0]
	c.next, c.mmsgErr = 0, nil
	// The headers hold unsafe pointers into the buffers, so the buffers have to
	// outlive the call whether or not anything reads them again.
	runtime.KeepAlive(packets)
	if waitErr != nil {
		return waitErr
	}
	if mmsgErr != nil {
		if sent == 0 && mmsgErr == unix.ENOSYS {
			// A kernel older than 3.0. Everything from here on leaves one
			// datagram per call rather than failing for good.
			c.many = false
			return c.sendManyEach(packets)
		}
		return os.NewSyscallError("sendmmsg", mmsgErr)
	}
	if sent != len(packets) {
		return io.ErrShortWrite
	}
	return nil
}

// sendMessages is the poller callback of a sendmmsg run. The kernel takes as many
// datagrams as the send buffer holds and reports how many that were, so a partial
// send is normal and the rest stays at the front of the list; EAGAIN means this
// call took none, and the runtime then waits for room.
func (c *batchedConn) sendMessages(fd uintptr) bool {
	for c.next < len(c.messages) {
		sent, err := c.mmsgCall(int(fd), c.messages[c.next:])
		if err == nil {
			c.next += sent
			continue
		}
		if err == unix.EAGAIN {
			return false
		}
		c.mmsgErr = err
		return true
	}
	return true
}

// sendManyEach is sendMany without sendmmsg, for a kernel that does not have it.
func (c *batchedConn) sendManyEach(packets []Packet) error {
	for _, packet := range packets {
		if err := c.send(packet.Data, packet.Addr, 0); err != nil {
			return err
		}
	}
	return nil
}

// send is one sendmsg, optionally segmented. The call is made through the
// runtime poller, so a full send buffer waits instead of failing the send.
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

// addrSockaddrOf is sockaddrOf for an address that came from a caller: an
// address this package cannot send to is an error of the write, not of the
// package.
func addrSockaddrOf(addr net.Addr) (unix.Sockaddr, error) {
	udpAddr, isUDPAddr := addr.(*net.UDPAddr)
	if !isUDPAddr {
		return nil, &net.OpError{Op: "write", Net: "udp", Addr: addr, Err: errors.New("unsupported address type")}
	}
	return sockaddrOf(udpAddr)
}

// The lengths of the two address structures a batch can point at.
const (
	sizeofInet4Sockaddr = 16
	sizeofInet6Sockaddr = 28
)

// writeSockaddr writes the address into buffer as the kernel reads it and reports
// how many bytes that took: sockaddr_in or sockaddr_in6, family in host byte
// order, port in network byte order. The bytes are put together here because a
// msghdr carries a bare pointer to them, and what x/sys calls a Sockaddr keeps the
// kernel's structure in an unexported field behind a Go int port — the pointer a
// sendmmsg header takes has to point at the structure itself.
func writeSockaddr(buffer []byte, addr net.Addr) (int, error) {
	udpAddr, isUDPAddr := addr.(*net.UDPAddr)
	if !isUDPAddr {
		return 0, &net.OpError{Op: "write", Net: "udp", Addr: addr, Err: errors.New("unsupported address type")}
	}
	if ip := udpAddr.IP.To4(); ip != nil {
		binary.NativeEndian.PutUint16(buffer[0:], unix.AF_INET)
		binary.BigEndian.PutUint16(buffer[2:], uint16(udpAddr.Port))
		copy(buffer[4:8], ip)
		clear(buffer[8:sizeofInet4Sockaddr])
		return sizeofInet4Sockaddr, nil
	}
	ip := udpAddr.IP.To16()
	if ip == nil {
		return 0, errors.New("udpio: " + udpAddr.String() + " is not an IP address")
	}
	binary.NativeEndian.PutUint16(buffer[0:], unix.AF_INET6)
	binary.BigEndian.PutUint16(buffer[2:], uint16(udpAddr.Port))
	copy(buffer[8:24], ip)
	clear(buffer[4:8])
	clear(buffer[24:sizeofInet6Sockaddr])
	return sizeofInet6Sockaddr, nil
}

// mmsghdr is struct mmsghdr from linux/socket.h: one msghdr plus the number of
// bytes the kernel moved for it. The syscall package has no sendmmsg and x/sys
// does not declare the structure for Linux, so the two fields are spelled out
// here; the layout is a msghdr followed by a uint32, and the alignment of the
// msghdr supplies the padding the kernel's own union has.
type mmsghdr struct {
	header unix.Msghdr
	sent   uint32
}

// sendmmsg is one sendmmsg system call over the given headers. It returns how
// many datagrams the kernel took, which may be fewer than offered when the send
// buffer filled up part way, and only fails when it took none.
func sendmmsg(fd int, messages []mmsghdr) (int, error) {
	if len(messages) == 0 {
		return 0, nil
	}
	for {
		sent, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(fd), uintptr(unsafe.Pointer(&messages[0])), uintptr(len(messages)), 0, 0, 0)
		if errno == unix.EINTR {
			continue
		}
		if errno != 0 {
			return int(sent), errno
		}
		return int(sent), nil
	}
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
