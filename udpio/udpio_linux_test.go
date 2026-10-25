//go:build linux

package udpio

import (
	"bytes"
	"encoding/binary"
	"net"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// appendGROSize builds the control message a merged read carries. The value is
// an int, unlike the uint16 UDP_SEGMENT takes on the way out.
func appendGROSize(oob []byte, size int) []byte {
	start := len(oob)
	const dataLen = 4
	oob = append(oob, make([]byte, unix.CmsgSpace(dataLen))...)
	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[start]))
	header.Level = unix.IPPROTO_UDP
	header.Type = udpGRO
	header.SetLen(unix.CmsgLen(dataLen))
	*(*int32)(unsafe.Pointer(&oob[start+unix.CmsgSpace(0)])) = int32(size)
	return oob
}

func TestSegmentSizeMessage(t *testing.T) {
	size, ok := segmentSizeOf(appendGROSize(nil, 1400))
	if !ok {
		t.Fatal("the segment size did not survive the control message")
	}
	if size != 1400 {
		t.Fatalf("segment size is %d, want 1400", size)
	}
	oob := appendGROSize(nil, 1400)
	if size, ok := segmentSizeOf(oob[:unix.CmsgLen(4)-1]); ok {
		t.Fatalf("a truncated control message reported %d", size)
	}
	if size, ok := segmentSizeOf(appendSegmentSize(nil, 1400)); ok {
		t.Fatalf("a segment size request was read as a report of %d", size)
	}
	if _, ok := segmentSizeOf(nil); ok {
		t.Fatal("an empty control message reported a segment size")
	}
}

// TestMergedRead checks what the receive path makes of a read the kernel merged.
// The loopback device has no GRO feature to turn on, so a socket test could not
// produce one here.
func TestMergedRead(t *testing.T) {
	from := &unix.SockaddrInet4{Port: 5000}
	data := make([]byte, 0, 3*1400+40)
	for index := range 3 {
		for range 1400 {
			data = append(data, byte(index))
		}
	}
	for range 40 {
		data = append(data, 9)
	}
	packet := receivedPacket(data, appendGROSize(nil, 1400), from)
	if packet.Segments != 4 {
		t.Fatalf("read holds %d datagrams, want 4", packet.Segments)
	}
	if packet.SegmentSize != 1400 {
		t.Fatalf("segment size is %d, want 1400", packet.SegmentSize)
	}
	var lengths []int
	packet.ForEach(func(datagram []byte) { lengths = append(lengths, len(datagram)) })
	want := []int{1400, 1400, 1400, 40}
	if len(lengths) != len(want) {
		t.Fatalf("got %d datagrams %v, want %v", len(lengths), lengths, want)
	}
	for index := range lengths {
		if lengths[index] != want[index] {
			t.Fatalf("datagram %d is %d bytes, want %d", index, lengths[index], want[index])
		}
	}
	if alone := receivedPacket(data[:1400], nil, from); alone.Segments != 1 {
		t.Fatalf("a single datagram reports %d segments", alone.Segments)
	}
}

func TestSegmentCount(t *testing.T) {
	first := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000}
	second := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2000}
	for _, testCase := range []struct {
		name    string
		gso     bool
		packets []Packet
		start   int
		want    int
	}{
		{
			name: "run of equal packets",
			gso:  true,
			packets: []Packet{
				{Data: make([]byte, 100), Addr: first},
				{Data: make([]byte, 100), Addr: first},
				{Data: make([]byte, 100), Addr: first},
			},
			want: 3,
		},
		{
			name: "shorter packet ends the run",
			gso:  true,
			packets: []Packet{
				{Data: make([]byte, 100), Addr: first},
				{Data: make([]byte, 100), Addr: first},
				{Data: make([]byte, 40), Addr: first},
				{Data: make([]byte, 100), Addr: first},
			},
			want: 3,
		},
		{
			name: "longer packet is not a tail",
			gso:  true,
			packets: []Packet{
				{Data: make([]byte, 100), Addr: first},
				{Data: make([]byte, 120), Addr: first},
			},
			want: 1,
		},
		{
			name: "another address ends the run",
			gso:  true,
			packets: []Packet{
				{Data: make([]byte, 100), Addr: first},
				{Data: make([]byte, 100), Addr: first},
				{Data: make([]byte, 100), Addr: second},
			},
			want: 2,
		},
		{
			name: "without gso nothing is merged",
			gso:  false,
			packets: []Packet{
				{Data: make([]byte, 100), Addr: first},
				{Data: make([]byte, 100), Addr: first},
			},
			want: 1,
		},
		{
			name: "a single packet stays a single packet",
			gso:  true,
			packets: []Packet{
				{Data: make([]byte, 100), Addr: first},
			},
			want: 1,
		},
		{
			name: "empty packet is never merged",
			gso:  true,
			packets: []Packet{
				{Data: nil, Addr: first},
				{Data: nil, Addr: first},
			},
			want: 1,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			conn := &batchedConn{gso: testCase.gso}
			if got := conn.segmentCount(testCase.packets, testCase.start); got != testCase.want {
				t.Fatalf("got %d packets in one send, want %d", got, testCase.want)
			}
		})
	}
}

// TestMmsghdrLayout checks the one thing a hand-written structure can get wrong:
// the kernel writes the length right after the msghdr, so the field has to be
// exactly there.
func TestMmsghdrLayout(t *testing.T) {
	var message mmsghdr
	if offset := unsafe.Offsetof(message.sent); offset != syscall.SizeofMsghdr {
		t.Fatalf("the length field is %d bytes in, want %d", offset, syscall.SizeofMsghdr)
	}
}

func TestSendmmsgCount(t *testing.T) {
	first := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000}
	second := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2000}
	increasing := make([]Packet, 0, maxSendmmsg+3)
	for index := range maxSendmmsg + 3 {
		increasing = append(increasing, Packet{Data: make([]byte, 100+index), Addr: first})
	}
	for _, testCase := range []struct {
		name    string
		gso     bool
		many    bool
		packets []Packet
		want    int
	}{
		{
			name: "a run that cannot be segmented",
			gso:  true,
			many: true,
			packets: []Packet{
				{Data: make([]byte, 100), Addr: first},
				{Data: make([]byte, 120), Addr: first},
				{Data: make([]byte, 140), Addr: first},
			},
			want: 3,
		},
		{
			name: "another address is part of the same call",
			gso:  true,
			many: true,
			packets: []Packet{
				{Data: make([]byte, 100), Addr: first},
				{Data: make([]byte, 120), Addr: second},
			},
			want: 2,
		},
		{
			name: "a segmentable run ends the call",
			gso:  true,
			many: true,
			packets: []Packet{
				{Data: make([]byte, 100), Addr: first},
				{Data: make([]byte, 200), Addr: first},
				{Data: make([]byte, 200), Addr: first},
			},
			want: 1,
		},
		{
			name: "empty packets are not segmentable either",
			gso:  true,
			many: true,
			packets: []Packet{
				{Data: nil, Addr: first},
				{Data: nil, Addr: first},
			},
			want: 2,
		},
		{
			name: "without gso everything goes together",
			gso:  false,
			many: true,
			packets: []Packet{
				{Data: make([]byte, 100), Addr: first},
				{Data: make([]byte, 100), Addr: first},
				{Data: make([]byte, 100), Addr: first},
			},
			want: 3,
		},
		{
			name:    "without sendmmsg nothing is merged",
			gso:     true,
			many:    false,
			packets: increasing,
			want:    1,
		},
		{
			name:    "one call takes at most maxSendmmsg packets",
			gso:     true,
			many:    true,
			packets: increasing,
			want:    maxSendmmsg,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			conn := &batchedConn{gso: testCase.gso, many: testCase.many}
			if got := conn.sendmmsgCount(testCase.packets, 0); got != testCase.want {
				t.Fatalf("got %d packets in one call, want %d", got, testCase.want)
			}
		})
	}
}

// TestUnequalSend sends batches a segmented send cannot take as they are and
// checks that every packet still arrives as its own datagram, in order. The first
// batch is what a real one looks like: runs of equal packets with packets of other
// sizes in between. The second one is only increasing, so no pair of it can share
// a segment size and the whole batch is one sendmmsg.
func TestUnequalSend(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		sizes []int
	}{
		{name: "runs and singles", sizes: []int{60, 100, 140, 180, 1400, 1400, 200, 0, 1200, 900}},
		{name: "only increasing", sizes: []int{200, 400, 600, 800, 1000, 1400}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			sender := listenPacket(t)
			receiver := listenPacket(t)
			senderConn := New(sender, Options{})
			receiverAddr, isUDPAddr := receiver.LocalAddr().(*net.UDPAddr)
			if !isUDPAddr {
				t.Fatalf("local address is %T", receiver.LocalAddr())
			}
			payloads := makePayloadsOfSizes(testCase.sizes)
			packets := make([]Packet, 0, len(payloads))
			for _, payload := range payloads {
				packets = append(packets, Packet{Data: payload, Addr: receiverAddr})
			}
			if err := senderConn.WritePackets(packets); err != nil {
				t.Fatalf("write: %v", err)
			}
			if err := receiver.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatalf("set deadline: %v", err)
			}
			buffer := make([]byte, 2048)
			for index, payload := range payloads {
				read, addr, err := receiver.ReadFrom(buffer)
				if err != nil {
					t.Fatalf("read datagram %d: %v", index, err)
				}
				if addr.String() != sender.LocalAddr().String() {
					t.Fatalf("datagram %d came from %s", index, addr)
				}
				if read != len(payload) {
					t.Fatalf("datagram %d is %d bytes, want %d", index, read, len(payload))
				}
				if !bytes.Equal(buffer[:read], payload) {
					t.Fatalf("datagram %d does not match what was sent", index)
				}
			}
		})
	}
}

// makePayloadsOfSizes fills each payload with its own index, so a reordered or
// merged datagram shows in the comparison.
func makePayloadsOfSizes(sizes []int) [][]byte {
	payloads := make([][]byte, 0, len(sizes))
	for index, size := range sizes {
		payload := make([]byte, size)
		for position := range payload {
			payload[position] = byte(index)
		}
		payloads = append(payloads, payload)
	}
	return payloads
}

// TestWriteSockaddr checks the bytes a batch points at: the layout the kernel
// parses, not the Go structure x/sys keeps behind an int port.
func TestWriteSockaddr(t *testing.T) {
	buffer := make([]byte, sizeofInet6Sockaddr)
	length, err := writeSockaddr(buffer, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000})
	if err != nil {
		t.Fatalf("write sockaddr: %v", err)
	}
	if length != sizeofInet4Sockaddr {
		t.Fatalf("an IPv4 address is %d bytes, want %d", length, sizeofInet4Sockaddr)
	}
	if family := binary.NativeEndian.Uint16(buffer[0:]); family != unix.AF_INET {
		t.Fatalf("family is %d, want %d", family, unix.AF_INET)
	}
	if port := binary.BigEndian.Uint16(buffer[2:]); port != 5000 {
		t.Fatalf("port is %d, want 5000", port)
	}
	if address := net.IP(buffer[4:8]); !address.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("address is %s", address)
	}
	length, err = writeSockaddr(buffer, &net.UDPAddr{IP: net.ParseIP("::1"), Port: 5001})
	if err != nil {
		t.Fatalf("write sockaddr: %v", err)
	}
	if length != sizeofInet6Sockaddr {
		t.Fatalf("an IPv6 address is %d bytes, want %d", length, sizeofInet6Sockaddr)
	}
	if family := binary.NativeEndian.Uint16(buffer[0:]); family != unix.AF_INET6 {
		t.Fatalf("family is %d, want %d", family, unix.AF_INET6)
	}
	if port := binary.BigEndian.Uint16(buffer[2:]); port != 5001 {
		t.Fatalf("port is %d, want 5001", port)
	}
	if address := net.IP(buffer[8:24]); !address.Equal(net.ParseIP("::1")) {
		t.Fatalf("address is %s", address)
	}
	if _, err := writeSockaddr(buffer, nil); err == nil {
		t.Fatal("an address that is not an IP address was written")
	}
}

// TestBatchToSeveralAddresses sends one batch to two sockets: a batch does not
// have to share a destination, and every header carries its own address.
func TestBatchToSeveralAddresses(t *testing.T) {
	first := listenPacket(t)
	second := listenPacket(t)
	sender := listenPacket(t)
	senderConn := New(sender, Options{})
	payloads := makePayloadsOfSizes([]int{300, 400, 500, 600})
	packets := []Packet{
		{Data: payloads[0], Addr: first.LocalAddr()},
		{Data: payloads[1], Addr: second.LocalAddr()},
		{Data: payloads[2], Addr: first.LocalAddr()},
		{Data: payloads[3], Addr: second.LocalAddr()},
	}
	if err := senderConn.WritePackets(packets); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, testCase := range []struct {
		name     string
		receiver net.PacketConn
		want     [][]byte
	}{
		{name: "first", receiver: first, want: [][]byte{payloads[0], payloads[2]}},
		{name: "second", receiver: second, want: [][]byte{payloads[1], payloads[3]}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if err := testCase.receiver.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatalf("set deadline: %v", err)
			}
			buffer := make([]byte, 2048)
			for index, want := range testCase.want {
				read, _, err := testCase.receiver.ReadFrom(buffer)
				if err != nil {
					t.Fatalf("read datagram %d: %v", index, err)
				}
				if !bytes.Equal(buffer[:read], want) {
					t.Fatalf("datagram %d is %d bytes, want %d", index, read, len(want))
				}
			}
		})
	}
}

// TestSendmmsgMissingKernel covers the other way a batched send can be
// unavailable: a kernel without the system call. What such a socket must not do is
// fail — it leaves one datagram per call, like every other fallback here.
func TestSendmmsgMissingKernel(t *testing.T) {
	receiver := listenPacket(t)
	sender := listenPacket(t)
	senderConn := New(sender, Options{})
	batched, isBatched := senderConn.(*batchedConn)
	if !isBatched {
		t.Skip("this socket has no batched path")
	}
	batched.mmsgCall = func(int, []mmsghdr) (int, error) { return 0, unix.ENOSYS }
	receiverAddr, isUDPAddr := receiver.LocalAddr().(*net.UDPAddr)
	if !isUDPAddr {
		t.Fatalf("local address is %T", receiver.LocalAddr())
	}
	payloads := makePayloadsOfSizes([]int{200, 400, 600, 800})
	packets := make([]Packet, 0, len(payloads))
	for _, payload := range payloads {
		packets = append(packets, Packet{Data: payload, Addr: receiverAddr})
	}
	if err := senderConn.WritePackets(packets); err != nil {
		t.Fatalf("write: %v", err)
	}
	if batched.many {
		t.Fatal("sendmmsg is still expected after it reported there is none")
	}
	if err := receiver.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buffer := make([]byte, 2048)
	for index, want := range payloads {
		read, _, err := receiver.ReadFrom(buffer)
		if err != nil {
			t.Fatalf("read datagram %d: %v", index, err)
		}
		if !bytes.Equal(buffer[:read], want) {
			t.Fatalf("datagram %d is %d bytes, want %d", index, read, len(want))
		}
	}
}

// TestSegmentedSend checks that a run of equal packets arrives as that many
// datagrams, which is the whole promise of GSO: one call, unchanged wire format.
func TestSegmentedSend(t *testing.T) {
	sender := listenPacket(t)
	receiver := listenPacket(t)
	senderConn := New(sender, Options{})
	if gso, _ := senderConn.Offload(); !gso {
		t.Skip("this kernel does not offer UDP_SEGMENT")
	}
	receiverAddr, isUDPAddr := receiver.LocalAddr().(*net.UDPAddr)
	if !isUDPAddr {
		t.Fatalf("local address is %T", receiver.LocalAddr())
	}
	payloads := makePayloads()
	packets := make([]Packet, 0, len(payloads))
	for _, payload := range payloads {
		packets = append(packets, Packet{Data: payload, Addr: receiverAddr})
	}
	if err := senderConn.WritePackets(packets); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buffer := make([]byte, 2048)
	for index, payload := range payloads {
		read, addr, err := receiver.ReadFrom(buffer)
		if err != nil {
			t.Fatalf("read datagram %d: %v", index, err)
		}
		if addr.String() != sender.LocalAddr().String() {
			t.Fatalf("datagram %d came from %s", index, addr)
		}
		if read != len(payload) {
			t.Fatalf("datagram %d is %d bytes, want %d", index, read, len(payload))
		}
		if !bytes.Equal(buffer[:read], payload) {
			t.Fatalf("datagram %d does not match what was sent", index)
		}
	}
}

// socketBuffer reads one buffer size off the socket.
func socketBuffer(t *testing.T, conn net.PacketConn, option int) int {
	t.Helper()
	syscallConn, isSyscallConn := conn.(syscall.Conn)
	if !isSyscallConn {
		t.Fatal("socket has no file descriptor")
	}
	raw, err := syscallConn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var size int
	var getErr error
	if err = raw.Control(func(fd uintptr) {
		size, getErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, option)
	}); err != nil {
		t.Fatal(err)
	}
	if getErr != nil {
		t.Fatal(getErr)
	}
	return size
}

// TestSocketBuffers requires the socket to be asked for buffers this protocol can
// use, and requires the ask not to make them smaller. A host that caps its
// buffers keeps the cap, which is why the test only reports what it got.
func TestSocketBuffers(t *testing.T) {
	conn := listenPacket(t)
	before := socketBuffer(t, conn, unix.SO_RCVBUF)
	if New(conn, Options{}) == nil {
		t.Skip("this kernel offers no batched path")
	}
	after := socketBuffer(t, conn, unix.SO_RCVBUF)
	if after < before {
		t.Fatalf("receive buffer shrank from %d to %d", before, after)
	}
	t.Logf("receive buffer %d -> %d (asked for %d)", before, after, desiredReceiveBuffer)
	if after < desiredReceiveBuffer {
		t.Logf("the host capped the buffer, so only %d bytes are usable", after)
	}
}
