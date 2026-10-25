//go:build linux

package udpio

import (
	"bytes"
	"net"
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
