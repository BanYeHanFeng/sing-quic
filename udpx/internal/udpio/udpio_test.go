package udpio

import (
	"bytes"
	"net"
	"os"
	"testing"
	"time"
)

type wrapper struct {
	net.PacketConn
}

type failingPacketConn struct {
	net.PacketConn
	failAfter int
	written   int
}

func (c *failingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.written >= c.failAfter {
		return 0, os.ErrInvalid
	}
	c.written++
	return c.PacketConn.WriteTo(p, addr)
}

func listenPacket(t *testing.T) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestPacketForEach(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		packet Packet
		want   []string
	}{
		{
			name:   "single",
			packet: Packet{Data: []byte("abcdef"), Segments: 1},
			want:   []string{"abcdef"},
		},
		{
			name:   "unset segment count",
			packet: Packet{Data: []byte("abcdef")},
			want:   []string{"abcdef"},
		},
		{
			name:   "merged",
			packet: Packet{Data: []byte("abcdefghij"), Segments: 3, SegmentSize: 4},
			want:   []string{"abcd", "efgh", "ij"},
		},
		{
			name:   "merged exact",
			packet: Packet{Data: []byte("abcdefgh"), Segments: 2, SegmentSize: 4},
			want:   []string{"abcd", "efgh"},
		},
		{
			name:   "segment size without count",
			packet: Packet{Data: []byte("abcdef"), SegmentSize: 4},
			want:   []string{"abcdef"},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var got []string
			testCase.packet.ForEach(func(datagram []byte) {
				got = append(got, string(datagram))
			})
			if len(got) != len(testCase.want) {
				t.Fatalf("got %d datagrams %q, want %d", len(got), got, len(testCase.want))
			}
			for index := range got {
				if got[index] != testCase.want[index] {
					t.Fatalf("datagram %d is %q, want %q", index, got[index], testCase.want[index])
				}
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	payloads := makePayloads()
	for _, testCase := range []struct {
		name     string
		sendPath string
	}{
		{name: "plain sender", sendPath: "plain"},
		{name: "batched sender", sendPath: "batched"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			receiver := listenPacket(t)
			sender := listenPacket(t)
			var senderConn Conn
			if testCase.sendPath == "batched" {
				senderConn = New(sender)
			} else {
				senderConn = New(&wrapper{PacketConn: sender})
			}
			receiverConn := New(receiver)
			receiverAddr, isUDPAddr := receiver.LocalAddr().(*net.UDPAddr)
			if !isUDPAddr {
				t.Fatalf("local address is %T", receiver.LocalAddr())
			}
			packets := make([]Packet, 0, len(payloads))
			for _, payload := range payloads {
				packets = append(packets, Packet{Data: payload, Addr: receiverAddr})
			}
			if _, err := senderConn.WritePackets(packets); err != nil {
				t.Fatalf("write: %v", err)
			}
			if err := receiver.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatalf("set deadline: %v", err)
			}
			buffer := make([]byte, 65536)
			received := 0
			merged := 0
			for received < len(payloads) {
				packet, err := receiverConn.ReadPacket(buffer)
				if err != nil {
					t.Fatalf("read after %d payloads: %v", received, err)
				}
				if packet.Segments > 1 {
					merged++
				}
				packet.ForEach(func(datagram []byte) {
					if received >= len(payloads) {
						t.Errorf("received more than the %d payloads sent", len(payloads))
						return
					}
					if !bytes.Equal(datagram, payloads[received]) {
						t.Errorf("payload %d is %d bytes, want %d", received, len(datagram), len(payloads[received]))
					}
					received++
				})
			}
			if merged == 0 {
				t.Log("the kernel did not merge any reads, so GRO was not exercised")
			}
		})
	}
}

func TestWriteRejectsUnknownAddress(t *testing.T) {
	conn := New(&wrapper{PacketConn: listenPacket(t)})
	_, err := conn.WritePackets([]Packet{{Data: []byte("x"), Addr: nil}})
	if err == nil {
		t.Fatal("a packet without an address was written")
	}
}

func TestWritePacketsReportsWrittenPrefix(t *testing.T) {
	receiver := listenPacket(t)
	sender := &failingPacketConn{PacketConn: listenPacket(t), failAfter: 2}
	conn := New(sender)
	packets := make([]Packet, 0, 4)
	for range 4 {
		packets = append(packets, Packet{Data: []byte("payload"), Addr: receiver.LocalAddr()})
	}
	written, err := conn.WritePackets(packets)
	if err == nil {
		t.Fatal("write did not fail")
	}
	if written != 2 {
		t.Fatalf("written %d, want the two packets before the failure", written)
	}
}

func TestOffload(t *testing.T) {
	batched := New(listenPacket(t))
	gso, gro := batched.Offload()
	if !gso || !gro {
		t.Skipf("this kernel offers gso=%v gro=%v", gso, gro)
	}
	if gso, gro := New(&wrapper{PacketConn: listenPacket(t)}).Offload(); gso || gro {
		t.Fatalf("a socket without a file descriptor reported gso=%v gro=%v", gso, gro)
	}
}

func makePayloads() [][]byte {
	payloads := make([][]byte, 0, 7)
	for index := range 6 {
		payload := make([]byte, 1400)
		for position := range payload {
			payload[position] = byte(index)
		}
		payloads = append(payloads, payload)
	}
	payloads = append(payloads, make([]byte, 60))
	return payloads
}
