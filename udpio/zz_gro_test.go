package udpio

import (
	"net"
	"testing"
	"time"
)

func TestProbeGRO(t *testing.T) {
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	receiverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer receiverConn.Close()
	senderConn, err := net.DialUDP("udp", nil, receiverConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer senderConn.Close()
	receiver := New(receiverConn, Options{GRO: true})
	sender := New(senderConn, Options{})
	senderGSO, senderGRO := sender.Offload()
	receiverGSO, receiverGRO := receiver.Offload()
	t.Logf("offload: sender gso=%v gro=%v, receiver gso=%v gro=%v", senderGSO, senderGRO, receiverGSO, receiverGRO)

	payload := make([]byte, 1200)
	packets := make([]Packet, 16)
	for index := range packets {
		packets[index] = Packet{Data: payload, Addr: receiverConn.LocalAddr()}
	}
	received := 0
	merged := 0
	reads := 0
	deadline := time.Now().Add(2 * time.Second)
	buffers := make([][]byte, 1)
	buffers[0] = make([]byte, 65536)
	for received < len(packets) && time.Now().Before(deadline) {
		if err = receiverConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if received == 0 {
			if err = sender.WritePackets(packets); err != nil {
				t.Fatal(err)
			}
		}
		read, readErr := receiver.ReadPackets(buffers)
		if readErr != nil {
			if netError, ok := readErr.(net.Error); ok && netError.Timeout() {
				if received == 0 {
					continue
				}
				break
			}
			t.Fatal(readErr)
		}
		for _, packet := range read {
			reads++
			if packet.Segments > 1 {
				merged++
			}
			received += max(packet.Segments, 1)
		}
	}
	t.Logf("reads=%d merged=%d packets=%d", reads, merged, received)
}
