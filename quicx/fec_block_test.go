package quicx

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

type fecTestFrame struct {
	blockID uint16
	frame   fecFrame
}

type fecTestSink struct {
	access sync.Mutex
	frames []fecTestFrame
}

func (s *fecTestSink) emit(blockID uint16, frame fecFrame) error {
	stored := fecFrame{shardIndex: frame.shardIndex, k: frame.k, m: frame.m}
	stored.payload = copyFECPayload(frame.payload)
	s.access.Lock()
	s.frames = append(s.frames, fecTestFrame{blockID: blockID, frame: stored})
	s.access.Unlock()
	return nil
}

func (s *fecTestSink) snapshot() []fecTestFrame {
	s.access.Lock()
	defer s.access.Unlock()
	frames := make([]fecTestFrame, len(s.frames))
	copy(frames, s.frames)
	return frames
}

func fecTestConfig(blockSize, parity, interleave int) fecConfig {
	return FECOptions{
		Enabled:      true,
		Block:        true,
		BlockSize:    blockSize,
		Parity:       parity,
		MaxParity:    4,
		Interleave:   interleave,
		BlockTimeout: 5 * time.Millisecond,
	}.build()
}

func fecTestMessage(index, size int) *udpMessage {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(index*31 + i*7 + 1)
	}
	return &udpMessage{
		sessionID:     3,
		packetID:      uint16(index),
		fragmentTotal: 1,
		destination:   M.SocksaddrFrom(netip.MustParseAddr("10.0.0.1"), uint16(1000+index)),
		data:          data,
	}
}

func fecTestEncode(t *testing.T, encoder *fecBlockEncoder, sink *fecTestSink, message *udpMessage) {
	t.Helper()
	body := make([]byte, message.bodySize())
	message.writeBody(body)
	if err := encoder.write(body, sink.emit); err != nil {
		t.Fatal(err)
	}
}

func fecTestDecode(t *testing.T, decoder *fecBlockDecoder, item fecTestFrame, delivered *[]*udpMessage) {
	t.Helper()
	err := decoder.input(item.blockID, item.frame.shardIndex, item.frame.k, item.frame.m, item.frame.payload, func(body []byte) error {
		message := allocMessage()
		if err := decodeUDPMessage(message, body, nil); err != nil {
			message.releaseMessage()
			return err
		}
		*delivered = append(*delivered, message)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func fecTestAssert(t *testing.T, messages []*udpMessage, delivered []*udpMessage) {
	t.Helper()
	if len(delivered) != len(messages) {
		t.Fatalf("delivered %d messages, want %d", len(delivered), len(messages))
	}
	seen := make(map[int]bool)
	for _, message := range delivered {
		index := int(message.destination.Port) - 1000
		if index < 0 || index >= len(messages) {
			t.Fatalf("unexpected destination %v", message.destination)
		}
		if seen[index] {
			t.Fatalf("message %d delivered twice", index)
		}
		seen[index] = true
		expected := messages[index]
		if len(message.data) != len(expected.data) {
			t.Fatalf("message %d length %d, want %d", index, len(message.data), len(expected.data))
		}
		for i := range expected.data {
			if message.data[i] != expected.data[i] {
				t.Fatalf("message %d differs at byte %d", index, i)
			}
		}
		if message.packetID != expected.packetID {
			t.Fatalf("message %d packet id %d, want %d", index, message.packetID, expected.packetID)
		}
	}
}

func TestFECBlockRoundTripWithoutLoss(t *testing.T) {
	config := fecTestConfig(4, 2, 1)
	encoder := newFECBlockEncoder(config)
	sink := new(fecTestSink)
	messages := make([]*udpMessage, 0, 10)
	for index := 0; index < 10; index++ {
		message := fecTestMessage(index, 300+index*17)
		messages = append(messages, message)
		fecTestEncode(t, encoder, sink, message)
	}
	time.Sleep(30 * time.Millisecond)
	decoder := newFECBlockDecoder(config, nil)
	var delivered []*udpMessage
	for _, item := range sink.snapshot() {
		fecTestDecode(t, decoder, item, &delivered)
	}
	fecTestAssert(t, messages, delivered)
}

func TestFECBlockRecoversLostShards(t *testing.T) {
	for _, lost := range []int{1, 2} {
		config := fecTestConfig(4, 2, 1)
		encoder := newFECBlockEncoder(config)
		sink := new(fecTestSink)
		var messages []*udpMessage
		for index := 0; index < 8; index++ {
			message := fecTestMessage(index, 400)
			messages = append(messages, message)
			fecTestEncode(t, encoder, sink, message)
		}
		time.Sleep(30 * time.Millisecond)
		decoder := newFECBlockDecoder(config, nil)
		var delivered []*udpMessage
		dropped := 0
		for _, item := range sink.snapshot() {
			if item.frame.shardIndex&fecParityShardFlag == 0 && item.blockID == 1 && dropped < lost {
				dropped++
				continue
			}
			fecTestDecode(t, decoder, item, &delivered)
		}
		fecTestAssert(t, messages, delivered)
	}
}

func TestFECBlockDropsMoreThanParityLost(t *testing.T) {
	config := fecTestConfig(4, 1, 1)
	encoder := newFECBlockEncoder(config)
	sink := new(fecTestSink)
	var messages []*udpMessage
	for index := 0; index < 8; index++ {
		message := fecTestMessage(index, 400)
		messages = append(messages, message)
		fecTestEncode(t, encoder, sink, message)
	}
	time.Sleep(30 * time.Millisecond)
	decoder := newFECBlockDecoder(config, nil)
	var delivered []*udpMessage
	dropped := 0
	for _, item := range sink.snapshot() {
		if item.frame.shardIndex&fecParityShardFlag == 0 && item.blockID == 1 && dropped < 2 {
			dropped++
			continue
		}
		fecTestDecode(t, decoder, item, &delivered)
	}
	if len(delivered) != len(messages)-2 {
		t.Fatalf("delivered %d messages, want %d", len(delivered), len(messages)-2)
	}
}

func TestFECBlockFlushByTimeout(t *testing.T) {
	config := fecTestConfig(10, 2, 1)
	encoder := newFECBlockEncoder(config)
	sink := new(fecTestSink)
	var messages []*udpMessage
	for index := 0; index < 2; index++ {
		message := fecTestMessage(index, 200)
		messages = append(messages, message)
		fecTestEncode(t, encoder, sink, message)
	}
	time.Sleep(30 * time.Millisecond)
	encoder.access.Lock()
	pending := len(encoder.blocks[0].bodies)
	encoder.access.Unlock()
	if pending != 0 {
		t.Fatalf("pending bodies after timeout flush: %d", pending)
	}
	parity := 0
	frames := sink.snapshot()
	for _, item := range frames {
		if item.frame.shardIndex&fecParityShardFlag != 0 && item.frame.m > 0 {
			parity++
		}
	}
	if parity != 2 {
		t.Fatalf("parity frames after timeout flush: %d", parity)
	}
	decoder := newFECBlockDecoder(config, nil)
	var delivered []*udpMessage
	for _, item := range frames {
		if item.frame.shardIndex&fecParityShardFlag == 0 && item.frame.shardIndex == 0 {
			continue
		}
		fecTestDecode(t, decoder, item, &delivered)
	}
	fecTestAssert(t, messages, delivered)
}

func TestFECBlockInterleave(t *testing.T) {
	config := fecTestConfig(2, 1, 2)
	encoder := newFECBlockEncoder(config)
	sink := new(fecTestSink)
	for index := 0; index < 4; index++ {
		fecTestEncode(t, encoder, sink, fecTestMessage(index, 100))
	}
	blocks := make(map[uint16]bool)
	for _, item := range sink.snapshot() {
		blocks[item.blockID] = true
	}
	if len(blocks) != 2 {
		t.Fatalf("blocks used by 4 messages: %d, want 2", len(blocks))
	}
	time.Sleep(30 * time.Millisecond)
}

func TestFECParityForLoss(t *testing.T) {
	cases := []struct {
		loss   uint16
		want   int
		k      int
		maxPar int
	}{
		{0, 0, 10, 4},
		{1, 1, 10, 4},
		{5, 1, 10, 4},
		{20, 1, 10, 4},
		{50, 2, 10, 4},
		{100, 3, 10, 4},
		{200, 4, 10, 4},
		{1000, 4, 10, 4},
		{50, 1, 3, 4},
	}
	for _, c := range cases {
		if got := fecParityForLoss(c.k, c.loss, c.maxPar); got != c.want {
			t.Fatalf("loss %d k %d: parity %d, want %d", c.loss, c.k, got, c.want)
		}
	}
}

func TestFECBlockReportsLoss(t *testing.T) {
	config := fecTestConfig(4, 2, 1)
	encoder := newFECBlockEncoder(config)
	sink := new(fecTestSink)
	for index := 0; index < 64; index++ {
		fecTestEncode(t, encoder, sink, fecTestMessage(index, 200))
	}
	time.Sleep(30 * time.Millisecond)
	var reported atomic.Uint32
	decoder := newFECBlockDecoder(config, func(lossPerMille uint16) {
		reported.Store(uint32(lossPerMille))
	})
	var delivered []*udpMessage
	dropped := make(map[uint16]bool)
	for _, item := range sink.snapshot() {
		if item.frame.shardIndex&fecParityShardFlag == 0 && !dropped[item.blockID] && item.frame.shardIndex == 0 {
			dropped[item.blockID] = true
			continue
		}
		fecTestDecode(t, decoder, item, &delivered)
	}
	if reported.Load() != 250 {
		t.Fatalf("reported loss %d, want 250", reported.Load())
	}
}

func TestFECBlockRejectsInvalidHeader(t *testing.T) {
	decoder := newFECBlockDecoder(fecTestConfig(10, 2, 1), nil)
	err := decoder.input(1, 0, 200, 2, make([]byte, 10), func(body []byte) error {
		return nil
	})
	if err == nil {
		t.Fatal("oversized block accepted")
	}
}
