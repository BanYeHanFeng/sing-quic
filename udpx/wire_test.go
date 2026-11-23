package udpx

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func decodeFrames(payload []byte) ([]struct {
	Type byte
	Body []byte
}, error) {
	var frames []struct {
		Type byte
		Body []byte
	}
	for len(payload) > 0 {
		if len(payload) < frameHeaderLen {
			return nil, errShortFrame
		}
		frameType := payload[0]
		length := int(binary.BigEndian.Uint16(payload[1:3]))
		if len(payload) < frameHeaderLen+length {
			return nil, errShortFrame
		}
		frames = append(frames, struct {
			Type byte
			Body []byte
		}{frameType, payload[frameHeaderLen : frameHeaderLen+length]})
		payload = payload[frameHeaderLen+length:]
	}
	return frames, nil
}

func TestFrameRoundTrip(t *testing.T) {
	payload := appendPingFrame(nil)
	payload = appendCloseFrame(payload, closeCodeIdleTimeout)
	payload = appendMaxDataFrame(payload, 1<<30)
	payload = appendMaxStreamDataFrame(payload, 7, 1<<29)
	payload = appendMaxStreamsFrame(payload, 4096)
	payload = appendStreamHeader(payload, 3, 1<<20, true, 5)
	payload = append(payload, "hello"...)
	payload = appendResetStreamFrame(payload, 9, 1<<21, resetCodeNormal)
	payload = appendDatagramHeader(payload, 11, 12, 1, 2, 3)
	payload = append(payload, "abc"...)
	payload = appendPaddingFrame(payload, 4)

	frames, err := decodeFrames(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 9 {
		t.Fatalf("%d frames", len(frames))
	}
	if frames[0].Type != frameTypePing || len(frames[0].Body) != 0 {
		t.Fatal("ping")
	}
	if frames[1].Type != frameTypeClose || len(frames[1].Body) != 1 || closeCode(frames[1].Body[0]) != closeCodeIdleTimeout {
		t.Fatal("close")
	}
	if frames[2].Type != frameTypeMaxData || binary.BigEndian.Uint64(frames[2].Body) != 1<<30 {
		t.Fatal("max data")
	}
	if frames[3].Type != frameTypeMaxStreamData {
		t.Fatal("max stream data")
	}
	if binary.BigEndian.Uint32(frames[3].Body) != 7 || binary.BigEndian.Uint64(frames[3].Body[4:]) != 1<<29 {
		t.Fatal("max stream data body")
	}
	if frames[4].Type != frameTypeMaxStreams || binary.BigEndian.Uint32(frames[4].Body) != 4096 {
		t.Fatal("max streams")
	}
	stream := parseStreamFrame(frames[5].Type, frames[5].Body)
	if stream.streamID != 3 || stream.offset != 1<<20 || !stream.fin || string(stream.data) != "hello" {
		t.Fatal("stream")
	}
	reset := parseResetStream(frames[6].Body)
	if reset.streamID != 9 || reset.finalOffset != 1<<21 || reset.code != resetCodeNormal {
		t.Fatal("reset")
	}
	datagram := parseDatagram(frames[7].Body)
	if datagram.channel != 11 || datagram.message != 12 || datagram.index != 1 || datagram.total != 2 || string(datagram.data) != "abc" {
		t.Fatal("datagram")
	}
	if frames[8].Type != frameTypePadding || len(frames[8].Body) != 4 {
		t.Fatal("padding")
	}
}

func TestFinFlagDoesNotHideTheType(t *testing.T) {
	payload := appendStreamHeader(nil, 1, 0, true, 0)
	if payload[0]&frameTypeMask != frameTypeStream {
		t.Fatal("fin changed the frame type")
	}
	if payload[0]&frameFlagFin == 0 {
		t.Fatal("fin was not set")
	}
}

func TestStreamFrameTooLargeForTheLengthField(t *testing.T) {
	if len(appendStreamHeader(nil, 1, 0, false, 0xffff)) != streamHeaderLen {
		t.Fatal("header length changed")
	}
}

func FuzzFrame(f *testing.F) {
	f.Add(appendPingFrame(nil))
	f.Add(appendCloseFrame(nil, closeCodeNormal))
	f.Add(ack{largest: 4, count: 1, ranges: [maxAckRanges]pnRange{{start: 1, end: 4}}}.appendTo(nil))
	f.Add(appendStreamHeader(nil, 1, 2, true, 3))
	f.Add(appendResetStreamFrame(nil, 3, 4, resetCodeNormal))
	f.Add(appendDatagramHeader(nil, 1, 2, 0, 1, 2))
	f.Add(appendPaddingFrame(nil, 8))
	f.Fuzz(func(t *testing.T, payload []byte) {
		frames, err := decodeFrames(payload)
		if err != nil {
			return
		}
		for _, frame := range frames {
			switch frame.Type & frameTypeMask {
			case frameTypeAck:
				_, _ = parseAckFrame(frame.Body)
			case frameTypeStream:
				if len(frame.Body) < 12 {
					continue
				}
				stream := parseStreamFrame(frame.Type, frame.Body)
				_ = len(stream.data)
			case frameTypeResetStream:
				if len(frame.Body) < 13 {
					continue
				}
				_ = parseResetStream(frame.Body)
			case frameTypeDatagram:
				if len(frame.Body) < 8 {
					continue
				}
				_ = parseDatagram(frame.Body)
			}
		}
	})
}

func TestHeaderRoundTrip(t *testing.T) {
	original := header{ConnectionID: connectionID{1, 2, 3, 4, 5, 6, 7, 8}, Type: packetTypeData, PacketNumber: 42}
	packet := original.appendTo(nil)
	if len(packet) != headerLen {
		t.Fatalf("header of %d bytes", len(packet))
	}
	parsed, err := parseHeader(packet)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != original {
		t.Fatal("the header changed")
	}
}

func TestParseHeaderRejects(t *testing.T) {
	for _, packet := range [][]byte{
		nil,
		make([]byte, headerLen-1),
		append(append(make([]byte, connectionIDLen), packetReservedMask), 0, 0, 0, 0),
		append(append(make([]byte, connectionIDLen), 3), 0, 0, 0, 0),
	} {
		if _, err := parseHeader(packet); err == nil {
			t.Fatalf("parsed a packet of %d bytes", len(packet))
		}
	}
}

func TestSealOpen(t *testing.T) {
	key := make([]byte, keyLen)
	cipher, err := newPacketCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	h := header{ConnectionID: connectionID{9}, Type: packetTypeData, PacketNumber: 7}
	payload := appendPingFrame(nil)
	packet := h.appendTo(make([]byte, 0, headerLen+len(payload)+tagLen))
	packet = append(packet, payload...)
	packet = append(packet, make([]byte, tagLen)...)
	cipher.seal(packet, headerLen, h.PacketNumber)

	opened, decrypted, err := cipher.open(packet)
	if err != nil {
		t.Fatal(err)
	}
	if opened != h {
		t.Fatal("the header changed")
	}
	if !bytes.Equal(decrypted, payload) {
		t.Fatal("the payload changed")
	}
}

func TestOpenTampered(t *testing.T) {
	key := make([]byte, keyLen)
	cipher, err := newPacketCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	h := header{ConnectionID: connectionID{9}, Type: packetTypeData, PacketNumber: 7}
	payload := appendPingFrame(nil)
	packet := h.appendTo(make([]byte, 0, headerLen+len(payload)+tagLen))
	packet = append(packet, payload...)
	packet = append(packet, make([]byte, tagLen)...)
	cipher.seal(packet, headerLen, h.PacketNumber)

	tampered := bytes.Clone(packet)
	tampered[headerLen] ^= 0xff
	if _, _, openErr := cipher.open(tampered); openErr == nil {
		t.Fatal("a tampered payload opened")
	}
	truncated := packet[:headerLen+tagLen-1]
	if _, _, openErr := cipher.open(truncated); openErr == nil {
		t.Fatal("a truncated packet opened")
	}
	other, err := newPacketCipher(bytes.Repeat([]byte{1}, keyLen))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, openErr := other.open(packet); openErr == nil {
		t.Fatal("a packet opened with another key")
	}
}

func TestAckFrameRoundTrip(t *testing.T) {
	original := ack{largest: 100, delay: 5 * 1000 * 1000, count: 2}
	original.ranges[0] = pnRange{start: 90, end: 100}
	original.ranges[1] = pnRange{start: 1, end: 4}
	parsed, err := parseAckFrame(original.appendTo(nil)[frameHeaderLen:])
	if err != nil {
		t.Fatal(err)
	}
	if parsed.largest != original.largest || parsed.delay != original.delay || parsed.count != original.count {
		t.Fatal("the acknowledgement changed")
	}
	for index := range original.count {
		if parsed.ranges[index] != original.ranges[index] {
			t.Fatalf("range %d changed", index)
		}
	}
}

func TestAckParseRejects(t *testing.T) {
	for _, body := range [][]byte{
		nil,
		{0, 0, 0, 1, 0, 0},
		{0, 0, 0, 1, 0, 0, 0},
		{0, 0, 0, 1, 0, 0, 33, 0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 9, 0, 0, 0, 1},
		{0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1},
	} {
		if _, err := parseAckFrame(body); err == nil {
			t.Fatalf("parsed an acknowledgement of %d bytes", len(body))
		}
	}
}

func FuzzParseAck(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1})
	f.Add([]byte{0, 0, 0, 9, 0, 1, 2, 0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, 6, 0, 0, 0, 2})
	f.Fuzz(func(t *testing.T, body []byte) {
		parsed, err := parseAckFrame(body)
		if err != nil {
			return
		}
		if parsed.count == 0 || parsed.count > maxAckRanges {
			t.Fatalf("%d ranges", parsed.count)
		}
		for index := range parsed.count {
			if parsed.ranges[index].start > parsed.ranges[index].end {
				t.Fatal("an empty range was parsed")
			}
		}
	})
}
