package udpx

import (
	"bytes"
	"testing"
)

func TestStreamFrameRoundTrip(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
		fin  bool
	}{
		{"empty", nil, false},
		{"empty final", nil, true},
		{"data", []byte("hello"), false},
		{"data final", bytes.Repeat([]byte{0x7f}, 1200), true},
	} {
		encoded := appendStream(nil, 7, 1<<40, test.fin, test.data)
		f, rest, err := nextFrame(encoded)
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		if len(rest) != 0 {
			t.Fatalf("%s: %d bytes after the frame", test.name, len(rest))
		}
		if f.frameType != frameTypeStream {
			t.Fatalf("%s: frame of type %d", test.name, f.frameType)
		}
		data := f.stream()
		if data.streamID != 7 || data.offset != 1<<40 || data.fin != test.fin {
			t.Fatalf("%s: %+v", test.name, data)
		}
		if !bytes.Equal(data.data, test.data) {
			t.Fatalf("%s: data changed", test.name)
		}
	}
}

func TestStreamFrameRejects(t *testing.T) {
	valid := appendStream(nil, 1, 0, true, []byte("data"))
	for _, truncated := range []int{0, 1, 5, streamFixedLen - 1, len(valid) - 1} {
		if _, _, err := nextFrame(valid[:truncated]); err == nil {
			t.Fatalf("stream frame truncated to %d bytes parsed", truncated)
		}
	}
	// The flags of the type byte belong to the stream frame; another frame that
	// sets them is not a frame this implementation wrote.
	ping := []byte{byte(frameTypePing) | frameFlagFIN}
	if _, _, err := nextFrame(ping); err == nil {
		t.Fatal("a ping with the end-of-stream flag parsed")
	}
	if _, _, err := nextFrame([]byte{byte(frameTypeStream) + 1}); err == nil {
		t.Fatal("a frame of an unknown type parsed")
	}
}

// TestResetStreamFrame requires a reset to name the stream it ends and the code it
// carries, and to be rejected when it is cut short or flagged.
func TestResetStreamFrame(t *testing.T) {
	encoded := appendResetStream(nil, 1<<30, resetCodeNormal)
	if len(encoded) != resetStreamFixedLen {
		t.Fatalf("reset frame is %d bytes", len(encoded))
	}
	f, rest, err := nextFrame(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 {
		t.Fatalf("%d bytes after the frame", len(rest))
	}
	if f.frameType != frameTypeResetStream {
		t.Fatalf("frame of type %d", f.frameType)
	}
	if reset := f.streamReset(); reset.streamID != 1<<30 || reset.code != resetCodeNormal {
		t.Fatalf("reset %+v", f.streamReset())
	}
	for _, truncated := range []int{0, 1, resetStreamFixedLen - 1} {
		if _, _, err = nextFrame(encoded[:truncated]); err == nil {
			t.Fatalf("reset frame truncated to %d bytes parsed", truncated)
		}
	}
	flagged := append([]byte(nil), encoded...)
	flagged[0] |= frameFlagFIN
	if _, _, err = nextFrame(flagged); err == nil {
		t.Fatal("a reset with the end-of-stream flag parsed")
	}
	// A reset is what a stream needs to hear about even when its packet was lost,
	// while an acknowledgement and a ping are never sent again.
	if !frameTypeResetStream.retransmittable() {
		t.Fatal("a reset is not retransmitted")
	}
}

// TestFramesMix requires several frames of different types to be split back out
// of one payload in the order they were written.
func TestFramesMix(t *testing.T) {
	payload := appendPing(nil)
	payload = appendStream(payload, 3, 0, false, []byte("part"))
	var ranges pnRanges
	fillRanges(&ranges, 0, 2)
	payload = ranges.ack().appendTo(payload)
	payload = appendResetStream(payload, 5, resetCodeNormal)
	payload = appendClose(payload, closeCodeIdleTimeout)

	expected := []frameType{frameTypePing, frameTypeStream, frameTypeAck, frameTypeResetStream, frameTypeClose}
	for index := range expected {
		f, rest, err := nextFrame(payload)
		if err != nil {
			t.Fatalf("frame %d: %v", index, err)
		}
		if f.frameType != expected[index] {
			t.Fatalf("frame %d is of type %d", index, f.frameType)
		}
		if f.frameType == frameTypeClose && f.closeCode() != closeCodeIdleTimeout {
			t.Fatalf("close code %d", f.closeCode())
		}
		if f.frameType == frameTypeResetStream && f.streamReset().streamID != 5 {
			t.Fatalf("reset of stream %d", f.streamReset().streamID)
		}
		payload = rest
	}
	if len(payload) != 0 {
		t.Fatalf("%d bytes left", len(payload))
	}
}
