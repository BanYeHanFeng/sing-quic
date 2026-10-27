package udpx

import (
	"encoding/binary"
	"net"

	E "github.com/sagernet/sing/common/exceptions"
)

// Frames
//
// A payload is a sequence of frames. Every frame starts with a type byte, and
// the sequence has no length of its own: a packet is one datagram, so the end
// of the payload is the end of the frame list. Small frames share a packet,
// which is what keeps an acknowledgement from costing a packet of its own while
// there is other traffic.
type frameType uint8

const (
	// frameTypePing proves that an association is still there. It carries
	// nothing and has no answer of its own: it exists so that a peer which would
	// otherwise be idle keeps sending, which is what keeps a NAT mapping open and
	// what gives the other end something to acknowledge.
	frameTypePing frameType = iota

	// frameTypeClose ends the association. The code in it is what the peer
	// reports as the reason.
	frameTypeClose

	// frameTypeAck acknowledges a set of packet numbers. It is the only frame
	// that is not eliciting an acknowledgement of its own: two ends that did
	// nothing but acknowledge each other would never stop.
	frameTypeAck

	// frameTypeStream carries a piece of a stream. It is the only frame that has
	// to be sent again after a loss, because it is the only one that carries
	// something the peer cannot reconstruct.
	frameTypeStream

	// frameTypeMaxData moves the association window forward: the peer may send
	// more than it was allowed to before.
	frameTypeMaxData

	// frameTypeMaxStreamData moves one stream's window forward.
	frameTypeMaxStreamData

	// frameTypeResetStream ends one stream in both directions before its data
	// is complete. It is what a proxied connection that failed in the middle
	// needs: the stream is done, and the association and the streams beside it
	// are not.
	frameTypeResetStream

	// frameTypeDatagram carries one unreliable message, or one piece of one.
	// Nothing about it is retransmitted: a datagram that is lost is lost, which
	// is what a forwarded UDP packet wants and what keeps a datagram from
	// holding up a stream.
	frameTypeDatagram

	// frameTypeMaxStreams moves the number of streams the peer may open forward.
	// It is what the peer needs before it can open a stream at all, and the
	// number is cumulative: the peer may have opened that many in total, so a
	// stream that ended is a stream it may open again.
	//
	// It is last in this list because the numbers are the wire format: the ones
	// above are already sent by deployed peers, so a new type goes at the end
	// rather than beside the frames it belongs with.
	frameTypeMaxStreams
)

// Layout of the type byte.
const (
	frameTypeBits = 0x0f
	frameFlagFIN  = 0x80
)

// Layout of a stream frame: the type byte, then the stream it belongs to, where
// in that stream the data goes, how much of it there is, and the data. The length
// is explicit because a packet holds several frames.
const (
	streamFixedLen = 1 + 4 + 8 + 2
	streamBodyLen  = 4 + 8 + 2
)

// Layout of a reset-stream frame: the type byte, the stream it ends, and the
// code. There is no offset: a stream that is reset has no end.
const (
	resetStreamFixedLen = 1 + 4 + 1
	resetStreamBodyLen  = 4 + 1
)

// Layout of a datagram frame: the type byte, the channel the message belongs to,
// which message on that channel it is part of, where in that message it goes and
// how much of it is here. The channel is a key the caller chooses; one association
// carries as many of them as the caller needs, which is what keeps a forwarded UDP
// packet from opening an association of its own.
const (
	datagramFixedLen = 1 + 4 + 2 + 1 + 1 + 2
	datagramBodyLen  = 4 + 2 + 1 + 1 + 2
)

// frame is one parsed frame of a payload. The body points into the payload, so
// a frame must be used before the packet it came from is reused.
type frame struct {
	body      []byte
	frameType frameType
	flags     uint8
}

// retransmittable reports whether a lost frame of this type has to be sent
// again. Frames that carry data, and frames that move a ceiling forward, do: a
// ceiling that was lost would leave the peer waiting for credit that was already
// granted, while repeating one that arrived is harmless because a ceiling only
// ever moves forward. A stream reset does too, and for the same reason in
// reverse: a peer that never hears it keeps writing into a stream nobody reads.
func (t frameType) retransmittable() bool {
	switch t {
	case frameTypeStream, frameTypeMaxData, frameTypeMaxStreamData, frameTypeResetStream, frameTypeMaxStreams:
		return true
	default:
		return false
	}
}

// nextFrame splits the first frame off payload and returns it with the rest.
func nextFrame(payload []byte) (frame, []byte, error) {
	if len(payload) == 0 {
		return frame{}, nil, errShortFrame
	}
	flags := payload[0] &^ frameTypeBits
	switch frameType(payload[0] & frameTypeBits) {
	case frameTypePing:
		if flags != 0 {
			return frame{}, nil, errShortFrame
		}
		return frame{frameType: frameTypePing}, payload[1:], nil
	case frameTypeClose:
		if flags != 0 || len(payload) < 2 {
			return frame{}, nil, errShortFrame
		}
		return frame{frameType: frameTypeClose, body: payload[1:2]}, payload[2:], nil
	case frameTypeAck:
		if flags != 0 {
			return frame{}, nil, errShortFrame
		}
		bodyLen, err := ackBodyLen(payload[1:])
		if err != nil {
			return frame{}, nil, err
		}
		return frame{frameType: frameTypeAck, body: payload[1 : 1+bodyLen]}, payload[1+bodyLen:], nil
	case frameTypeStream:
		if len(payload) < streamFixedLen {
			return frame{}, nil, errShortFrame
		}
		length := int(binary.BigEndian.Uint16(payload[1+4+8:]))
		if len(payload) < streamFixedLen+length {
			return frame{}, nil, errShortFrame
		}
		return frame{
			frameType: frameTypeStream,
			flags:     flags,
			body:      payload[1 : streamFixedLen+length],
		}, payload[streamFixedLen+length:], nil
	case frameTypeMaxData:
		if flags != 0 || len(payload) < 1+8 {
			return frame{}, nil, errShortFrame
		}
		return frame{frameType: frameTypeMaxData, body: payload[1:9]}, payload[9:], nil
	case frameTypeMaxStreamData:
		if flags != 0 || len(payload) < 1+4+8 {
			return frame{}, nil, errShortFrame
		}
		return frame{frameType: frameTypeMaxStreamData, body: payload[1:13]}, payload[13:], nil
	case frameTypeResetStream:
		if flags != 0 || len(payload) < resetStreamFixedLen {
			return frame{}, nil, errShortFrame
		}
		return frame{
			frameType: frameTypeResetStream,
			body:      payload[1:resetStreamFixedLen],
		}, payload[resetStreamFixedLen:], nil
	case frameTypeDatagram:
		if flags != 0 || len(payload) < datagramFixedLen {
			return frame{}, nil, errShortFrame
		}
		length := int(binary.BigEndian.Uint16(payload[datagramFixedLen-2:]))
		if len(payload) < datagramFixedLen+length {
			return frame{}, nil, errShortFrame
		}
		return frame{
			frameType: frameTypeDatagram,
			body:      payload[1 : datagramFixedLen+length],
		}, payload[datagramFixedLen+length:], nil
	case frameTypeMaxStreams:
		if flags != 0 || len(payload) < 1+4 {
			return frame{}, nil, errShortFrame
		}
		return frame{frameType: frameTypeMaxStreams, body: payload[1:5]}, payload[5:], nil
	default:
		return frame{}, nil, E.New("unknown frame type ", int(payload[0]))
	}
}

// streamData is what a stream frame carries.
type streamData struct {
	data     []byte
	offset   uint64
	streamID uint32
	fin      bool
}

// stream returns what a stream frame carries.
func (f frame) stream() streamData {
	return streamData{
		streamID: binary.BigEndian.Uint32(f.body),
		offset:   binary.BigEndian.Uint64(f.body[4:]),
		data:     f.body[streamBodyLen:],
		fin:      f.flags&frameFlagFIN != 0,
	}
}

// appendStream appends a stream frame to dst.
func appendStream(dst []byte, streamID uint32, offset uint64, fin bool, data []byte) []byte {
	flags := byte(0)
	if fin {
		flags = frameFlagFIN
	}
	dst = append(dst, byte(frameTypeStream)|flags)
	dst = binary.BigEndian.AppendUint32(dst, streamID)
	dst = binary.BigEndian.AppendUint64(dst, offset)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(data)))
	return append(dst, data...)
}

// streamReset is what a reset-stream frame carries.
type streamReset struct {
	streamID uint32
	code     resetCode
}

// streamReset returns what a reset-stream frame carries.
func (f frame) streamReset() streamReset {
	return streamReset{
		streamID: binary.BigEndian.Uint32(f.body),
		code:     resetCode(f.body[resetStreamBodyLen-1]),
	}
}

// appendResetStream appends a reset-stream frame to dst.
func appendResetStream(dst []byte, streamID uint32, code resetCode) []byte {
	dst = append(dst, byte(frameTypeResetStream))
	dst = binary.BigEndian.AppendUint32(dst, streamID)
	return append(dst, byte(code))
}

// resetCode is why a stream ended before both halves of it closed. It is not the
// code of a close frame: a stream ending is one stream, not the association.
type resetCode uint8

const (
	// resetCodeNormal is a stream the resetting end was done with: it stopped
	// reading, and it is not a failure of the connection the stream carries.
	resetCodeNormal resetCode = iota
)

// err maps the code a stream was reset with to what the application sees. The
// code stays in the error, so that a caller can tell an abort from a stream that
// ended on purpose, which is what the difference between an ERROR line and a
// closed connection comes down to.
func (c resetCode) err() error {
	return StreamResetError{Code: uint8(c)}
}

// datagramData is what a datagram frame carries.
type datagramData struct {
	data    []byte
	channel uint32
	message uint16
	index   uint8
	total   uint8
}

// datagram returns what a datagram frame carries.
func (f frame) datagram() datagramData {
	return datagramData{
		channel: binary.BigEndian.Uint32(f.body),
		message: binary.BigEndian.Uint16(f.body[4:]),
		index:   f.body[6],
		total:   f.body[7],
		data:    f.body[datagramBodyLen:],
	}
}

// appendDatagram appends a datagram frame to dst.
func appendDatagram(dst []byte, data datagramData) []byte {
	dst = append(dst, byte(frameTypeDatagram))
	dst = binary.BigEndian.AppendUint32(dst, data.channel)
	dst = binary.BigEndian.AppendUint16(dst, data.message)
	dst = append(dst, data.index, data.total)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(data.data)))
	return append(dst, data.data...)
}

// closeCode returns the code of a close frame.
func (f frame) closeCode() closeCode {
	return closeCode(f.body[0])
}

// closeCode is why an association ended, as far as the peer needs to know. The
// string a local error carries stays local: what travels is the class of the
// ending, because that is all the peer can act on.
type closeCode uint8

const (
	// closeCodeNormal is a close both ends expected.
	closeCodeNormal closeCode = iota

	// closeCodeIdleTimeout is an association closed for silence.
	closeCodeIdleTimeout

	// closeCodeReset is an association the peer reset without keeping state for
	// it.
	closeCodeReset

	// closeCodeError is any other local error.
	closeCodeError
)

// err maps the code a peer closed with to the reason this end reports.
func (c closeCode) err() error {
	switch c {
	case closeCodeNormal:
		return net.ErrClosed
	case closeCodeIdleTimeout:
		return ErrIdleTimeout
	case closeCodeReset:
		return ErrStatelessReset
	default:
		return E.New("udpx: closed by peer with code ", int(c))
	}
}

// closeCodeOf maps the error an end closes with to the code it announces.
func closeCodeOf(err error) closeCode {
	switch err {
	case nil, net.ErrClosed:
		return closeCodeNormal
	case ErrIdleTimeout:
		return closeCodeIdleTimeout
	case ErrStatelessReset:
		return closeCodeReset
	default:
		return closeCodeError
	}
}

func appendPing(dst []byte) []byte {
	return append(dst, byte(frameTypePing))
}

func appendClose(dst []byte, code closeCode) []byte {
	return append(dst, byte(frameTypeClose), byte(code))
}
