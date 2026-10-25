package udpx

import (
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
)

// frame is one parsed frame of a payload. The body points into the payload, so
// a frame must be used before the packet it came from is reused.
type frame struct {
	frameType frameType
	body      []byte
}

// nextFrame splits the first frame off payload and returns it with the rest.
func nextFrame(payload []byte) (frame, []byte, error) {
	if len(payload) == 0 {
		return frame{}, nil, errShortFrame
	}
	switch frameType(payload[0]) {
	case frameTypePing:
		return frame{frameType: frameTypePing}, payload[1:], nil
	case frameTypeClose:
		if len(payload) < 2 {
			return frame{}, nil, errShortFrame
		}
		return frame{frameType: frameTypeClose, body: payload[1:2]}, payload[2:], nil
	case frameTypeAck:
		bodyLen, err := ackBodyLen(payload[1:])
		if err != nil {
			return frame{}, nil, err
		}
		return frame{frameType: frameTypeAck, body: payload[1 : 1+bodyLen]}, payload[1+bodyLen:], nil
	default:
		return frame{}, nil, E.New("unknown frame type ", int(payload[0]))
	}
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
