package udpx

import (
	"encoding/binary"
	"net"

	E "github.com/sagernet/sing/common/exceptions"
)

type frameType uint8

const (
	frameTypePing frameType = iota

	frameTypeClose

	frameTypeAck

	frameTypeStream

	frameTypeMaxData

	frameTypeMaxStreamData

	frameTypeResetStream

	frameTypeDatagram

	frameTypeMaxStreams

	frameTypePadding
)

const paddingFixedLen = 1 + 2

const (
	frameTypeBits = 0x0f
	frameFlagFIN  = 0x80
)

const (
	streamFixedLen = 1 + 4 + 8 + 2
	streamBodyLen  = 4 + 8 + 2
)

const (
	resetStreamFixedLen = 1 + 4 + 1
	resetStreamBodyLen  = 4 + 1
)

const maxStreamDataFrameLen = 1 + 4 + 8

const (
	datagramFixedLen = 1 + 4 + 2 + 1 + 1 + 2
	datagramBodyLen  = 4 + 2 + 1 + 1 + 2
)

type frame struct {
	body      []byte
	frameType frameType
	flags     uint8
}

func (t frameType) retransmittable() bool {
	switch t {
	case frameTypeStream, frameTypeMaxData, frameTypeMaxStreamData, frameTypeResetStream, frameTypeMaxStreams:
		return true
	default:
		return false
	}
}

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
	case frameTypePadding:
		if flags != 0 || len(payload) < paddingFixedLen {
			return frame{}, nil, errShortFrame
		}
		length := int(binary.BigEndian.Uint16(payload[1:3]))
		if len(payload) < paddingFixedLen+length {
			return frame{}, nil, errShortFrame
		}
		return frame{frameType: frameTypePadding}, payload[paddingFixedLen+length:], nil
	default:
		return frame{}, nil, E.New("unknown frame type ", int(payload[0]))
	}
}

type streamData struct {
	data     []byte
	offset   uint64
	streamID uint32
	fin      bool
}

func (f frame) stream() streamData {
	return streamData{
		streamID: binary.BigEndian.Uint32(f.body),
		offset:   binary.BigEndian.Uint64(f.body[4:]),
		data:     f.body[streamBodyLen:],
		fin:      f.flags&frameFlagFIN != 0,
	}
}

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

type streamReset struct {
	streamID uint32
	code     resetCode
}

func (f frame) streamReset() streamReset {
	return streamReset{
		streamID: binary.BigEndian.Uint32(f.body),
		code:     resetCode(f.body[resetStreamBodyLen-1]),
	}
}

func appendResetStream(dst []byte, streamID uint32, code resetCode) []byte {
	dst = append(dst, byte(frameTypeResetStream))
	dst = binary.BigEndian.AppendUint32(dst, streamID)
	return append(dst, byte(code))
}

type resetCode uint8

const (
	resetCodeNormal resetCode = iota
)

func (c resetCode) err() error {
	return StreamResetError{Code: uint8(c)}
}

type datagramData struct {
	data    []byte
	channel uint32
	message uint16
	index   uint8
	total   uint8
}

func (f frame) datagram() datagramData {
	return datagramData{
		channel: binary.BigEndian.Uint32(f.body),
		message: binary.BigEndian.Uint16(f.body[4:]),
		index:   f.body[6],
		total:   f.body[7],
		data:    f.body[datagramBodyLen:],
	}
}

func appendDatagram(dst []byte, data datagramData) []byte {
	dst = append(dst, byte(frameTypeDatagram))
	dst = binary.BigEndian.AppendUint32(dst, data.channel)
	dst = binary.BigEndian.AppendUint16(dst, data.message)
	dst = append(dst, data.index, data.total)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(data.data)))
	return append(dst, data.data...)
}

func (f frame) closeCode() closeCode {
	return closeCode(f.body[0])
}

type closeCode uint8

const (
	closeCodeNormal closeCode = iota

	closeCodeIdleTimeout

	closeCodeError
)

func (c closeCode) err() error {
	switch c {
	case closeCodeNormal:
		return net.ErrClosed
	case closeCodeIdleTimeout:
		return ErrIdleTimeout
	default:
		return E.New("udpx: closed by peer with code ", int(c))
	}
}

func closeCodeOf(err error) closeCode {
	switch err {
	case nil, net.ErrClosed:
		return closeCodeNormal
	case ErrIdleTimeout:
		return closeCodeIdleTimeout
	default:
		return closeCodeError
	}
}

func appendPing(dst []byte) []byte {
	return append(dst, byte(frameTypePing))
}

func appendPadding(dst []byte, length int) []byte {
	dst = append(dst, byte(frameTypePadding))
	dst = binary.BigEndian.AppendUint16(dst, uint16(length))
	return append(dst, make([]byte, length)...)
}

func appendClose(dst []byte, code closeCode) []byte {
	return append(dst, byte(frameTypeClose), byte(code))
}
