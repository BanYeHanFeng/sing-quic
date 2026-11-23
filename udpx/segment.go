package udpx

import (
	"sync"
)

type recvSegment struct {
	buffer []byte
	data   []byte
	offset uint64
}

var recvSegmentPool = sync.Pool{
	New: func() any {
		buffer := make([]byte, maxPacketSize)
		return &buffer
	},
}

func storeSegment(s *Stream, offset uint64, data []byte) {
	var buffer []byte
	if len(data) <= maxPacketSize {
		pooled := recvSegmentPool.Get().(*[]byte)
		buffer = (*pooled)[:len(data)]
	} else {
		buffer = make([]byte, len(data))
	}
	copy(buffer, data)
	s.insertSegment(recvSegment{data: buffer, offset: offset, buffer: buffer})
}

func releaseSegment(segment recvSegment) {
	if cap(segment.buffer) != maxPacketSize {
		return
	}
	buffer := segment.buffer[:maxPacketSize]
	recvSegmentPool.Put(&buffer)
}

func (s *Stream) insertSegment(segment recvSegment) {
	if count := len(s.segments); count > 0 {
		last := s.segments[count-1]
		if last.offset+uint64(len(last.data)) <= segment.offset {
			s.segments = append(s.segments, segment)
			return
		}
	}
	end := segment.offset + uint64(len(segment.data))
	index := 0
	for index < len(s.segments) && s.segments[index].offset < segment.offset {
		index++
	}
	if index > 0 {
		previous := s.segments[index-1]
		previousEnd := previous.offset + uint64(len(previous.data))
		if previousEnd > segment.offset {
			skip := previousEnd - segment.offset
			if skip >= uint64(len(segment.data)) {
				releaseSegment(segment)
				return
			}
			segment.data = segment.data[skip:]
			segment.offset = previousEnd
		}
	}
	for index < len(s.segments) {
		following := s.segments[index]
		if following.offset >= end {
			break
		}
		followingEnd := following.offset + uint64(len(following.data))
		if followingEnd <= end {
			releaseSegment(following)
			s.segments = append(s.segments[:index], s.segments[index+1:]...)
			continue
		}
		segment.data = segment.data[:following.offset-segment.offset]
		end = following.offset
		break
	}
	if len(segment.data) == 0 {
		releaseSegment(segment)
		return
	}
	s.segments = append(s.segments, recvSegment{})
	copy(s.segments[index+1:], s.segments[index:])
	s.segments[index] = segment
}

func (s *Stream) truncate(finalOffset uint64) int {
	dropped := 0
	kept := s.segments[:0]
	for _, segment := range s.segments {
		if segment.offset >= finalOffset {
			dropped += len(segment.data)
			releaseSegment(segment)
			continue
		}
		if end := segment.offset + uint64(len(segment.data)); end > finalOffset {
			dropped += int(end - finalOffset)
			segment.data = segment.data[:finalOffset-segment.offset]
		}
		kept = append(kept, segment)
	}
	for index := len(kept); index < len(s.segments); index++ {
		s.segments[index] = recvSegment{}
	}
	s.segments = kept
	return dropped
}
