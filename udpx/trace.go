package udpx

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sagernet/sing/common/logger"
)

const (
	traceQueueSize = 4096

	traceRecordSeparator = 0x1e

	defaultTraceCapacity = 384
)

// TraceOptions 控制 qlog 输出。
type TraceOptions struct {
	// Dir 非空时每条连接在里面写一个 qlog JSON-SEQ 文件。
	Dir string
	// Capacity 是单个文件的上限，单位 MB，零值使用默认值 384。
	Capacity int
}

// traceEvent 在产生它的 goroutine 上取时间，序列化与写盘交给后台。
type traceEvent struct {
	at   time.Duration
	name string
	data any
}

// tracer 把一条连接上的事件写成 qlog JSON-SEQ，文件名按连接标识生成。
// 未开启 trace 时 tracer 为 nil，record 与 close 在 nil 上安全。
type tracer struct {
	start time.Time
	path  string
	limit int

	mu      sync.Mutex
	events  chan traceEvent
	closed  bool
	dropped int
	done    chan struct{}
}

func newTracer(dir string, vantage string, groupID connectionID, capacity int, log logger.Logger) *tracer {
	if dir == "" {
		return nil
	}
	if capacity <= 0 {
		capacity = defaultTraceCapacity
	}
	err := os.MkdirAll(dir, 0o755)
	if err != nil {
		log.Debug("udpx: create trace directory: ", err)
		return nil
	}
	now := time.Now()
	path := filepath.Join(dir, vantage+"-"+groupID.String()+"-"+now.Format("20060102T150405.000000")+".sqlog")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Debug("udpx: create trace file: ", err)
		return nil
	}
	t := &tracer{
		start:  now,
		path:   path,
		limit:  capacity << 20,
		events: make(chan traceEvent, traceQueueSize),
		done:   make(chan struct{}),
	}
	go t.run(file, vantage, groupID)
	return t
}

func (t *tracer) record(name string, data any) {
	if t == nil {
		return
	}
	event := traceEvent{at: time.Since(t.start), name: name, data: data}
	t.mu.Lock()
	if !t.closed {
		select {
		case t.events <- event:
		default:
			t.dropped++
		}
	}
	t.mu.Unlock()
}

func (t *tracer) close() {
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	close(t.events)
	t.mu.Unlock()
	<-t.done
}

func (t *tracer) run(file *os.File, vantage string, groupID connectionID) {
	defer close(t.done)
	defer file.Close()
	writer := bufio.NewWriterSize(file, 64<<10)
	defer writer.Flush()
	written := t.writeHeader(writer, vantage, groupID)
	writtenEvents := 0
	dropped := 0
	full := false
	for event := range t.events {
		if full {
			dropped++
			continue
		}
		record := traceRecord{
			Time: traceMillis(event.at),
			Name: event.name,
			Data: event.data,
		}
		line, err := json.Marshal(record)
		if err != nil {
			dropped++
			continue
		}
		if written+len(line)+2 > t.limit {
			full = true
			dropped++
			continue
		}
		_, _ = writer.Write([]byte{traceRecordSeparator})
		_, _ = writer.Write(line)
		_, _ = writer.Write([]byte{'\n'})
		written += len(line) + 2
		writtenEvents++
	}
	t.mu.Lock()
	dropped += t.dropped
	t.mu.Unlock()
	if dropped > 0 || full {
		record := traceRecord{
			Time: traceMillis(time.Since(t.start)),
			Name: "udpx:trace_closed",
			Data: traceClosed{
				Events:  writtenEvents,
				Dropped: dropped,
				Bytes:   written,
			},
		}
		line, err := json.Marshal(record)
		if err == nil {
			_, _ = writer.Write([]byte{traceRecordSeparator})
			_, _ = writer.Write(line)
			_, _ = writer.Write([]byte{'\n'})
		}
	}
}

func (t *tracer) writeHeader(writer *bufio.Writer, vantage string, groupID connectionID) int {
	header := traceFileHeader{
		FileSchema:          "urn:ietf:params:qlog:file:sequential",
		SerializationFormat: "application/qlog+json-seq",
		Title:               "udpx qlog",
		Trace: traceHeader{
			VantagePoint: traceVantagePoint{Type: vantage},
			CommonFields: traceCommonFields{
				GroupID: groupID.String(),
				ReferenceTime: traceReferenceTime{
					ClockType:     "monotonic",
					Epoch:         "unknown",
					WallClockTime: t.start.Format(time.RFC3339Nano),
				},
			},
		},
		QlogFormat:  "JSON-SEQ",
		QlogVersion: "0.3",
	}
	line, err := json.Marshal(header)
	if err != nil {
		return t.limit
	}
	_, _ = writer.Write([]byte{traceRecordSeparator})
	_, _ = writer.Write(line)
	_, _ = writer.Write([]byte{'\n'})
	return len(line) + 2
}

func (id connectionID) String() string {
	return hex.EncodeToString(id[:])
}

// traceCloseOf 把连接结束的原因归类成 qlog 的 trigger。
func traceCloseOf(cause error) (string, closeCode) {
	code := closeCodeOf(cause)
	switch {
	case errors.Is(cause, ErrIdleTimeout):
		return "idle_timeout", code
	case errors.Is(cause, ErrProbeTimeout):
		return "probe_timeout", code
	case IsNormalClose(cause):
		return "clean", code
	default:
		return "error", code
	}
}

func traceMillis(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}

type traceRecord struct {
	Time float64 `json:"time"`
	Name string  `json:"name"`
	Data any     `json:"data"`
}

type traceFileHeader struct {
	FileSchema          string      `json:"file_schema"`
	SerializationFormat string      `json:"serialization_format"`
	Title               string      `json:"title"`
	Trace               traceHeader `json:"trace"`
	QlogFormat          string      `json:"qlog_format"`
	QlogVersion         string      `json:"qlog_version"`
}

type traceHeader struct {
	VantagePoint traceVantagePoint `json:"vantage_point"`
	CommonFields traceCommonFields `json:"common_fields"`
}

type traceVantagePoint struct {
	Type string `json:"type"`
}

type traceCommonFields struct {
	GroupID       string             `json:"group_id"`
	ReferenceTime traceReferenceTime `json:"reference_time"`
}

type traceReferenceTime struct {
	ClockType     string `json:"clock_type"`
	Epoch         string `json:"epoch"`
	WallClockTime string `json:"wall_clock_time"`
}

type traceConnectionStarted struct {
	Role        string  `json:"role"`
	LocalID     string  `json:"local_id"`
	PeerID      string  `json:"peer_id"`
	Remote      string  `json:"remote"`
	MTU         int     `json:"mtu"`
	Version     int     `json:"version"`
	IdleTimeout float64 `json:"idle_timeout,omitempty"`
	KeepAlive   float64 `json:"keep_alive,omitempty"`
}

type traceConnectionClosed struct {
	Initiator string `json:"initiator"`
	Trigger   string `json:"trigger,omitempty"`
	ErrorCode int    `json:"error_code,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

type tracePacketHeader struct {
	PacketType   string `json:"packet_type"`
	PacketNumber uint32 `json:"packet_number"`
}

type tracePacketRaw struct {
	Length int `json:"length"`
}

type tracePacket struct {
	Header tracePacketHeader `json:"header"`
	Raw    tracePacketRaw    `json:"raw"`
	Frames []traceFrame      `json:"frames,omitempty"`
}

type tracePacketLost struct {
	Header  tracePacketHeader `json:"header"`
	Trigger string            `json:"trigger"`
}

type tracePacketDropped struct {
	Header  tracePacketHeader `json:"header"`
	Raw     tracePacketRaw    `json:"raw"`
	Trigger string            `json:"trigger"`
}

type traceFrame struct {
	FrameType  string      `json:"frame_type"`
	Length     int         `json:"length"`
	StreamID   uint32      `json:"stream_id,omitempty"`
	Offset     uint64      `json:"offset,omitempty"`
	Fin        bool        `json:"fin,omitempty"`
	Maximum    uint64      `json:"maximum,omitempty"`
	StreamType string      `json:"stream_type,omitempty"`
	ErrorCode  int         `json:"error_code,omitempty"`
	FinalSize  uint64      `json:"final_size,omitempty"`
	AckDelay   float64     `json:"ack_delay,omitempty"`
	AckRanges  [][2]uint32 `json:"acked_ranges,omitempty"`
}

type traceMetrics struct {
	MinRTT               float64 `json:"min_rtt,omitempty"`
	SmoothedRTT          float64 `json:"smoothed_rtt,omitempty"`
	LatestRTT            float64 `json:"latest_rtt,omitempty"`
	RTTVariance          float64 `json:"rtt_variance,omitempty"`
	CongestionWindow     uint64  `json:"congestion_window,omitempty"`
	BytesInFlight        uint64  `json:"bytes_in_flight,omitempty"`
	PacketsInFlight      int     `json:"packets_in_flight,omitempty"`
	PTO                  float64 `json:"pto,omitempty"`
	ProbeCount           int     `json:"probe_count,omitempty"`
	BandwidthEstimate    uint64  `json:"bandwidth_estimate,omitempty"`
	PacingRate           uint64  `json:"pacing_rate,omitempty"`
	MaxAckHeight         uint64  `json:"max_ack_height,omitempty"`
	PacingGain           float64 `json:"pacing_gain,omitempty"`
	CongestionWindowGain float64 `json:"congestion_window_gain,omitempty"`
	AtFullBandwidth      bool    `json:"is_at_full_bandwidth,omitempty"`
}

type traceCongestionState struct {
	Old string `json:"old,omitempty"`
	New string `json:"new"`
}

type traceMTU struct {
	MTU int `json:"mtu"`
}

type traceMTUProbe struct {
	Candidate int  `json:"candidate"`
	Confirmed bool `json:"confirmed"`
}

type traceStream struct {
	StreamID  uint32 `json:"stream_id"`
	Initiator string `json:"initiator,omitempty"`
	FinalSize uint64 `json:"final_size,omitempty"`
}

type traceDatagram struct {
	Message   uint16 `json:"message"`
	Fragments int    `json:"fragments"`
	Length    int    `json:"length"`
}

type traceDatagramDrop struct {
	Message uint16 `json:"message"`
	Reason  string `json:"reason"`
}

type traceHello struct {
	Attempt int     `json:"attempt"`
	Length  int     `json:"length,omitempty"`
	Elapsed float64 `json:"elapsed,omitempty"`
	Reason  string  `json:"reason,omitempty"`
}

type traceClosed struct {
	Events  int `json:"events"`
	Dropped int `json:"dropped"`
	Bytes   int `json:"bytes"`
}

// traceFrameOf 把线上帧还原成 qlog 的 frame 对象。
func traceFrameOf(payload []byte) traceFrame {
	if len(payload) < frameHeaderLen {
		return traceFrame{FrameType: "unknown"}
	}
	frameType := payload[0]
	bodyLength := int(binary.BigEndian.Uint16(payload[1:3]))
	if bodyLength > len(payload)-frameHeaderLen {
		return traceFrame{FrameType: "unknown"}
	}
	body := payload[frameHeaderLen : frameHeaderLen+bodyLength]
	switch frameType & frameTypeMask {
	case frameTypePadding:
		return traceFrame{FrameType: "padding", Length: bodyLength}
	case frameTypePing:
		return traceFrame{FrameType: "ping"}
	case frameTypeClose:
		frame := traceFrame{FrameType: "connection_close"}
		if len(body) > 0 {
			frame.ErrorCode = int(body[0])
		}
		return frame
	case frameTypeAck:
		return traceAckFrame(body)
	case frameTypeStream:
		if len(body) < 12 {
			return traceFrame{FrameType: "stream"}
		}
		return traceFrame{
			FrameType: "stream",
			StreamID:  binary.BigEndian.Uint32(body),
			Offset:    binary.BigEndian.Uint64(body[4:]),
			Length:    len(body) - 12,
			Fin:       frameType&frameFlagFin != 0,
		}
	case frameTypeMaxData:
		if len(body) < 8 {
			return traceFrame{FrameType: "max_data"}
		}
		return traceFrame{FrameType: "max_data", Maximum: binary.BigEndian.Uint64(body)}
	case frameTypeMaxStreamData:
		if len(body) < 12 {
			return traceFrame{FrameType: "max_stream_data"}
		}
		return traceFrame{
			FrameType: "max_stream_data",
			StreamID:  binary.BigEndian.Uint32(body),
			Maximum:   binary.BigEndian.Uint64(body[4:]),
		}
	case frameTypeResetStream:
		if len(body) < 13 {
			return traceFrame{FrameType: "reset_stream"}
		}
		return traceFrame{
			FrameType: "reset_stream",
			StreamID:  binary.BigEndian.Uint32(body),
			FinalSize: binary.BigEndian.Uint64(body[4:]),
		}
	case frameTypeDatagram:
		if len(body) < 4 {
			return traceFrame{FrameType: "datagram"}
		}
		return traceFrame{FrameType: "datagram", Length: len(body) - 4}
	case frameTypeMaxStreams:
		if len(body) < 4 {
			return traceFrame{FrameType: "max_streams"}
		}
		return traceFrame{
			FrameType:  "max_streams",
			Maximum:    uint64(binary.BigEndian.Uint32(body)),
			StreamType: "bidirectional",
		}
	default:
		return traceFrame{FrameType: "unknown"}
	}
}

func traceAckFrame(body []byte) traceFrame {
	frame := traceFrame{FrameType: "ack", Length: len(body)}
	if len(body) < 7 {
		return frame
	}
	frame.AckDelay = traceMillis(time.Duration(binary.BigEndian.Uint16(body[4:])) * time.Microsecond)
	count := int(body[6])
	if count == 0 || len(body) < 7+count*8 {
		return frame
	}
	frame.AckRanges = make([][2]uint32, 0, count)
	for index := range count {
		start := binary.BigEndian.Uint32(body[7+index*8:])
		end := binary.BigEndian.Uint32(body[7+index*8+4:])
		frame.AckRanges = append(frame.AckRanges, [2]uint32{start, end})
	}
	return frame
}
