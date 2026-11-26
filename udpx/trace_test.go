package udpx

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

type tracedRecord struct {
	Time float64         `json:"time"`
	Name string          `json:"name"`
	Data json.RawMessage `json:"data"`
}

func readTrace(t *testing.T, dir string, vantage string) (traceFileHeader, []tracedRecord) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, vantage+"-*.sqlog"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected one %s trace file in %s, got %v", vantage, dir, matches)
	}
	content, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	var chunks [][]byte
	for _, chunk := range bytes.Split(content, []byte{traceRecordSeparator}) {
		if len(bytes.TrimSpace(chunk)) > 0 {
			chunks = append(chunks, chunk)
		}
	}
	if len(chunks) < 2 {
		t.Fatalf("trace file %s has %d records", matches[0], len(chunks))
	}
	var header traceFileHeader
	err = json.Unmarshal(chunks[0], &header)
	if err != nil {
		t.Fatalf("parse header of %s: %v", matches[0], err)
	}
	records := make([]tracedRecord, 0, len(chunks)-1)
	for _, chunk := range chunks[1:] {
		var record tracedRecord
		err = json.Unmarshal(chunk, &record)
		if err != nil {
			t.Fatalf("parse record %q: %v", chunk, err)
		}
		records = append(records, record)
	}
	return header, records
}

func traceNames(records []tracedRecord) map[string]int {
	names := make(map[string]int)
	for _, record := range records {
		names[record.Name]++
	}
	return names
}

func tracePackets(t *testing.T, records []tracedRecord, eventName string) []tracePacket {
	t.Helper()
	var packets []tracePacket
	for _, record := range records {
		if record.Name != eventName {
			continue
		}
		var packet tracePacket
		err := json.Unmarshal(record.Data, &packet)
		if err != nil {
			t.Fatalf("parse %s: %v", eventName, err)
		}
		packets = append(packets, packet)
	}
	return packets
}

func requireTraces(t *testing.T, records []tracedRecord, names ...string) {
	t.Helper()
	counts := traceNames(records)
	for _, name := range names {
		if counts[name] == 0 {
			t.Fatalf("the trace has no %s event, only %v", name, counts)
		}
	}
}

func TestTraceWritesQLog(t *testing.T) {
	dir := t.TempDir()
	client, server, listener := testSetup(t, Options{MTU: mtuIPv4, Trace: TraceOptions{Dir: dir}}, Options{MTU: mtuIPv4, Trace: TraceOptions{Dir: dir}})
	ctx := testContext(t, 10*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload(4096)
	_, err = stream.Write(payload)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, accepted, len(payload))
	err = client.SendDatagram([]byte("query"))
	if err != nil {
		t.Fatal(err)
	}
	datagram, err := server.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(datagram) != "query" {
		t.Fatalf("the datagram arrived as %q", datagram)
	}
	_ = stream.Close()
	_ = accepted.Close()
	_ = client.CloseWithError(nil)
	_ = server.CloseWithError(nil)
	_ = listener.Close()

	clientHeader, clientRecords := readTrace(t, dir, "client")
	serverHeader, serverRecords := readTrace(t, dir, "server")
	if clientHeader.QlogFormat != "JSON-SEQ" || clientHeader.QlogVersion != "0.3" {
		t.Fatalf("the client trace declares %s %s", clientHeader.QlogFormat, clientHeader.QlogVersion)
	}
	if clientHeader.Trace.VantagePoint.Type != "client" || serverHeader.Trace.VantagePoint.Type != "server" {
		t.Fatalf("the traces are from %q and %q", clientHeader.Trace.VantagePoint.Type, serverHeader.Trace.VantagePoint.Type)
	}
	if clientHeader.Trace.CommonFields.GroupID != serverHeader.Trace.CommonFields.GroupID {
		t.Fatalf("the traces are grouped as %q and %q", clientHeader.Trace.CommonFields.GroupID, serverHeader.Trace.CommonFields.GroupID)
	}
	requireTraces(t, clientRecords,
		"udpx:hello_sent",
		"udpx:hello_received",
		"udpx:connection_started",
		"udpx:stream_opened",
		"udpx:datagram_sent",
		"transport:packet_sent",
		"transport:packet_received",
		"transport:connection_closed",
	)
	requireTraces(t, serverRecords,
		"udpx:connection_started",
		"udpx:stream_opened",
		"udpx:datagram_received",
		"transport:packet_sent",
		"transport:packet_received",
		"transport:connection_closed",
	)
	sentFrames := make(map[string]int)
	for _, packet := range tracePackets(t, clientRecords, "transport:packet_sent") {
		for _, frame := range packet.Frames {
			sentFrames[frame.FrameType]++
		}
	}
	if sentFrames["stream"] == 0 || sentFrames["datagram"] == 0 {
		t.Fatalf("the client sent frames %v", sentFrames)
	}
	serverFrames := make(map[string]int)
	for _, packet := range tracePackets(t, serverRecords, "transport:packet_sent") {
		for _, frame := range packet.Frames {
			serverFrames[frame.FrameType]++
		}
	}
	if serverFrames["ack"] == 0 {
		t.Fatalf("the server sent frames %v", serverFrames)
	}
	var closed traceConnectionClosed
	for _, record := range clientRecords {
		if record.Name == "transport:connection_closed" {
			err = json.Unmarshal(record.Data, &closed)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if closed.Trigger != "clean" {
		t.Fatalf("the client closed with trigger %q", closed.Trigger)
	}
	for _, record := range clientRecords {
		if record.Time < 0 || record.Time > time.Minute.Seconds()*1000 {
			t.Fatalf("the event %s is at %f", record.Name, record.Time)
		}
	}
}

func TestTraceFrameOf(t *testing.T) {
	streamFrame := appendStreamHeader(nil, 3, 1024, true, 10)
	streamFrame = append(streamFrame, make([]byte, 10)...)
	frame := traceFrameOf(streamFrame)
	if frame.FrameType != "stream" || frame.StreamID != 3 || frame.Offset != 1024 || frame.Length != 10 || !frame.Fin {
		t.Fatalf("the stream frame decoded as %+v", frame)
	}
	datagramFrame := appendDatagramHeader(nil, 7, 0, 1, 4)
	datagramFrame = append(datagramFrame, 1, 2, 3, 4)
	frame = traceFrameOf(datagramFrame)
	if frame.FrameType != "datagram" || frame.Length != 4 {
		t.Fatalf("the datagram frame decoded as %+v", frame)
	}
	frame = traceFrameOf(appendMaxDataFrame(nil, 65536))
	if frame.FrameType != "max_data" || frame.Maximum != 65536 {
		t.Fatalf("the max_data frame decoded as %+v", frame)
	}
	frame = traceFrameOf([]byte{frameTypePing, 0, 0})
	if frame.FrameType != "ping" {
		t.Fatalf("the ping frame decoded as %+v", frame)
	}
}

func TestTraceCapacityLimit(t *testing.T) {
	dir := t.TempDir()
	current := newTracer(dir, "client", connectionID{1}, 1, logger.NOP())
	if current == nil {
		t.Fatal("the tracer was not created")
	}
	padding := strings.Repeat("x", 64<<10)
	for range 40 {
		current.record("udpx:test", struct {
			Padding string `json:"padding"`
		}{Padding: padding})
	}
	current.close()
	info, err := os.Stat(current.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > 1<<20+4096 {
		t.Fatalf("the trace file grew to %d bytes", info.Size())
	}
	_, records := readTrace(t, dir, "client")
	last := records[len(records)-1]
	if last.Name != "udpx:trace_closed" {
		t.Fatalf("the trace ends with %s", last.Name)
	}
	var closed traceClosed
	err = json.Unmarshal(last.Data, &closed)
	if err != nil {
		t.Fatal(err)
	}
	if closed.Bytes < (1<<20)*9/10 {
		t.Fatalf("the trace stopped at %d bytes", closed.Bytes)
	}
	if closed.Dropped == 0 {
		t.Fatal("the trace dropped no event")
	}
}
