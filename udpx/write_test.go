package udpx

import (
	"errors"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-quic/udpio"
	"github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
)

type captureLogger struct {
	logger.Logger
	mu       sync.Mutex
	messages []string
}

func (l *captureLogger) Trace(args ...any) { l.record(args...) }
func (l *captureLogger) Debug(args ...any) { l.record(args...) }
func (l *captureLogger) Info(args ...any)  { l.record(args...) }

func (l *captureLogger) record(args ...any) {
	message := format.ToString(args...)
	l.mu.Lock()
	l.messages = append(l.messages, message)
	l.mu.Unlock()
}

func (l *captureLogger) lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.messages)
}

type failingIO struct {
	conn     *fakeConn
	mu       sync.Mutex
	failures int
	err      error
}

func (c *failingIO) WritePackets(packets []udpio.Packet) error {
	c.mu.Lock()
	if c.failures > 0 {
		c.failures--
		err := c.err
		c.mu.Unlock()
		return err
	}
	c.mu.Unlock()
	for _, packet := range packets {
		if _, err := c.conn.WriteTo(packet.Data, packet.Addr); err != nil {
			return err
		}
	}
	return nil
}

func (c *failingIO) ReadPackets([][]byte) ([]udpio.Packet, error) {
	return nil, net.ErrClosed
}

func (c *failingIO) LocalAddr() net.Addr { return c.conn.LocalAddr() }

func (c *failingIO) Offload() (bool, bool) { return false, false }

func TestWriteFailedLogsSizes(t *testing.T) {
	a := newTestAssociation(t, newFakeConn())
	capture := &captureLogger{}
	a.logger = capture
	packet := &sentPacket{packetNumber: 1, size: 1200, ackEliciting: true}
	a.flightMu.Lock()
	a.inFlight.append(packet)
	a.flightMu.Unlock()
	a.writeFailed([]pendingPacket{{sent: packet}}, errors.New("socket refused"))
	lines := capture.lines()
	if len(lines) == 0 {
		t.Fatal("write failure was not logged")
	}
	if !strings.Contains(lines[0], "write failed") || !strings.Contains(lines[0], "1200") {
		t.Fatalf("log line %q", lines[0])
	}
}

func TestWriteTooLongStepsDownMTU(t *testing.T) {
	conn := newFakeConn()
	a := newTestAssociation(t, conn)
	a.batchIO = &failingIO{conn: conn, failures: 1, err: os.NewSyscallError("sendmsg", syscall.EMSGSIZE)}
	a.sendMu.Lock()
	a.mtu = 1352
	a.updatePayloadLocked()
	a.sendMu.Unlock()
	a.queueFrame(appendStream(nil, 1, 0, false, []byte("hello")))
	if err := a.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	a.sendMu.Lock()
	mtu := a.mtu
	a.sendMu.Unlock()
	if mtu != 1232 {
		t.Fatalf("mtu is %d, want 1232", mtu)
	}
	deadline := time.Now().Add(time.Second)
	for {
		a.sendMu.Lock()
		queued := a.queue.len()
		a.sendMu.Unlock()
		if queued == 0 && conn.len() == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d frames queued and %d packets written after the retry", queued, conn.len())
		}
		time.Sleep(time.Millisecond)
	}
	if a.ctx.Err() != nil {
		t.Fatal("association closed on a size the path refused")
	}
}

func TestWriteTooLongAtSmallestMTU(t *testing.T) {
	conn := newFakeConn()
	a := newTestAssociation(t, conn)
	a.batchIO = &failingIO{conn: conn, failures: 1, err: os.NewSyscallError("sendmsg", syscall.EMSGSIZE)}
	a.queueFrame(appendStream(nil, 1, 0, false, []byte("hello")))
	if err := a.flush(); err == nil {
		t.Fatal("a write the path refused at the smallest size was not reported")
	}
	select {
	case <-a.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("association did not close")
	}
}
