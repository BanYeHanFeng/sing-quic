package udpx

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-quic/udpx/internal/udpio"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

var ErrIdleTimeout = E.New("udpx: idle timeout")

var ErrProbeTimeout = E.New("udpx: probe timeout")

func IsNormalClose(err error) bool {
	if err == nil || E.IsClosedOrCanceled(err) {
		return true
	}
	return errors.Is(err, net.ErrClosed) ||
		errors.Is(err, ErrIdleTimeout) ||
		errors.Is(err, ErrProbeTimeout)
}

const (
	maxPacketSize = 1452

	maxReceiveSize = 64 * 1024

	defaultIdleTimeout = 30 * time.Second

	helloRetransmitInterval = 250 * time.Millisecond

	defaultHandshakeTimeout = 10 * time.Second

	writeDrainTimeout = 100 * time.Millisecond
)

type Options struct {
	IdleTimeout time.Duration

	KeepAlivePeriod time.Duration

	MTU int

	Logger logger.Logger

	Trace TraceOptions

	// NewHandler 必填：每条连接在握手成功之后、收发循环启动之前被调用一次。
	// 返回 nil 表示拒绝这条连接。
	NewHandler func(conn *Conn) Handler
}

func (o Options) withDefaults() Options {
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = defaultIdleTimeout
	}
	if o.KeepAlivePeriod < 0 {
		o.KeepAlivePeriod = 0
	}
	if o.Logger == nil {
		o.Logger = logger.NOP()
	}
	return o
}

// Handler 接收连接上发生的事件。
//
// OnDatagram 在接收循环上调用，data 的所有权转移给 handler，不得阻塞。
// OnStream 每条入站流在新 goroutine 上调用。
// OnClose 在连接结束后恰好调用一次，可能与上面两者并发。
type Handler interface {
	OnDatagram(conn *Conn, data []byte)
	OnStream(conn *Conn, stream *Stream)
	OnClose(conn *Conn, cause error)
}

type Conn struct {
	socket     net.PacketConn
	io         udpio.Conn
	ownsSocket bool
	options    Options
	logger     logger.Logger
	logTag     string
	tracer     *tracer
	handler    Handler
	initiator  bool

	localID    connectionID
	peerID     connectionID
	keyID      [keyIDLen]byte
	sendCipher packetCipher
	recvCipher packetCipher

	ctx        context.Context
	cancel     context.CancelCauseFunc
	finishMu   sync.Mutex
	finished   bool
	finishDone chan struct{}
	sendDone   chan struct{}
	sendWake   chan struct{}

	peerAddr     atomic.Pointer[net.Addr]
	openStreams  atomic.Int32 // 供发送循环的空闲判定读取
	closedByPeer atomic.Bool  // 收到对端 CLOSE 帧时置位，只用于 trace

	sendMu sync.Mutex
	send   sender

	streamsMu sync.Mutex
	streams   map[uint32]*Stream
	outbound  outboundStreamGate
	inbound   inboundStreamGate

	defragger datagramDefragger // 只有接收循环访问

	onClose func() // 内部收尾钩子，供 Listener 把连接移出表
}

func newConn(socket net.PacketConn, io udpio.Conn, result handshakeResult, peer net.Addr, options Options, initiator bool, trace *tracer) *Conn {
	ctx, cancel := context.WithCancelCause(context.Background())
	options = options.withDefaults()
	if trace == nil {
		trace = newTracer(options.Trace.Dir, "server", result.peerID, options.Trace.Capacity, options.Logger)
	}
	c := &Conn{
		logTag:     hex.EncodeToString(result.localID[:2]),
		socket:     socket,
		io:         io,
		options:    options,
		logger:     options.Logger,
		tracer:     trace,
		initiator:  initiator,
		localID:    result.localID,
		peerID:     result.peerID,
		keyID:      result.keyID,
		sendCipher: result.send,
		recvCipher: result.recv,
		ctx:        ctx,
		cancel:     cancel,
		finishDone: make(chan struct{}),
		sendWake:   make(chan struct{}, 1),
		sendDone:   make(chan struct{}),
		streams:    make(map[uint32]*Stream),
		outbound: outboundStreamGate{
			credit:     initialStreams,
			creditWait: make(chan struct{}),
		},
		inbound: inboundStreamGate{
			limit:   initialStreams,
			skipped: make(map[uint32]struct{}),
		},
		defragger: newDatagramDefragger(trace),
	}
	c.peerAddr.Store(&peer)
	mtu := mtuMin
	if options.MTU > 0 {
		mtu = max(mtuMin, min(options.MTU, maxPacketSize))
	}
	c.send.init(c, mtu)
	role := "server"
	if initiator {
		role = "client"
	}
	c.tracer.record("udpx:connection_started", traceConnectionStarted{
		Role:        role,
		LocalID:     c.localID.String(),
		PeerID:      c.peerID.String(),
		Remote:      peer.String(),
		MTU:         mtu,
		Version:     version,
		IdleTimeout: traceMillis(options.IdleTimeout),
		KeepAlive:   traceMillis(options.KeepAlivePeriod),
	})
	fields := []any{"connection up local=", c.logTag,
		" client=", initiator, " remote=", peer, " mtu=", mtu}
	if trace != nil {
		fields = append(fields, " trace=", trace.path)
	}
	c.logDebug(fields...)
	return c
}

// Trace 记录一条自定义 qlog 事件，未开启 trace 时为空操作。
func (c *Conn) Trace(name string, data any) {
	c.tracer.record(name, data)
}

func (c *Conn) logDebug(args ...any) {
	c.logger.Debug(append([]any{"udpx[" + c.logTag + "]: "}, args...)...)
}

func (c *Conn) LocalAddr() net.Addr {
	return c.socket.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return *c.peerAddr.Load()
}

func (c *Conn) Context() context.Context {
	return c.ctx
}

func (c *Conn) KeyID() [keyIDLen]byte {
	return c.keyID
}

func (c *Conn) CloseWithError(err error) error {
	c.shutdown(err, true)
	return nil
}

// fail 记录致命原因并可选地通知对端。幂等，不等待。
func (c *Conn) fail(cause error, notifyPeer bool) {
	c.sendMu.Lock()
	changed := c.send.fail(cause, notifyPeer)
	c.sendMu.Unlock()
	if changed {
		c.wake()
	}
}

// cause 本次连接结束的原因。
func (c *Conn) cause() error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if c.send.cause != nil {
		return c.send.cause
	}
	return net.ErrClosed
}

// finish 取消 ctx、结束所有流、释放 socket、通知 handler，恰好执行一次。
// 后来的调用者会在收尾完成后再返回，OnClose 因此可能晚于 CloseWithError，
// 但 OnClose 里再调 CloseWithError 也不会自锁。
func (c *Conn) finish(cause error) {
	c.finishMu.Lock()
	if c.finished {
		done := c.finishDone
		c.finishMu.Unlock()
		<-done
		return
	}
	c.finished = true
	c.finishMu.Unlock()
	if cause == nil {
		cause = net.ErrClosed
	}
	c.logDebug("connection closed: ", cause)
	trigger, code := traceCloseOf(cause)
	initiator := "local"
	if c.closedByPeer.Load() {
		initiator = "remote"
	}
	c.tracer.record("transport:connection_closed", traceConnectionClosed{
		Initiator: initiator,
		Trigger:   trigger,
		ErrorCode: int(code),
		Reason:    cause.Error(),
	})
	c.cancel(cause)
	c.closeStreams(cause)
	if c.ownsSocket {
		_ = c.socket.Close()
	}
	if c.onClose != nil {
		c.onClose()
	}
	c.tracer.close()
	close(c.finishDone)
	if c.handler != nil {
		c.handler.OnClose(c, cause)
	}
}

// finishFromLoop 发送循环排空自己的队列后收尾。
func (c *Conn) finishFromLoop() {
	c.finish(c.cause())
}

// shutdown 外部关闭：先通知对端，给它一点时间发出 CLOSE，然后收尾。
func (c *Conn) shutdown(cause error, notifyPeer bool) {
	c.fail(cause, notifyPeer)
	select {
	case <-c.sendDone:
	case <-time.After(writeDrainTimeout):
	}
	c.finish(c.cause())
}

func (c *Conn) closeStreams(cause error) {
	c.streamsMu.Lock()
	streams := make([]*Stream, 0, len(c.streams))
	for _, stream := range c.streams {
		streams = append(streams, stream)
	}
	c.streams = make(map[uint32]*Stream)
	c.streamsMu.Unlock()
	for _, stream := range streams {
		stream.end(cause)
	}
}

func (c *Conn) wake() {
	select {
	case c.sendWake <- struct{}{}:
	default:
	}
}

func Dial(ctx context.Context, socket net.PacketConn, remote net.Addr, credential Credential, options Options) (*Conn, error) {
	if options.NewHandler == nil {
		return nil, E.New("missing NewHandler")
	}
	if _, loaded := ctx.Deadline(); !loaded {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultHandshakeTimeout)
		defer cancel()
	}
	handshake, err := newClientHandshake(credential)
	if err != nil {
		return nil, err
	}
	trace := newTracer(options.Trace.Dir, "client", handshake.connID, options.Trace.Capacity, options.Logger)
	result, err := exchangeHello(ctx, socket, remote, handshake, trace)
	if err != nil {
		trace.record("udpx:handshake_failed", traceHello{Reason: err.Error()})
		trace.record("transport:connection_closed", traceConnectionClosed{
			Initiator: "local",
			Trigger:   "handshake_failed",
			Reason:    err.Error(),
		})
		trace.close()
		return nil, err
	}
	c := newConn(socket, udpio.New(socket), result, remote, options, true, trace)
	c.ownsSocket = true
	c.handler = options.NewHandler(c)
	if c.handler == nil {
		rejected := E.New("the handler rejected the connection")
		c.finish(rejected)
		return nil, rejected
	}
	go c.sendLoop()
	go c.recvLoop()
	return c, nil
}

func exchangeHello(ctx context.Context, socket net.PacketConn, remote net.Addr, handshake *clientHandshake, trace *tracer) (handshakeResult, error) {
	buffer := make([]byte, maxPacketSize)
	hello := handshake.hello()
	attempt := 0
	for {
		attempt++
		sentAt := time.Now()
		_, err := socket.WriteTo(hello, remote)
		if err != nil {
			return handshakeResult{}, E.Cause(err, "write hello")
		}
		trace.record("udpx:hello_sent", traceHello{Attempt: attempt, Length: len(hello)})
		deadline := sentAt.Add(helloRetransmitInterval)
		if contextDeadline, loaded := ctx.Deadline(); loaded && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		err = socket.SetReadDeadline(deadline)
		if err != nil {
			return handshakeResult{}, E.Cause(err, "set read deadline")
		}
		for {
			n, source, readErr := socket.ReadFrom(buffer)
			if readErr != nil {
				select {
				case <-ctx.Done():
					return handshakeResult{}, context.Cause(ctx)
				default:
				}
				if isTimeout(readErr) {
					break
				}
				return handshakeResult{}, E.Cause(readErr, "read hello answer")
			}
			if source.String() != remote.String() {
				continue
			}
			packetHeader, parseErr := parseHeader(buffer[:n])
			if parseErr != nil || packetHeader.Type != packetTypeHandshake {
				continue
			}
			result, handleErr := handshake.handleResponse(buffer[:n])
			if handleErr != nil {
				continue
			}
			trace.record("udpx:hello_received", traceHello{Attempt: attempt, Elapsed: traceMillis(time.Since(sentAt))})
			err = socket.SetReadDeadline(time.Time{})
			if err != nil {
				return handshakeResult{}, E.Cause(err, "clear read deadline")
			}
			return result, nil
		}
	}
}

func (c *Conn) recvLoop() {
	buffer := make([]byte, maxReceiveSize)
	for {
		packet, err := c.io.ReadPacket(buffer)
		if err != nil {
			if c.ctx.Err() != nil {
				return
			}
			if isClosed(err) {
				c.shutdown(err, false)
				return
			}
			continue
		}
		packet.ForEach(func(datagram []byte) {
			_ = c.handlePacket(datagram, packet.Addr)
		})
	}
}

func isTimeout(err error) bool {
	netErr, isNetErr := err.(net.Error)
	return isNetErr && netErr.Timeout()
}

func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed)
}
