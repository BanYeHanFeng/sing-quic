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
}

func (o Options) withDefaults() Options {
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = defaultIdleTimeout
	}
	if o.KeepAlivePeriod < 0 {
		o.KeepAlivePeriod = 0
	}
	return o
}

type Conn struct {
	socket    net.PacketConn
	io        udpio.Conn
	options   Options
	logger    logger.Logger
	logTag    string
	initiator bool

	localID    connectionID
	peerID     connectionID
	keyID      [keyIDLen]byte
	sendCipher packetCipher
	recvCipher packetCipher

	ctx    context.Context
	cancel context.CancelCauseFunc

	peerAddr    atomic.Pointer[net.Addr]
	openStreams atomic.Int32 // 供发送循环的空闲判定读取

	sendMu    sync.Mutex
	send      sender
	sendWake  chan struct{}
	sendDone  chan struct{}
	closeOnce sync.Once

	streamsMu sync.Mutex
	streams   streamTable

	datagramMessage atomic.Uint32
	defragger       datagramDefragger
	datagrams       chan Datagram

	onClose func()
}

func newConn(conn net.PacketConn, io udpio.Conn, result handshakeResult, peer net.Addr, options Options, initiator bool) *Conn {
	ctx, cancel := context.WithCancelCause(context.Background())
	if options.Logger == nil {
		options.Logger = logger.NOP()
	}
	c := &Conn{
		logTag:     hex.EncodeToString(result.localID[:2]),
		socket:     conn,
		io:         io,
		options:    options.withDefaults(),
		logger:     options.Logger,
		initiator:  initiator,
		localID:    result.localID,
		peerID:     result.peerID,
		keyID:      result.keyID,
		sendCipher: result.send,
		recvCipher: result.recv,
		ctx:        ctx,
		cancel:     cancel,
		sendWake:   make(chan struct{}, 1),
		sendDone:   make(chan struct{}),
		streams:    newStreamTable(initiator),
		defragger:  newDatagramDefragger(),
		datagrams:  make(chan Datagram, datagramBacklog),
	}
	c.peerAddr.Store(&peer)
	mtu := mtuMin
	if options.MTU > 0 {
		mtu = max(mtuMin, min(options.MTU, maxPacketSize))
	}
	c.send.init(c, mtu)
	c.logDebug("connection up local=", c.logTag,
		" client=", initiator, " remote=", peer, " mtu=", mtu)
	return c
}

func (c *Conn) logDebug(args ...any) {
	c.logger.Debug(append([]any{"udpx[" + c.logTag + "]: "}, args...)...)
}

func (c *Conn) start() {
	go c.sendLoop()
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

// finish 取消 ctx、结束所有流、释放 socket、通知关闭，恰好执行一次。
func (c *Conn) finish(cause error) {
	c.closeOnce.Do(func() {
		if cause == nil {
			cause = net.ErrClosed
		}
		c.cancel(cause)
		if c.initiator {
			_ = c.socket.SetReadDeadline(time.Now())
		}
		c.closeStreams(cause)
		if c.onClose != nil {
			c.onClose()
		}
	})
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
	streams := make([]*Stream, 0, len(c.streams.table))
	for _, stream := range c.streams.table {
		streams = append(streams, stream)
	}
	c.streams.table = make(map[uint32]*Stream)
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

func Dial(ctx context.Context, conn net.PacketConn, remote net.Addr, credential Credential, options Options) (*Conn, error) {
	if _, loaded := ctx.Deadline(); !loaded {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultHandshakeTimeout)
		defer cancel()
	}
	handshake, err := newClientHandshake(credential)
	if err != nil {
		return nil, err
	}
	result, err := exchangeHello(ctx, conn, remote, handshake)
	if err != nil {
		return nil, err
	}
	io := udpio.New(conn)
	c := newConn(conn, io, result, remote, options, true)
	c.start()
	go c.recvLoop()
	return c, nil
}

func exchangeHello(ctx context.Context, conn net.PacketConn, remote net.Addr, handshake *clientHandshake) (handshakeResult, error) {
	buffer := make([]byte, maxPacketSize)
	hello := handshake.hello()
	for {
		_, err := conn.WriteTo(hello, remote)
		if err != nil {
			return handshakeResult{}, E.Cause(err, "write hello")
		}
		deadline := time.Now().Add(helloRetransmitInterval)
		if contextDeadline, loaded := ctx.Deadline(); loaded && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		err = conn.SetReadDeadline(deadline)
		if err != nil {
			return handshakeResult{}, E.Cause(err, "set read deadline")
		}
		for {
			n, source, readErr := conn.ReadFrom(buffer)
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
			err = conn.SetReadDeadline(time.Time{})
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
