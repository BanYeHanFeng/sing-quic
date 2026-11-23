package quicx

import (
	"context"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-quic/udpx"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type ClientOptions struct {
	Context       context.Context
	Dialer        N.Dialer
	ServerAddress M.Socksaddr
	Password      string
	IdleTimeout   time.Duration
	Heartbeat     time.Duration

	MTU    int
	Logger logger.Logger
}

type Client struct {
	ctx        context.Context
	dialer     N.Dialer
	serverAddr M.Socksaddr
	password   udpx.Password
	transport  udpx.Options
	logger     logger.Logger

	connAccess sync.Mutex
	conn       *clientSession
	pending    *clientOffer
}

func NewClient(options ClientOptions) (*Client, error) {
	if options.Heartbeat == 0 {
		options.Heartbeat = 10 * time.Second
	}
	transportLogger := options.Logger
	if options.Logger == nil {
		options.Logger = logger.NOP()
	}
	return &Client{
		ctx:        options.Context,
		dialer:     options.Dialer,
		serverAddr: options.ServerAddress,
		password:   udpx.NewPassword(options.Password),
		transport: udpx.Options{
			IdleTimeout:     options.IdleTimeout,
			KeepAlivePeriod: options.Heartbeat,
			MTU:             options.MTU,
			Logger:          transportLogger,
		},
		logger: options.Logger,
	}, nil
}

var errPathQuiet = E.New("path quiet")

var errRetired = E.New("session retired")

const quietGrace = 6 * time.Second

func (c *Client) offer(ctx context.Context) (*clientSession, error) {
	c.connAccess.Lock()
	conn := c.conn
	if conn != nil && conn.active() {
		if conn.reachable() {
			c.connAccess.Unlock()
			return conn, nil
		}
		c.conn = nil
		conn.retire()
	}
	pending := c.pending
	if pending != nil {
		c.connAccess.Unlock()
		select {
		case <-pending.done:
			return pending.conn, pending.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	offerCtx := c.ctx
	if offerCtx == nil {
		offerCtx = context.Background()
	}
	offerCtx, cancel := context.WithCancelCause(offerCtx)
	pending = &clientOffer{
		done:   make(chan struct{}),
		cancel: cancel,
	}
	c.pending = pending
	c.connAccess.Unlock()

	go c.completeOffer(pending, offerCtx)

	select {
	case <-pending.done:
		return pending.conn, pending.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Client) completeOffer(pending *clientOffer, offerCtx context.Context) {
	conn, err := c.offerNew(offerCtx)
	pending.cancel(nil)

	discardErr := err
	shouldDiscard := false
	c.connAccess.Lock()
	if pending.discarded {
		shouldDiscard = true
		if pending.cause != nil {
			discardErr = pending.cause
		}
		pending.err = discardErr
	} else {
		pending.conn = conn
		pending.err = err
		if err == nil {
			c.conn = conn
		}
	}
	if c.pending == pending {
		c.pending = nil
	}
	close(pending.done)
	c.connAccess.Unlock()

	if shouldDiscard && conn != nil {
		conn.closeWithError(discardErr)
	}
}

func (c *Client) offerNew(ctx context.Context) (*clientSession, error) {
	dialStart := time.Now()
	udpConn, err := c.dialer.DialContext(ctx, "udp", c.serverAddr)
	if err != nil {
		c.logger.Error("QUICX dial failed: stage=dial transport=udp server=", c.serverAddr, " elapsed=", dialElapsed(dialStart), " error=", err)
		return nil, err
	}
	remote := udpConn.RemoteAddr()
	association, err := udpx.Dial(ctx, bindPacketConn(udpConn), remote, c.password, c.transport)
	if err != nil {
		_ = udpConn.Close()
		c.logger.Error("QUICX dial failed: stage=handshake server=", c.serverAddr, " remote=", remote, " elapsed=", dialElapsed(dialStart), " error=", err)
		return nil, E.Cause(err, "open session")
	}
	c.logger.Debug("QUICX dial: stage=handshake server=", c.serverAddr, " remote=", remote, " elapsed=", dialElapsed(dialStart))
	connCtx := c.ctx
	if connCtx == nil {
		connCtx = context.Background()
	}
	session := &clientSession{
		ctx:         connCtx,
		association: association,
		connDone:    make(chan struct{}),
		udpConnMap:  make(map[uint32]*udpPacketConn),
	}
	go c.loopMessages(session)
	go func() {
		<-association.Context().Done()
		cause := context.Cause(association.Context())
		session.closeWithError(cause)
		if isNormalSessionEnd(cause) {
			c.logger.Debug("QUICX session closed: server=", c.serverAddr, " remote=", remote, " elapsed=", dialElapsed(dialStart), " error=", cause)
		} else {
			c.logger.Error("QUICX session failed: server=", c.serverAddr, " remote=", remote, " elapsed=", dialElapsed(dialStart), " error=", cause)
		}
	}()
	return session, nil
}

func dialElapsed(start time.Time) time.Duration {
	return time.Since(start).Round(time.Millisecond)
}

func (c *Client) DialConn(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	session, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := session.association.OpenStream(ctx)
	if err != nil {
		return nil, E.Cause(err, "open stream")
	}
	session.workStarted()
	err = writeRequest(stream, destination)
	if err != nil {
		_ = stream.Close()
		session.workEnded()
		return nil, err
	}
	return &streamConn{stream: stream, destination: destination, onClose: session.workEnded}, nil
}

func writeRequest(stream *udpx.Stream, destination M.Socksaddr) error {
	request := buf.NewSize(2 + AddressSerializer.AddrPortLen(destination))
	defer request.Release()
	request.WriteByte(Version)
	request.WriteByte(CommandConnect)
	err := AddressSerializer.WriteAddrPort(request, destination)
	if err != nil {
		return E.Cause(err, "write request")
	}
	_, err = stream.Write(request.Bytes())
	if err != nil {
		return E.Cause(err, "write request")
	}
	return nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	session, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	session.udpAccess.Lock()
	select {
	case <-session.connDone:
		session.udpAccess.Unlock()
		return nil, E.Errors(session.connErr, os.ErrClosed)
	default:
	}
	sessionID := session.udpSessionID
	session.udpSessionID++
	session.workStarted()
	packetConn := newUDPPacketConn(c.ctx, session.association, sessionID, false, func() {
		session.udpAccess.Lock()
		delete(session.udpConnMap, sessionID)
		session.udpAccess.Unlock()
		session.workEnded()
	})
	session.udpConnMap[sessionID] = packetConn
	session.udpAccess.Unlock()
	return packetConn, nil
}

func (c *Client) CloseWithError(err error) error {
	c.connAccess.Lock()
	conn := c.conn
	c.conn = nil
	pending := c.pending
	if pending != nil {
		pending.discarded = true
		pending.cause = err
	}
	c.connAccess.Unlock()

	if pending != nil {
		pending.cancel(err)
	}
	if conn != nil {
		conn.closeWithError(err)
	}
	return nil
}

type clientOffer struct {
	done      chan struct{}
	cancel    func(error)
	conn      *clientSession
	err       error
	discarded bool
	cause     error
}

type clientSession struct {
	ctx          context.Context
	association  udpx.Association
	closeOnce    sync.Once
	connDone     chan struct{}
	connErr      error
	udpAccess    sync.RWMutex
	udpConnMap   map[uint32]*udpPacketConn
	udpSessionID uint32
	workAccess   sync.Mutex
	work         int
	retired      bool
	retireOnce   sync.Once
}

func (c *clientSession) active() bool {
	select {
	case <-c.connDone:
		return false
	default:
	}
	return !common.Done(c.association.Context())
}

func (c *clientSession) reachable() bool {
	return c.association.Reachable()
}

func (c *clientSession) retire() {
	c.retireOnce.Do(func() {
		c.workAccess.Lock()
		c.retired = true
		work := c.work
		c.workAccess.Unlock()
		if work == 0 {
			c.dropQuiet()
			return
		}
		time.AfterFunc(quietGrace, c.quietExpired)
	})
}

func (c *clientSession) quietExpired() {
	if c.reachable() {
		return
	}
	c.dropQuiet()
}

func (c *clientSession) workStarted() {
	c.workAccess.Lock()
	c.work++
	c.workAccess.Unlock()
}

func (c *clientSession) workEnded() {
	c.workAccess.Lock()
	c.work--
	done := c.retired && c.work == 0
	c.workAccess.Unlock()
	if done {
		go c.closeWithError(errRetired)
	}
}

func (c *clientSession) dropQuiet() {
	go c.closeWithError(errPathQuiet)
}

func (c *clientSession) closeWithError(err error) {
	c.closeOnce.Do(func() {
		c.connErr = err
		c.udpAccess.Lock()
		close(c.connDone)
		udpConnMap := c.udpConnMap
		c.udpConnMap = make(map[uint32]*udpPacketConn)
		c.udpAccess.Unlock()
		for _, udpConn := range udpConnMap {
			udpConn.closeWithError(err)
		}
		_ = c.association.CloseWithError(err)
	})
}
