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

// ClientOptions are what a client is built from. Authentication is the password:
// it proves the account to the server without ever being sent, in the handshake
// the transport runs before the first stream exists.
type ClientOptions struct {
	Context       context.Context
	Dialer        N.Dialer
	ServerAddress M.Socksaddr
	Password      string
	IdleTimeout   time.Duration
	Heartbeat     time.Duration

	// FEC protects what this client sends, which is the direction its requests
	// travel in: a lost packet that the redundancy replaces does not cost a round
	// trip of the request it belongs to.
	FEC udpx.FECOptions
	// Logger receives the dial diagnostics. A failed dial is otherwise only
	// visible as a generic error to the caller, which cannot tell whether the
	// address failed to resolve, the handshake timed out, or the server
	// rejected the authentication.
	Logger logger.Logger
}

// Client is the client side of QUICX: it keeps one session to the server and
// multiplexes every proxied connection and packet connection on it, because a
// session is a handshake and a handshake is a password hash.
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
	if options.Logger == nil {
		options.Logger = logger.NOP()
	}
	return &Client{
		ctx:        options.Context,
		dialer:     options.Dialer,
		serverAddr: options.ServerAddress,
		password:   udpx.NewPassword(options.Password),
		transport: udpx.Options{
			IdleTimeout: options.IdleTimeout,
			// The heartbeat option is what keeps a NAT mapping open, which in
			// this protocol is exactly what the keepalive of the transport does:
			// a ping the peer acknowledges.
			KeepAlivePeriod: options.Heartbeat,
			FEC:             options.FEC,
		},
		logger: options.Logger,
	}, nil
}

// offer returns the session to use, dialing one if there is none. Concurrent
// callers share one attempt: a second handshake to the same server while the
// first is running is a password hash nobody waits for.
func (c *Client) offer(ctx context.Context) (*clientSession, error) {
	c.connAccess.Lock()
	conn := c.conn
	if conn != nil && conn.active() {
		c.connAccess.Unlock()
		return conn, nil
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
	// A pending offer is shared by concurrent callers. Do not derive offerCtx
	// from the foreground request ctx: a timed-out request must stop waiting for
	// the shared result, but it must not tear down the background dial that may
	// still be reused by later requests. The connection attempt is owned by the
	// client lifetime context instead.
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
		// The dialer resolves the configured server address itself, so this
		// stage covers resolving the address and setting up the UDP socket;
		// the error tells which of the two failed. It is logged because the
		// caller only sees a generic dial failure, which is what made an
		// unreachable path indistinguishable from a rejecting server.
		c.logger.Error("QUICX dial failed: stage=dial transport=udp server=", c.serverAddr, " elapsed=", dialElapsed(dialStart), " error=", err)
		return nil, err
	}
	remote := udpConn.RemoteAddr()
	// The dialer hands back a connection to the server: a connected UDP socket,
	// or whatever a proxy chain gave it. The transport addresses a session by the
	// socket it runs on, so the one destination this connection has is what its
	// writes go to and what its reads come from.
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

// dialElapsed rounds a dial timing to milliseconds: the diagnostics are meant to
// be read from a log file, where sub-millisecond precision is noise.
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
	err = writeRequest(stream, destination)
	if err != nil {
		// One connection which cannot be opened is one connection: the others
		// multiplexed on this session run beside it.
		_ = stream.Close()
		return nil, err
	}
	return &streamConn{stream: stream, destination: destination}, nil
}

// writeRequest sends the request that starts a proxied connection: which version
// and command this is, and where the connection goes. It is the first thing on
// the stream, because the server cannot connect anywhere before it read it.
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
	// The channel number is chosen before the connection is published, so that
	// the destroy callback captures a value which is never reassigned
	// afterwards.
	sessionID := session.udpSessionID
	session.udpSessionID++
	packetConn := newUDPPacketConn(c.ctx, session.association, sessionID, false, func() {
		session.udpAccess.Lock()
		delete(session.udpConnMap, sessionID)
		session.udpAccess.Unlock()
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

// clientSession is one session as the client keeps it: the association, the
// packet connections multiplexed on it, and the reason it ended.
type clientSession struct {
	ctx          context.Context
	association  udpx.Association
	closeOnce    sync.Once
	connDone     chan struct{}
	connErr      error
	udpAccess    sync.RWMutex
	udpConnMap   map[uint32]*udpPacketConn
	udpSessionID uint32
}

// active reports whether the session can still be used, which is what decides
// whether the next connection dials a new one.
func (c *clientSession) active() bool {
	select {
	case <-c.connDone:
		return false
	default:
	}
	return !common.Done(c.association.Context())
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
