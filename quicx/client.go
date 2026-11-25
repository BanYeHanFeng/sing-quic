package quicx

import (
	"context"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/sing-quic/udpx"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/sync/singleflight"
)

var errNetworkChanged = E.New("network changed")

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
	credential udpx.Credential
	transport  udpx.Options
	logger     logger.Logger

	access     sync.Mutex
	session    *session
	generation uint64
	closed     bool
	dialGroup  singleflight.Group
}

func NewClient(options ClientOptions) (*Client, error) {
	if options.Context == nil {
		options.Context = context.Background()
	}
	if options.Logger == nil {
		options.Logger = logger.NOP()
	}
	if options.Dialer == nil {
		return nil, E.New("missing dialer")
	}
	if !options.ServerAddress.IsValid() {
		return nil, E.New("missing server address")
	}
	if options.Password == "" {
		return nil, E.New("missing password")
	}
	return &Client{
		ctx:        options.Context,
		dialer:     options.Dialer,
		serverAddr: options.ServerAddress,
		credential: udpx.NewCredential(options.Password),
		transport: udpx.Options{
			IdleTimeout:     options.IdleTimeout,
			KeepAlivePeriod: options.Heartbeat,
			MTU:             options.MTU,
			Logger:          options.Logger,
		},
		logger: options.Logger,
	}, nil
}

func (c *Client) getSession(ctx context.Context) (*session, error) {
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return nil, os.ErrClosed
	}
	current := c.session
	generation := c.generation
	c.access.Unlock()
	if current != nil && current.live() {
		return current, nil
	}
	result := c.dialGroup.DoChan(strconv.FormatUint(generation, 10), func() (any, error) {
		return c.dialSession(generation)
	})
	select {
	case outcome := <-result:
		if outcome.Err != nil {
			return nil, outcome.Err
		}
		return outcome.Val.(*session), nil
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-c.ctx.Done():
		return nil, context.Cause(c.ctx)
	}
}

func (c *Client) dialSession(generation uint64) (*session, error) {
	dialStart := time.Now()
	udpConn, err := c.dialer.DialContext(c.ctx, "udp", c.serverAddr)
	if err != nil {
		c.logger.Error("QUICX dial failed: stage=dial transport=udp server=", c.serverAddr, " elapsed=", dialElapsed(dialStart), " error=", err)
		return nil, err
	}
	remote := udpConn.RemoteAddr()
	conn, err := udpx.Dial(c.ctx, bindPacketConn(udpConn), remote, c.credential, c.transport)
	if err != nil {
		_ = udpConn.Close()
		c.logger.Error("QUICX dial failed: stage=handshake server=", c.serverAddr, " remote=", remote, " elapsed=", dialElapsed(dialStart), " error=", err)
		return nil, E.Cause(err, "open session")
	}
	c.logger.Debug("QUICX dial: stage=handshake server=", c.serverAddr, " remote=", remote, " elapsed=", dialElapsed(dialStart))
	current := newSession(c.ctx, conn, c.logger, nil)
	c.access.Lock()
	closed := c.closed
	stale := closed || c.generation != generation
	if !stale {
		c.session = current
	}
	c.access.Unlock()
	if stale {
		closeErr := errNetworkChanged
		if closed {
			closeErr = os.ErrClosed
		}
		current.closeWithError(closeErr)
		_ = udpConn.Close()
		return nil, closeErr
	}
	go c.watchSession(current, udpConn, dialStart)
	return current, nil
}

func (c *Client) watchSession(current *session, udpConn net.Conn, dialStart time.Time) {
	go current.run()
	<-current.conn.Context().Done()
	cause := context.Cause(current.conn.Context())
	current.closeWithError(cause)
	_ = udpConn.Close()
	c.access.Lock()
	if c.session == current {
		c.session = nil
	}
	c.access.Unlock()
	if udpx.IsNormalClose(cause) {
		c.logger.Debug("QUICX session closed: server=", c.serverAddr, " elapsed=", dialElapsed(dialStart), " error=", cause)
	} else {
		c.logger.Error("QUICX session failed: server=", c.serverAddr, " elapsed=", dialElapsed(dialStart), " error=", cause)
	}
}

func dialElapsed(start time.Time) time.Duration {
	return time.Since(start).Round(time.Millisecond)
}

func (c *Client) DialConn(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	current, err := c.getSession(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := current.conn.OpenStream(ctx)
	if err != nil {
		return nil, E.Cause(err, "open stream")
	}
	err = writeRequest(stream, destination)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	return &streamConn{stream: stream, destination: destination}, nil
}

func writeRequest(stream *udpx.Stream, destination M.Socksaddr) error {
	request := writeStreamRequest(nil, destination)
	_, err := stream.Write(request)
	if err != nil {
		return E.Cause(err, "write request")
	}
	return nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	current, err := c.getSession(ctx)
	if err != nil {
		return nil, err
	}
	return current.openChannel(c.ctx)
}

func (c *Client) Reset() {
	c.access.Lock()
	c.generation++
	current := c.session
	c.session = nil
	c.access.Unlock()
	if current != nil {
		current.closeWithError(errNetworkChanged)
	}
}

func (c *Client) CloseWithError(err error) error {
	c.access.Lock()
	c.closed = true
	c.generation++
	current := c.session
	c.session = nil
	c.access.Unlock()
	if current != nil {
		current.closeWithError(err)
	}
	return nil
}

type socketPacketConn struct {
	net.PacketConn
	socket syscallConn
}

type syscallConn interface {
	SyscallConn() (syscall.RawConn, error)
}

func bindPacketConn(conn net.Conn) net.PacketConn {
	unbound := bufio.NewUnbindPacketConn(conn)
	socket, isSocket := conn.(syscallConn)
	if !isSocket {
		return unbound
	}
	return &socketPacketConn{PacketConn: unbound, socket: socket}
}

func (c *socketPacketConn) SyscallConn() (syscall.RawConn, error) {
	return c.socket.SyscallConn()
}
