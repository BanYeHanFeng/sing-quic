package quicx

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/qlogwriter"
	qtls "github.com/sagernet/sing-quic"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type ClientOptions struct {
	Context       context.Context
	Dialer        N.Dialer
	ServerAddress M.Socksaddr
	TLSConfig     aTLS.Config
	QUICOptions   qtls.QUICOptions
	Password      string
	Heartbeat     time.Duration
	BBRProfile    string
	Tracer        func(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace
}

type Client struct {
	ctx        context.Context
	dialer     N.Dialer
	serverAddr M.Socksaddr
	tlsConfig  aTLS.Config
	quicConfig *quic.Config
	password   string
	heartbeat  time.Duration
	bbrProfile congestion_meta2.Profile

	connAccess sync.Mutex
	conn       *clientQUICConnection
	pending    *clientOffer
}

func NewClient(options ClientOptions) (*Client, error) {
	if options.Heartbeat == 0 {
		options.Heartbeat = 10 * time.Second
	}
	bbrProfile, err := parseBBRProfile(options.BBRProfile)
	if err != nil {
		return nil, err
	}
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery: !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:         true,
		MaxIncomingUniStreams:   1 << 60,
		Tracer:                  options.Tracer,
	}
	qtls.ApplyQUICOptions(quicConfig, options.QUICOptions)
	// 0-RTT requires resuming a previous TLS session, which in turn requires a
	// session ticket cache: without it the client never requests a session
	// ticket, and quic-go has no ticket to resume from.
	if sessionCacheSetter, isSessionCacheSetter := options.TLSConfig.(sessionCacheSetter); isSessionCacheSetter {
		sessionCacheSetter.SetClientSessionCache(tls.NewLRUClientSessionCache(0))
	} else if stdConfig, sErr := options.TLSConfig.STDConfig(); sErr == nil {
		stdConfig.ClientSessionCache = tls.NewLRUClientSessionCache(0)
	}
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{http3.NextProtoH3})
	}
	return &Client{
		ctx:        options.Context,
		dialer:     options.Dialer,
		serverAddr: options.ServerAddress,
		tlsConfig:  options.TLSConfig,
		quicConfig: quicConfig,
		password:   options.Password,
		heartbeat:  options.Heartbeat,
		bbrProfile: bbrProfile,
	}, nil
}

// sessionCacheSetter is implemented by TLS configs which allow their underlying
// crypto/tls or uTLS configuration to be adjusted.
type sessionCacheSetter interface {
	SetClientSessionCache(cache tls.ClientSessionCache)
}

func (c *Client) offer(ctx context.Context) (*clientQUICConnection, error) {
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
	// the shared result, but it must not tear down the background QUIC dial that
	// may still be reused by later requests. The connection attempt is owned by
	// the client lifetime context instead.
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

func (c *Client) offerNew(ctx context.Context) (*clientQUICConnection, error) {
	udpConn, err := c.dialer.DialContext(ctx, "udp", c.serverAddr)
	if err != nil {
		return nil, err
	}
	quicConn, err := qtls.DialEarly(ctx, udpConn, c.tlsConfig, c.quicConfig)
	if err != nil {
		udpConn.Close()
		return nil, E.Cause(err, "open connection")
	}
	setCongestion(c.ctx, quicConn, c.bbrProfile)
	connCtx := c.ctx
	if connCtx == nil {
		connCtx = context.Background()
	}
	conn := &clientQUICConnection{
		ctx:        connCtx,
		quicConn:   quicConn,
		rawConn:    udpConn,
		connDone:   make(chan struct{}),
		udpConnMap: make(map[uint16]*udpPacketConn),
	}
	go func() {
		hErr := c.clientHandshake(quicConn)
		if hErr != nil {
			conn.closeWithError(hErr)
		}
	}()
	go c.loopMessages(conn)
	go c.loopHeartbeats(conn)
	return conn, nil
}

func (c *Client) clientHandshake(conn *quic.Conn) error {
	authRequest := buf.NewSize(2 + 2 + len(c.password))
	defer authRequest.Release()
	authRequest.WriteByte(Version)
	authRequest.WriteByte(CommandAuthenticate)
	var passwordLen [2]byte
	binary.BigEndian.PutUint16(passwordLen[:], uint16(len(c.password)))
	authRequest.Write(passwordLen[:])
	authRequest.WriteString(c.password)
	return writeUniStream0RTT(c.ctx, conn, authRequest.Bytes())
}

func (c *Client) loopHeartbeats(conn *clientQUICConnection) {
	ticker := time.NewTicker(c.heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-conn.connDone:
			return
		case <-ticker.C:
			err := conn.quicConn.SendDatagram([]byte{Version, CommandHeartbeat})
			if err != nil {
				conn.closeWithError(E.Cause(err, "send heartbeat"))
			}
		}
	}
}

func (c *Client) DialConn(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := openStream0RTT(conn.ctx, conn.quicConn)
	if err != nil {
		return nil, err
	}
	return &clientConn{
		Stream:      stream,
		parent:      conn,
		destination: destination,
	}, nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	var sessionID uint16
	clientPacketConn := newUDPPacketConn(c.ctx, conn.quicConn, false, func() {
		conn.udpAccess.Lock()
		delete(conn.udpConnMap, sessionID)
		conn.udpAccess.Unlock()
	})
	conn.udpAccess.Lock()
	select {
	case <-conn.connDone:
		conn.udpAccess.Unlock()
		return nil, E.Errors(conn.connErr, os.ErrClosed)
	default:
	}
	sessionID = conn.udpSessionID
	conn.udpSessionID++
	conn.udpConnMap[sessionID] = clientPacketConn
	conn.udpAccess.Unlock()
	clientPacketConn.sessionID = sessionID
	return clientPacketConn, nil
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

// openStream0RTT opens a bidirectional stream, recovering from an open-time
// 0-RTT rejection. quic-go reports quic.Err0RTTRejected from OpenStream until
// the handshake completes and the stream maps are reset, so the stream has to be
// opened again afterwards. On a connection without a resumed session no early
// data is sent and quic.Err0RTTRejected never occurs, in which case both helpers
// are equivalent to a plain OpenStream / OpenUniStream call.
func openStream0RTT(ctx context.Context, conn *quic.Conn) (*quic.Stream, error) {
	stream, err := conn.OpenStream()
	if !errors.Is(err, quic.Err0RTTRejected) {
		return stream, err
	}
	_, nerr := conn.NextConnection(ctx)
	if nerr != nil {
		return nil, nerr
	}
	return conn.OpenStream()
}

func openUniStream0RTT(ctx context.Context, conn *quic.Conn) (*quic.SendStream, error) {
	stream, err := conn.OpenUniStream()
	if !errors.Is(err, quic.Err0RTTRejected) {
		return stream, err
	}
	_, nerr := conn.NextConnection(ctx)
	if nerr != nil {
		return nil, nerr
	}
	return conn.OpenUniStream()
}

// writeUniStream0RTT opens a unidirectional stream, writes message on it and
// closes it. A rejected 0-RTT attempt is recovered instead of failing the
// connection, see writeEarlyMessage.
func writeUniStream0RTT(ctx context.Context, conn *quic.Conn, message []byte) error {
	stream, err := openUniStream0RTT(ctx, conn)
	if err != nil {
		return E.Cause(err, "open handshake stream")
	}
	rejected, err := writeEarlyMessage(ctx, conn, stream, message)
	if err != nil {
		stream.CancelWrite(0)
		return E.Cause(err, "write handshake request")
	}
	if !rejected {
		closeHandshakeStream(stream)
		return nil
	}
	// The early data was discarded by the peer: the message has to be resent on
	// a stream which is valid after the stream maps were reset.
	stream.CancelWrite(0)
	if _, err = conn.NextConnection(ctx); err != nil {
		return E.Cause(err, "wait for handshake after 0-RTT rejection")
	}
	stream, err = conn.OpenUniStream()
	if err != nil {
		return E.Cause(err, "open handshake stream")
	}
	_, err = stream.Write(message)
	if err != nil {
		stream.CancelWrite(0)
		return E.Cause(err, "write handshake request")
	}
	closeHandshakeStream(stream)
	return nil
}

// closeHandshakeStream half-closes the send side of the authentication stream.
// The peer only needs the message itself and stops reading the stream as soon as
// it has it, which quic-go reports as closing a canceled stream. The message was
// written before that happens, so the error is not fatal.
func closeHandshakeStream(stream *quic.SendStream) {
	_ = stream.Close()
}

// earlyStream is implemented by both quic-go stream types and gives access to
// the context which quic-go cancels with quic.Err0RTTRejected when the server
// rejects the early data a stream was created in.
type earlyStream interface {
	Write([]byte) (int, error)
	Context() context.Context
}

// writeEarlyMessage reports whether message was discarded because the server
// rejected a 0-RTT attempt.
//
// quic-go reports quic.Err0RTTRejected from Write only when the rejection was
// already processed at the time of the call. A message which fits into a single
// STREAM frame is buffered and reported as written, and is dropped later without
// any further local error, so the outcome of the early data has to be checked
// after the handshake completed.
func writeEarlyMessage(ctx context.Context, conn *quic.Conn, stream earlyStream, message []byte) (rejected bool, err error) {
	select {
	case <-conn.HandshakeComplete():
		// No early data is in flight anymore, a plain write is enough.
		_, err = stream.Write(message)
		return false, err
	default:
	}
	_, err = stream.Write(message)
	if err != nil {
		if errors.Is(err, quic.Err0RTTRejected) {
			// The rejection is already known: recover instead of failing.
			return true, nil
		}
		return false, err
	}
	// The handshake is still running, so the message may have been sent as early
	// data which the peer is allowed to discard. Wait for the handshake outcome,
	// which is also the point where quic-go resets the streams of a rejected
	// attempt.
	select {
	case <-conn.HandshakeComplete():
	case <-conn.Context().Done():
	case <-ctx.Done():
	}
	return errors.Is(context.Cause(stream.Context()), quic.Err0RTTRejected), nil
}

// writeStream0RTT writes message on stream and recovers from a rejected 0-RTT
// attempt by reopening the stream after the handshake. It returns the stream the
// message was written to, which may differ from stream.
func writeStream0RTT(ctx context.Context, conn *quic.Conn, stream *quic.Stream, message []byte) (*quic.Stream, error) {
	rejected, err := writeEarlyMessage(ctx, conn, stream, message)
	if err != nil || !rejected {
		return stream, err
	}
	// A stream created during 0-RTT is unusable once the server rejected the
	// early data: quic-go resets the stream maps, so the request has to be sent
	// again on a stream opened after the handshake.
	if _, err = conn.NextConnection(ctx); err != nil {
		return stream, err
	}
	newStream, err := conn.OpenStream()
	if err != nil {
		return stream, err
	}
	_, err = newStream.Write(message)
	if err != nil {
		return newStream, err
	}
	return newStream, nil
}

type clientOffer struct {
	done      chan struct{}
	cancel    func(error)
	conn      *clientQUICConnection
	err       error
	discarded bool
	cause     error
}

type clientQUICConnection struct {
	ctx          context.Context
	quicConn     *quic.Conn
	rawConn      io.Closer
	closeOnce    sync.Once
	connDone     chan struct{}
	connErr      error
	udpAccess    sync.RWMutex
	udpConnMap   map[uint16]*udpPacketConn
	udpSessionID uint16
}

func (c *clientQUICConnection) active() bool {
	select {
	case <-c.quicConn.Context().Done():
		return false
	default:
	}
	select {
	case <-c.connDone:
		return false
	default:
	}
	return true
}

func (c *clientQUICConnection) closeWithError(err error) {
	c.closeOnce.Do(func() {
		c.connErr = err
		c.udpAccess.Lock()
		close(c.connDone)
		udpConnMap := c.udpConnMap
		c.udpConnMap = make(map[uint16]*udpPacketConn)
		c.udpAccess.Unlock()
		for _, udpConn := range udpConnMap {
			udpConn.closeWithError(err)
		}
		_ = c.quicConn.CloseWithError(0, "")
		_ = c.rawConn.Close()
	})
}

type clientConn struct {
	*quic.Stream
	access         sync.Mutex
	parent         *clientQUICConnection
	destination    M.Socksaddr
	requestWritten bool
}

func (c *clientConn) NeedHandshake() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return !c.requestWritten
}

func (c *clientConn) Read(b []byte) (n int, err error) {
	c.access.Lock()
	stream := c.Stream
	c.access.Unlock()
	n, err = stream.Read(b)
	return n, qtls.WrapError(err)
}

func (c *clientConn) Write(b []byte) (n int, err error) {
	c.access.Lock()
	defer c.access.Unlock()
	if !c.requestWritten {
		request := buf.NewSize(2 + AddressSerializer.AddrPortLen(c.destination) + len(b))
		defer request.Release()
		request.WriteByte(Version)
		request.WriteByte(CommandConnect)
		err = AddressSerializer.WriteAddrPort(request, c.destination)
		if err != nil {
			return
		}
		request.Write(b)
		// The stream may have been opened while 0-RTT was still pending. When
		// the server rejects the early data the request never arrived and this
		// stream is invalid, so it is reopened after the handshake instead of
		// closing the whole connection.
		var stream *quic.Stream
		stream, err = writeStream0RTT(c.parent.ctx, c.parent.quicConn, c.Stream, request.Bytes())
		if err != nil {
			c.parent.closeWithError(E.Cause(err, "create new connection"))
			return 0, qtls.WrapError(err)
		}
		c.Stream = stream
		c.requestWritten = true
		return len(b), nil
	}
	n, err = c.Stream.Write(b)
	return n, qtls.WrapError(err)
}

func (c *clientConn) Close() error {
	c.access.Lock()
	stream := c.Stream
	c.access.Unlock()
	stream.CancelRead(0)
	err := stream.Close()
	// quic-go's Stream.Close does not unblock a Write blocked on flow control,
	// but a past write deadline does; buffered data and the FIN are unaffected.
	stream.SetWriteDeadline(time.Now())
	return err
}

func (c *clientConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) RemoteAddr() net.Addr {
	return c.destination
}
