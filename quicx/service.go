package quicx

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

const (
	AuthFailurePolicyH3Close    = "h3_close"
	AuthFailurePolicySilentDrop = "silent_drop"
)

type ServiceOptions struct {
	Context           context.Context
	Logger            logger.Logger
	TLSConfig         aTLS.ServerConfig
	QUICOptions       qtls.QUICOptions
	AuthTimeout       time.Duration
	Heartbeat         time.Duration
	UDPTimeout        time.Duration
	Handler           ServiceHandler
	AuthFailurePolicy string
}

type ServiceHandler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

type Service[U comparable] struct {
	ctx               context.Context
	logger            logger.Logger
	tlsConfig         aTLS.ServerConfig
	heartbeat         time.Duration
	quicConfig        *quic.Config
	userMap           map[string]U
	authTimeout       time.Duration
	udpTimeout        time.Duration
	handler           ServiceHandler
	authFailurePolicy string

	quicListener io.Closer
}

func NewService[U comparable](options ServiceOptions) (*Service[U], error) {
	if options.AuthTimeout == 0 {
		options.AuthTimeout = 3 * time.Second
	}
	if options.Heartbeat == 0 {
		options.Heartbeat = 10 * time.Second
	}
	if options.AuthFailurePolicy == "" {
		options.AuthFailurePolicy = AuthFailurePolicyH3Close
	}
	switch options.AuthFailurePolicy {
	case AuthFailurePolicyH3Close, AuthFailurePolicySilentDrop:
	default:
		return nil, E.New("unknown auth failure policy: ", options.AuthFailurePolicy)
	}
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery: !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:         true,
		Allow0RTT:               true,
		MaxIncomingStreams:      1 << 60,
		MaxIncomingUniStreams:   1 << 60,
		DisablePathManager:      true,
	}
	qtls.ApplyQUICOptions(quicConfig, options.QUICOptions)
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{http3.NextProtoH3})
	}
	return &Service[U]{
		ctx:               options.Context,
		logger:            options.Logger,
		tlsConfig:         options.TLSConfig,
		heartbeat:         options.Heartbeat,
		quicConfig:        quicConfig,
		userMap:           make(map[string]U),
		authTimeout:       options.AuthTimeout,
		udpTimeout:        options.UDPTimeout,
		handler:           options.Handler,
		authFailurePolicy: options.AuthFailurePolicy,
	}, nil
}

func (s *Service[U]) UpdateUsers(userList []U, passwordList []string) {
	userMap := make(map[string]U)
	for index := range userList {
		userMap[passwordList[index]] = userList[index]
	}
	s.userMap = userMap
}

func (s *Service[U]) Start(conn net.PacketConn) error {
	listener, err := qtls.ListenEarlyWithOptions(conn, s.tlsConfig, s.quicConfig, qtls.ListenOptions{
		StatelessReset: true,
	})
	if err != nil {
		return err
	}
	s.quicListener = listener
	go s.loopConnections(listener)
	return nil
}

func (s *Service[U]) Close() error {
	return common.Close(
		s.quicListener,
	)
}

func (s *Service[U]) loopConnections(listener qtls.EarlyListener) {
	for {
		connection, err := listener.Accept(s.ctx)
		if err != nil {
			if E.IsClosedOrCanceled(err) || errors.Is(err, quic.ErrServerClosed) {
				s.logger.Debug(E.Cause(err, "listener closed"))
			} else {
				s.logger.Error(E.Cause(err, "listener closed"))
			}
			return
		}
		go s.handleConnection(connection)
	}
}

func (s *Service[U]) handleConnection(connection *quic.Conn) {
	setCongestion(s.ctx, connection)
	h3Server := http3.Server{}
	h3Conn, err := h3Server.NewRawServerConn(connection)
	if err != nil {
		_ = connection.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
		return
	}
	sessionCtx, sessionCancel := context.WithCancelCause(s.ctx)
	session := &serverSession[U]{
		Service:    s,
		ctx:        sessionCtx,
		cancel:     sessionCancel,
		quicConn:   connection,
		h3Conn:     h3Conn,
		connDone:   make(chan struct{}),
		authDone:   make(chan struct{}),
		udpConnMap: make(map[uint16]*udpPacketConn),
	}
	session.handle()
}

type serverSession[U comparable] struct {
	*Service[U]
	ctx        context.Context
	cancel     context.CancelCauseFunc
	quicConn   *quic.Conn
	h3Conn     *http3.RawServerConn
	connAccess sync.Mutex
	connDone   chan struct{}
	connErr    error
	authDone   chan struct{}
	authUser   U
	udpAccess  sync.RWMutex
	udpConnMap map[uint16]*udpPacketConn

	authTimeoutOnce sync.Once
}

func (s *serverSession[U]) handle() {
	go func() {
		select {
		case <-s.ctx.Done():
			s.closeWithError(s.ctx.Err())
		case <-s.connDone:
		}
	}()
	go s.loopUniStreams()
	go s.loopStreams()
	go s.loopMessages()
	go s.loopHeartbeats()
}

func (s *serverSession[U]) startAuthTimeout() {
	s.authTimeoutOnce.Do(func() {
		go s.handleAuthTimeout()
	})
}

func (s *serverSession[U]) handleAuthTimeout() {
	select {
	case <-s.connDone:
	case <-s.authDone:
	case <-time.After(s.authTimeout):
		s.closeWithError(E.New("authentication timeout"))
	}
}

func (s *serverSession[U]) loopUniStreams() {
	for {
		uniStream, err := s.quicConn.AcceptUniStream(s.ctx)
		if err != nil {
			return
		}
		go func() {
			err = s.handleUniStream(uniStream)
			if err != nil {
				s.closeWithError(E.Cause(err, "handle uni stream"))
			}
		}()
	}
}

func (s *serverSession[U]) handleUniStream(stream *quic.ReceiveStream) error {
	var header [2]byte
	n, _ := stream.Peek(header[:])
	if n > 0 && header[0] == Version && isQUICXUniCommand(header[1]) {
		defer stream.CancelRead(0)
		s.startAuthTimeout()
		return s.handleQUICXUniStream(stream)
	}
	// A unidirectional stream that is not a QUICX command belongs to the
	// standard HTTP/3 machinery (control/QPACK streams). Let the HTTP/3
	// connection consume it so the connection stays well-formed until a
	// graceful shutdown is triggered by request streams or auth failure.
	s.h3Conn.HandleUnidirectionalStream(stream)
	return nil
}

func isQUICXUniCommand(command byte) bool {
	switch command {
	case CommandAuthenticate, CommandDissociate:
		return true
	default:
		return false
	}
}

func (s *serverSession[U]) handleQUICXUniStream(stream *quic.ReceiveStream) error {
	buffer := buf.New()
	defer buffer.Release()
	_, err := buffer.ReadAtLeastFrom(stream, 2)
	if err != nil {
		return E.Cause(err, "read request")
	}
	version := buffer.Byte(0)
	if version != Version {
		return E.New("unknown version ", version)
	}
	command := buffer.Byte(1)
	switch command {
	case CommandAuthenticate:
		select {
		case <-s.authDone:
			return E.New("authentication: multiple authentication requests")
		default:
		}
		// Authentication request message:
		// [version(1)][command(1)][password length(2)][password(variable)]
		if buffer.Len() < 4 {
			_, err = buffer.ReadFullFrom(stream, 4-buffer.Len())
			if err != nil {
				return E.Cause(err, "authentication: read request")
			}
		}
		passwordLen := int(binary.BigEndian.Uint16(buffer.Range(2, 4)))
		if passwordLen == 0 {
			return E.New("authentication: empty password")
		}
		if buffer.Len() < 4+passwordLen {
			_, err = buffer.ReadFullFrom(stream, 4+passwordLen-buffer.Len())
			if err != nil {
				return E.Cause(err, "authentication: read request")
			}
		}
		password := string(buffer.Range(4, 4+passwordLen))
		user, loaded := s.userMap[password]
		if !loaded {
			return s.authFailure(E.New("authentication: unknown user"))
		}
		s.authUser = user
		close(s.authDone)
		return nil
	case CommandDissociate:
		select {
		case <-s.connDone:
			return s.connErr
		case <-s.authDone:
		}
		if buffer.Len() > 4 {
			return E.New("invalid dissociate message")
		}
		var sessionID uint16
		err = binary.Read(io.MultiReader(bytes.NewReader(buffer.From(2)), stream), binary.BigEndian, &sessionID)
		if err != nil {
			return err
		}
		s.udpAccess.RLock()
		udpConn, loaded := s.udpConnMap[sessionID]
		s.udpAccess.RUnlock()
		if loaded {
			udpConn.closeWithError(E.New("remote closed"))
			s.udpAccess.Lock()
			delete(s.udpConnMap, sessionID)
			s.udpAccess.Unlock()
		}
		return nil
	default:
		return E.New("unknown command ", command)
	}
}

func (s *serverSession[U]) loopStreams() {
	for {
		stream, err := s.quicConn.AcceptStream(s.ctx)
		if err != nil {
			return
		}
		go func() {
			err = s.handleStream(stream)
			if err != nil {
				stream.CancelRead(0)
				stream.Close()
				s.logger.Error(E.Cause(err, "handle stream request"))
				s.closeWithError(E.Cause(err, "handle stream request"))
			}
		}()
	}
}

func (s *serverSession[U]) handleStream(stream *quic.Stream) error {
	if s.h3Conn.Draining() {
		// After a GOAWAY frame the client must not open new request streams;
		// reject any that raced with the GOAWAY (RFC 9114 Section 5.2).
		s.h3Conn.RejectRequestStream(stream)
		return nil
	}
	var header [2]byte
	n, _ := stream.Peek(header[:])
	if n > 0 && header[0] == Version && header[1] == CommandConnect {
		s.startAuthTimeout()
		return s.handleQUICXStream(stream)
	}
	// Any other bidirectional stream is a standard HTTP/3 request stream.
	// It is not a QUICX proxy request, so there is no masquerade to serve;
	// terminate the connection like a normal HTTP/3 server.
	s.closeGracefully()
	return nil
}

func (s *serverSession[U]) handleQUICXStream(stream *quic.Stream) error {
	buffer := buf.NewSize(2 + M.MaxSocksaddrLength)
	defer buffer.Release()
	_, err := buffer.ReadAtLeastFrom(stream, 2)
	if err != nil {
		return E.Cause(err, "read request")
	}
	version, _ := buffer.ReadByte()
	if version != Version {
		return E.New("unknown version ", version)
	}
	command, _ := buffer.ReadByte()
	if command != CommandConnect {
		return E.New("unsupported stream command ", command)
	}
	destination, err := AddressSerializer.ReadAddrPort(io.MultiReader(buffer, stream))
	if err != nil {
		return E.Cause(err, "read request destination")
	}
	select {
	case <-s.connDone:
		return s.connErr
	case <-s.authDone:
	}
	var conn net.Conn = &serverConn{
		Stream:      stream,
		destination: destination,
	}
	if !buffer.IsEmpty() {
		conn = bufio.NewCachedConn(conn, buffer.ToOwned())
	}
	s.handler.NewConnectionEx(auth.ContextWithUser(s.ctx, s.authUser), conn, M.SocksaddrFromNet(s.quicConn.RemoteAddr()).Unwrap(), destination, nil)
	return nil
}

func (s *serverSession[U]) loopHeartbeats() {
	select {
	case <-s.connDone:
		return
	case <-s.authDone:
	}
	ticker := time.NewTicker(s.heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-s.connDone:
			return
		case <-ticker.C:
			err := s.quicConn.SendDatagram([]byte{Version, CommandHeartbeat})
			if err != nil {
				s.closeWithError(E.Cause(err, "send heartbeat"))
			}
		}
	}
}

func (s *serverSession[U]) authFailure(err error) error {
	switch s.authFailurePolicy {
	case AuthFailurePolicyH3Close:
		// Close the connection with H3_NO_ERROR (0x100), the standard HTTP/3
		// code for a normal connection close. This keeps the transport
		// indistinguishable from a standard HTTP/3 server. A GOAWAY frame is
		// intentionally not sent: this is not an HTTP/3 graceful shutdown of a
		// connection that served requests, but the termination of an
		// unauthenticated QUICX session before any request was served.
		s.closeWithErrorCode(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
	case AuthFailurePolicySilentDrop:
		s.silentClose(err)
	}
	return err
}

func (s *serverSession[U]) closeWithError(err error) {
	s.closeWithErrorCode(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
}

func (s *serverSession[U]) closeGracefully() {
	done := s.h3Conn.GracefulShutdown()
	go func() {
		<-done
		s.finalizeClose(E.New("connection closed"))
	}()
}

// finalizeClose tears down the session state without touching the QUIC
// connection. It is used after a graceful HTTP/3 shutdown has already closed
// the connection, so that session loops and blocked handlers observe the
// closure and exit.
func (s *serverSession[U]) finalizeClose(err error) {
	s.connAccess.Lock()
	defer s.connAccess.Unlock()
	select {
	case <-s.connDone:
		return
	default:
		s.connErr = err
		close(s.connDone)
	}
	s.logger.Debug(E.Cause(err, "connection closed gracefully"))
	s.udpAccess.Lock()
	udpConnMap := s.udpConnMap
	s.udpConnMap = make(map[uint16]*udpPacketConn)
	s.udpAccess.Unlock()
	for _, udpConn := range udpConnMap {
		udpConn.closeWithError(err)
	}
	s.cancel(err)
}

func (s *serverSession[U]) closeWithErrorCode(code quic.ApplicationErrorCode, desc string) {
	s.connAccess.Lock()
	defer s.connAccess.Unlock()
	select {
	case <-s.connDone:
		return
	default:
		s.connErr = E.New("connection closed")
		close(s.connDone)
	}
	if E.IsClosedOrCanceled(s.connErr) {
		s.logger.Debug(E.Cause(s.connErr, "connection failed"))
	} else {
		s.logger.Error(E.Cause(s.connErr, "connection failed"))
	}
	s.udpAccess.Lock()
	udpConnMap := s.udpConnMap
	s.udpConnMap = make(map[uint16]*udpPacketConn)
	s.udpAccess.Unlock()
	for _, udpConn := range udpConnMap {
		udpConn.closeWithError(s.connErr)
	}
	_ = s.quicConn.CloseWithError(code, desc)
	_ = s.h3Conn.CloseWithError(code, desc)
}

func (s *serverSession[U]) silentClose(err error) {
	s.connAccess.Lock()
	defer s.connAccess.Unlock()
	select {
	case <-s.connDone:
		return
	default:
		s.connErr = err
		close(s.connDone)
	}
	s.logger.Debug(E.Cause(err, "connection dropped silently"))
	s.udpAccess.Lock()
	udpConnMap := s.udpConnMap
	s.udpConnMap = make(map[uint16]*udpPacketConn)
	s.udpAccess.Unlock()
	for _, udpConn := range udpConnMap {
		udpConn.closeWithError(err)
	}
	s.cancel(err)
	// Do not close the QUIC connection: a probe must observe a timeout,
	// not a protocol-identifiable CONNECTION_CLOSE.
}

type serverConn struct {
	*quic.Stream
	destination M.Socksaddr
}

func (c *serverConn) Read(p []byte) (n int, err error) {
	n, err = c.Stream.Read(p)
	return n, qtls.WrapError(err)
}

func (c *serverConn) Write(p []byte) (n int, err error) {
	n, err = c.Stream.Write(p)
	return n, qtls.WrapError(err)
}

func (c *serverConn) LocalAddr() net.Addr {
	return c.destination
}

func (c *serverConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverConn) Close() error {
	c.Stream.CancelRead(0)
	err := c.Stream.Close()
	// quic-go's Stream.Close does not unblock a Write blocked on flow control,
	// but a past write deadline does; buffered data and the FIN are unaffected.
	c.Stream.SetWriteDeadline(time.Now())
	return err
}
