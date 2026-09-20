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
	"github.com/sagernet/quic-go/qlogwriter"
	qtls "github.com/sagernet/sing-quic"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
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

	// defaultSilentDropTimeout is how long a silently dropped session is kept
	// before its QUIC connection is reclaimed locally.
	defaultSilentDropTimeout = 30 * time.Second
)

// errAlreadyAuthenticated is returned for a second authentication stream on a
// session which already completed authentication. It is not fatal: the first
// stream authenticated the session, so a peer racing two authentication
// streams (or a buggy client) must not tear the session down.
var errAlreadyAuthenticated = E.New("authentication: multiple authentication requests")

type ServiceOptions struct {
	Context     context.Context
	Logger      logger.Logger
	TLSConfig   aTLS.ServerConfig
	QUICOptions qtls.QUICOptions
	AuthTimeout time.Duration
	Heartbeat   time.Duration
	UDPTimeout  time.Duration
	// SilentDropTimeout is how long a session closed by
	// AuthFailurePolicySilentDrop keeps its QUIC connection before it is
	// reclaimed locally. No CONNECTION_CLOSE is sent before that, so a probe
	// observes a timeout instead of a protocol-identifiable close; without a
	// reclamation timer a peer sending keepalives would pin the session
	// resources until the QUIC idle timeout expires.
	SilentDropTimeout time.Duration
	Handler           ServiceHandler
	AuthFailurePolicy string
	BBRProfile        string
	Tracer            func(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace
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
	usersAccess       sync.RWMutex
	userMap           map[string]U
	authTimeout       time.Duration
	udpTimeout        time.Duration
	handler           ServiceHandler
	authFailurePolicy string
	silentDropTimeout time.Duration
	bbrProfile        congestion_meta2.Profile

	quicListener io.Closer
}

func NewService[U comparable](options ServiceOptions) (*Service[U], error) {
	if options.AuthTimeout == 0 {
		options.AuthTimeout = 3 * time.Second
	}
	if options.Heartbeat == 0 {
		options.Heartbeat = 10 * time.Second
	}
	if options.UDPTimeout == 0 {
		// A zero UDP timeout makes the wrapped packet connection expire
		// immediately, so every UDP message replaces its session. Fall back to
		// the default the sing-box inbound uses.
		options.UDPTimeout = 5 * time.Minute
	}
	bbrProfile, err := parseBBRProfile(options.BBRProfile)
	if err != nil {
		return nil, err
	}
	if options.AuthFailurePolicy == "" {
		options.AuthFailurePolicy = AuthFailurePolicyH3Close
	}
	if options.SilentDropTimeout == 0 {
		options.SilentDropTimeout = defaultSilentDropTimeout
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
		Tracer:                  options.Tracer,
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
		silentDropTimeout: options.SilentDropTimeout,
		bbrProfile:        bbrProfile,
	}, nil
}

func (s *Service[U]) UpdateUsers(userList []U, passwordList []string) {
	userMap := make(map[string]U, len(userList))
	for index := range userList {
		userMap[passwordList[index]] = userList[index]
	}
	// The map is replaced, never mutated in place, and authentication reads it
	// under the same lock: a runtime update must not race with the
	// authentication path, which would be a concurrent map read/write fatal.
	s.usersAccess.Lock()
	s.userMap = userMap
	s.usersAccess.Unlock()
}

func (s *Service[U]) lookupUser(password string) (U, bool) {
	s.usersAccess.RLock()
	defer s.usersAccess.RUnlock()
	user, loaded := s.userMap[password]
	return user, loaded
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
	setCongestion(s.ctx, connection, s.bbrProfile)
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
	authAccess sync.Mutex
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
		go func(stream *quic.ReceiveStream) {
			err := s.handleUniStream(stream)
			if err == nil {
				return
			}
			if errors.Is(err, errAlreadyAuthenticated) {
				// The session is already authenticated by another stream, so
				// this duplicate request is a no-op instead of a session
				// teardown.
				s.logger.Debug(E.Cause(err, "handle uni stream"))
				return
			}
			s.closeWithError(E.Cause(err, "handle uni stream"))
		}(uniStream)
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
	// connection consume it so the connection stays well-formed.
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
		user, loaded := s.lookupUser(password)
		if !loaded {
			return s.authFailure(E.New("authentication: unknown user"))
		}
		return s.completeAuthentication(user)
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
		go func(stream *quic.Stream) {
			err := s.handleStream(stream)
			if err != nil {
				stream.CancelRead(0)
				stream.Close()
				s.logger.Error(E.Cause(err, "handle stream request"))
				s.closeWithError(E.Cause(err, "handle stream request"))
			}
		}(stream)
	}
}

func (s *serverSession[U]) handleStream(stream *quic.Stream) error {
	var header [2]byte
	n, _ := stream.Peek(header[:])
	if n > 0 && header[0] == Version && header[1] == CommandConnect {
		s.startAuthTimeout()
		return s.handleQUICXStream(stream)
	}
	// Any other bidirectional stream is a standard HTTP/3 request stream.
	// It is not a QUICX proxy request, so there is no masquerade to serve;
	// the session is terminated following auth_failure_policy, exactly like a
	// failed authentication, keeping the transport indistinguishable from a
	// standard HTTP/3 server.
	s.closeByPolicy(E.New("standard HTTP/3 request"))
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
	s.closeByPolicy(err)
	return err
}

// completeAuthentication publishes the authenticated user and signals authDone
// exactly once. The check and the state change have to be atomic: two
// authentication streams racing on one connection would otherwise both observe
// an unauthenticated session and execute close(s.authDone) twice, panicking with
// "close of closed channel" and taking the whole process down. Later readers
// observe authUser through the happens-before edge of the channel close.
func (s *serverSession[U]) completeAuthentication(user U) error {
	s.authAccess.Lock()
	defer s.authAccess.Unlock()
	select {
	case <-s.authDone:
		return errAlreadyAuthenticated
	default:
	}
	s.authUser = user
	close(s.authDone)
	return nil
}

// closeByPolicy terminates a session that is not a valid authenticated QUICX
// session, following auth_failure_policy.
func (s *serverSession[U]) closeByPolicy(err error) {
	switch s.authFailurePolicy {
	case AuthFailurePolicyH3Close:
		// Close the connection with H3_NO_ERROR (0x100), the standard HTTP/3
		// code for a normal connection close. This keeps the transport
		// indistinguishable from a standard HTTP/3 server. A GOAWAY frame is
		// intentionally not sent: the session ends before any request was
		// served.
		s.closeSession(quic.ApplicationErrorCode(http3.ErrCodeNoError), "", err)
	case AuthFailurePolicySilentDrop:
		s.silentClose(err)
	}
}

func (s *serverSession[U]) closeWithError(err error) {
	s.closeSession(quic.ApplicationErrorCode(http3.ErrCodeNoError), "", err)
}

// closeSession terminates the session exactly once and keeps cause as the
// session error, so callers of connDone still observe why it ended. Replacing
// it with a generic "connection closed" loses the real reason and reports
// normal closes (canceled contexts, closed pipes, ...) as ERROR level.
func (s *serverSession[U]) closeSession(code quic.ApplicationErrorCode, desc string, cause error) {
	s.connAccess.Lock()
	defer s.connAccess.Unlock()
	select {
	case <-s.connDone:
		return
	default:
	}
	if cause == nil {
		cause = E.New("connection closed")
	}
	s.connErr = cause
	close(s.connDone)
	if isNormalSessionEnd(cause) {
		s.logger.Debug(E.Cause(cause, "connection closed"))
	} else {
		s.logger.Error(E.Cause(cause, "connection failed"))
	}
	s.udpAccess.Lock()
	udpConnMap := s.udpConnMap
	s.udpConnMap = make(map[uint16]*udpPacketConn)
	s.udpAccess.Unlock()
	for _, udpConn := range udpConnMap {
		udpConn.closeWithError(cause)
	}
	_ = s.quicConn.CloseWithError(code, desc)
	_ = s.h3Conn.CloseWithError(code, desc)
}

func (s *serverSession[U]) silentClose(err error) {
	s.connAccess.Lock()
	select {
	case <-s.connDone:
		s.connAccess.Unlock()
		return
	default:
		s.connErr = err
		close(s.connDone)
	}
	s.connAccess.Unlock()
	s.logger.Debug(E.Cause(err, "connection dropped silently"))
	s.udpAccess.Lock()
	udpConnMap := s.udpConnMap
	s.udpConnMap = make(map[uint16]*udpPacketConn)
	s.udpAccess.Unlock()
	for _, udpConn := range udpConnMap {
		udpConn.closeWithError(err)
	}
	s.cancel(err)
	// Do not close the QUIC connection: a probe must observe a timeout, not a
	// protocol-identifiable CONNECTION_CLOSE. Keep the connection open for a
	// grace period only, so that a peer sending keepalives cannot pin the
	// session resources until the QUIC idle timeout expires.
	s.scheduleSilentReclaim()
}

// isNormalSessionEnd reports whether a session ended without a protocol or
// transport failure, in which case it must not be reported as an error. The
// QUIC error types below describe a peer which closed the connection on purpose,
// an idle timeout and a stateless reset, none of which is an application error.
func isNormalSessionEnd(err error) bool {
	if E.IsClosedOrCanceled(err) {
		return true
	}
	var applicationErr *quic.ApplicationError
	if errors.As(err, &applicationErr) {
		return true
	}
	var idleTimeoutErr *quic.IdleTimeoutError
	if errors.As(err, &idleTimeoutErr) {
		return true
	}
	var statelessResetErr *quic.StatelessResetError
	if errors.As(err, &statelessResetErr) {
		return true
	}
	return false
}

// scheduleSilentReclaim tears the QUIC connection down locally after
// silentDropTimeout. It gives up as soon as the connection is gone by itself.
func (s *serverSession[U]) scheduleSilentReclaim() {
	timeout := s.silentDropTimeout
	if timeout <= 0 {
		return
	}
	go func() {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-timer.C:
			_ = s.quicConn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
		case <-s.quicConn.Context().Done():
		}
	}()
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
