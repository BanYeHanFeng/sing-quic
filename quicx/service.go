package quicx

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-quic/udpx"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// The server side of QUICX
//
// A session is one association of the transport, and everything a client sends
// runs on it: each proxied connection is a stream, each forwarded UDP packet a
// datagram of a channel. Authentication happened before the association was
// accepted, so a session here is a session with a user, and there is nothing to
// time out and nothing to masquerade as.

type ServiceOptions struct {
	Context     context.Context
	Logger      logger.Logger
	IdleTimeout time.Duration
	Heartbeat   time.Duration
	UDPTimeout  time.Duration
	Handler     ServiceHandler
	// FEC protects what this server sends, which is the direction the answers
	// travel in. It is per direction: a client that wants its own requests covered
	// sets it on the client.
	FEC udpx.FECOptions
}

type ServiceHandler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

// Service is the server side of QUICX: it accepts sessions, tells the transport
// which accounts it knows, and hands what the sessions carry to the handler.
type Service[U comparable] struct {
	ctx        context.Context
	logger     logger.Logger
	handler    ServiceHandler
	udpTimeout time.Duration
	transport  udpx.Options

	usersAccess sync.RWMutex
	userMap     map[[8]byte]userEntry[U]

	listener *udpx.Listener
}

// userEntry is one account: the password the transport verifies the peer with,
// and what the rest of this package knows the account as.
type userEntry[U comparable] struct {
	password udpx.Password
	user     U
}

func NewService[U comparable](options ServiceOptions) (*Service[U], error) {
	if options.Logger == nil {
		options.Logger = logger.NOP()
	}
	if options.UDPTimeout == 0 {
		// A zero UDP timeout makes the wrapped packet connection expire
		// immediately, so every UDP message replaces its session. Fall back to
		// the default the sing-box inbound uses.
		options.UDPTimeout = 5 * time.Minute
	}
	if options.Heartbeat == 0 {
		options.Heartbeat = 10 * time.Second
	}
	return &Service[U]{
		ctx:        options.Context,
		logger:     options.Logger,
		handler:    options.Handler,
		udpTimeout: options.UDPTimeout,
		transport: udpx.Options{
			IdleTimeout:     options.IdleTimeout,
			KeepAlivePeriod: options.Heartbeat,
			FEC:             options.FEC,
		},
		userMap: make(map[[8]byte]userEntry[U]),
	}, nil
}

// UpdateUsers replaces the accounts this service accepts. The password itself is
// never sent: what travels is the key id, and what proves the password is the
// authentication key the transport derives from it.
func (s *Service[U]) UpdateUsers(userList []U, passwordList []string) {
	userMap := make(map[[8]byte]userEntry[U], len(userList))
	for index := range userList {
		password := udpx.NewPassword(passwordList[index])
		userMap[password.KeyID()] = userEntry[U]{
			password: password,
			user:     userList[index],
		}
	}
	// The map is replaced, never mutated in place, and the transport reads it
	// under the same lock: a runtime update must not race with a handshake,
	// which would be a concurrent map read/write fatal.
	s.usersAccess.Lock()
	s.userMap = userMap
	s.usersAccess.Unlock()
}

// Lookup is how the transport authenticates a peer: it reports the authentication
// key of the account whose password has that key id, and a key id that is not in
// the table is a peer with no account here.
func (s *Service[U]) Lookup(keyID [8]byte) (func(transcript []byte) []byte, bool) {
	s.usersAccess.RLock()
	entry, loaded := s.userMap[keyID]
	s.usersAccess.RUnlock()
	if !loaded {
		return nil, false
	}
	return entry.password.AuthKey, true
}

func (s *Service[U]) lookupUser(keyID [8]byte) (U, bool) {
	s.usersAccess.RLock()
	entry, loaded := s.userMap[keyID]
	s.usersAccess.RUnlock()
	if !loaded {
		var zero U
		return zero, false
	}
	return entry.user, true
}

func (s *Service[U]) Start(conn net.PacketConn) error {
	s.listener = udpx.ListenPacket(conn, s, s.transport)
	go s.loopSessions()
	return nil
}

func (s *Service[U]) Close() error {
	return common.Close(common.PtrOrNil(s.listener))
}

func (s *Service[U]) loopSessions() {
	for {
		association, err := s.listener.Accept(s.ctx)
		if err != nil {
			if E.IsClosedOrCanceled(err) {
				s.logger.Debug(E.Cause(err, "listener closed"))
			} else {
				s.logger.Error(E.Cause(err, "listener closed"))
			}
			return
		}
		user, loaded := s.lookupUser(association.KeyID())
		if !loaded {
			// The transport authenticated the connection with a key this service
			// knows, so a key it does not know anymore is an account that was
			// removed while the handshake ran.
			_ = association.CloseWithError(net.ErrClosed)
			continue
		}
		session := &serverSession[U]{
			Service:     s,
			association: association,
			requestCtx:  auth.ContextWithUser(association.Context(), user),
			udpConnMap:  make(map[uint32]*udpPacketConn),
		}
		go session.run()
	}
}

// serverSession is one session as the server keeps it: the association, the user
// it authenticated as, and the packet connections multiplexed on it.
type serverSession[U comparable] struct {
	*Service[U]
	association udpx.Association
	// requestCtx carries the authenticated user and ends with the session, which
	// is the context every connection of this session is handed to the handler
	// with.
	requestCtx context.Context
	closeOnce  sync.Once

	udpAccess  sync.RWMutex
	udpConnMap map[uint32]*udpPacketConn
}

func (s *serverSession[U]) run() {
	go s.loopStreams()
	go s.loopMessages()
	<-s.association.Context().Done()
	s.closeWithError(context.Cause(s.association.Context()))
}

// closeWithError ends the session once, and keeps the cause so that everything
// which waits on it reports why it stopped. An idle timeout or a close of the
// peer is not a failure: reporting it as one turns every client that went away
// into an ERROR line.
func (s *serverSession[U]) closeWithError(cause error) {
	s.closeOnce.Do(func() {
		source := M.SocksaddrFromNet(s.association.RemoteAddr())
		if isNormalSessionEnd(cause) {
			s.logger.Debug("session from ", source, " closed: ", E.Cause(cause, "closed"))
		} else {
			s.logger.Error("session from ", source, " failed: ", cause)
		}
		s.udpAccess.Lock()
		udpConnMap := s.udpConnMap
		s.udpConnMap = make(map[uint32]*udpPacketConn)
		s.udpAccess.Unlock()
		for _, udpConn := range udpConnMap {
			udpConn.closeWithError(cause)
		}
		_ = s.association.CloseWithError(cause)
	})
}

func (s *serverSession[U]) loopStreams() {
	for {
		stream, err := s.association.AcceptStream(s.association.Context())
		if err != nil {
			return
		}
		go func(stream *udpx.Stream) {
			err := s.handleStream(stream)
			if err != nil {
				// A request stream which cannot be served is reset, and only
				// that stream: every connection of a client is multiplexed on
				// one session, so ending the session over one bad stream tears
				// down all of them at once.
				_ = stream.Close()
				s.logger.Debug(E.Cause(err, "handle stream request"))
			}
		}(stream)
	}
}

// handleStream reads the request that starts a proxied connection and hands the
// connection to the handler.
func (s *serverSession[U]) handleStream(stream *udpx.Stream) error {
	var header [2]byte
	_, err := io.ReadFull(stream, header[:])
	if err != nil {
		return E.Cause(err, "read request")
	}
	if header[0] != Version {
		return E.New("unknown version ", header[0])
	}
	if header[1] != CommandConnect {
		return E.New("unknown stream command ", header[1])
	}
	destination, err := AddressSerializer.ReadAddrPort(stream)
	if err != nil {
		return E.Cause(err, "read request destination")
	}
	s.handler.NewConnectionEx(s.requestCtx, &streamConn{
		stream:      stream,
		destination: destination,
	}, M.SocksaddrFromNet(s.association.RemoteAddr()).Unwrap(), destination, nil)
	return nil
}

// closePacketConn ends one packet connection and forgets it, which is what a
// dissociate message from the peer asks for.
func (s *serverSession[U]) closePacketConn(sessionID uint32, cause error) {
	s.udpAccess.Lock()
	udpConn, loaded := s.udpConnMap[sessionID]
	delete(s.udpConnMap, sessionID)
	s.udpAccess.Unlock()
	if loaded {
		udpConn.closeWithError(cause)
	}
}

// isNormalSessionEnd reports whether a session ended without a failure. The three
// ways an association ends on purpose are a close of either end, an idle timeout
// and a stateless reset; a stream that was reset with a code is the only failure
// the peer can report without ending the session.
func isNormalSessionEnd(err error) bool {
	if err == nil || E.IsClosedOrCanceled(err) {
		return true
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return true
	}
	if errors.Is(err, udpx.ErrIdleTimeout) || errors.Is(err, udpx.ErrStatelessReset) {
		return true
	}
	return false
}
