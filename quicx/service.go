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

type ServiceOptions struct {
	Context     context.Context
	Logger      logger.Logger
	IdleTimeout time.Duration
	Heartbeat   time.Duration
	UDPTimeout  time.Duration
	Handler     ServiceHandler
	MTU         int
}

type ServiceHandler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

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

type userEntry[U comparable] struct {
	password udpx.Password
	user     U
}

func NewService[U comparable](options ServiceOptions) (*Service[U], error) {
	transportLogger := options.Logger
	if options.Logger == nil {
		options.Logger = logger.NOP()
	}
	if options.UDPTimeout == 0 {
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
			MTU:             options.MTU,
			Logger:          transportLogger,
		},
		userMap: make(map[[8]byte]userEntry[U]),
	}, nil
}

func (s *Service[U]) UpdateUsers(userList []U, passwordList []string) {
	userMap := make(map[[8]byte]userEntry[U], len(userList))
	for index := range userList {
		password := udpx.NewPassword(passwordList[index])
		userMap[password.KeyID()] = userEntry[U]{
			password: password,
			user:     userList[index],
		}
	}
	s.usersAccess.Lock()
	s.userMap = userMap
	s.usersAccess.Unlock()
}

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

type serverSession[U comparable] struct {
	*Service[U]
	association udpx.Association
	requestCtx  context.Context
	closeOnce   sync.Once

	udpAccess  sync.RWMutex
	udpConnMap map[uint32]*udpPacketConn
}

func (s *serverSession[U]) run() {
	go s.loopStreams()
	go s.loopMessages()
	<-s.association.Context().Done()
	s.closeWithError(context.Cause(s.association.Context()))
}

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
				_ = stream.Close()
				s.logger.Debug(E.Cause(err, "handle stream request"))
			}
		}(stream)
	}
}

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

func (s *serverSession[U]) closePacketConn(sessionID uint32, cause error) {
	s.udpAccess.Lock()
	udpConn, loaded := s.udpConnMap[sessionID]
	delete(s.udpConnMap, sessionID)
	s.udpAccess.Unlock()
	if loaded {
		udpConn.closeWithError(cause)
	}
}

func isNormalSessionEnd(err error) bool {
	if err == nil || E.IsClosedOrCanceled(err) {
		return true
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return true
	}
	if errors.Is(err, udpx.ErrIdleTimeout) {
		return true
	}
	if errors.Is(err, errPathQuiet) {
		return true
	}
	if errors.Is(err, errRetired) {
		return true
	}
	return false
}
