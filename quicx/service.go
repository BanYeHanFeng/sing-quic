package quicx

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-quic/udpx"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/canceler"
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
	Trace       TraceOptions
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
	options    udpx.Options

	usersAccess sync.RWMutex
	userMap     map[[8]byte]userEntry[U]

	listener *udpx.Listener
}

type userEntry[U comparable] struct {
	credential udpx.Credential
	user       U
}

func NewService[U comparable](options ServiceOptions) (*Service[U], error) {
	if options.Context == nil {
		options.Context = context.Background()
	}
	if options.Logger == nil {
		options.Logger = logger.NOP()
	}
	if options.Handler == nil {
		return nil, E.New("missing handler")
	}
	if options.UDPTimeout == 0 {
		options.UDPTimeout = 5 * time.Minute
	}
	return &Service[U]{
		ctx:        options.Context,
		logger:     options.Logger,
		handler:    options.Handler,
		udpTimeout: options.UDPTimeout,
		options: udpx.Options{
			IdleTimeout:     options.IdleTimeout,
			KeepAlivePeriod: options.Heartbeat,
			MTU:             options.MTU,
			Trace:           udpx.TraceOptions{Dir: options.Trace.Path, Capacity: options.Trace.Capacity},
			Logger:          options.Logger,
		},
		userMap: make(map[[8]byte]userEntry[U]),
	}, nil
}

func (s *Service[U]) UpdateUsers(userList []U, passwordList []string) {
	userMap := make(map[[8]byte]userEntry[U], len(userList))
	for index := range userList {
		credential := udpx.NewCredential(passwordList[index])
		userMap[credential.KeyID()] = userEntry[U]{
			credential: credential,
			user:       userList[index],
		}
	}
	s.usersAccess.Lock()
	s.userMap = userMap
	s.usersAccess.Unlock()
}

func (s *Service[U]) Lookup(keyID [8]byte) (udpx.Credential, bool) {
	s.usersAccess.RLock()
	entry, loaded := s.userMap[keyID]
	s.usersAccess.RUnlock()
	if !loaded {
		return udpx.Credential{}, false
	}
	return entry.credential, true
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
	options := s.options
	options.NewHandler = s.newHandler()
	s.listener = udpx.Listen(conn, s, options)
	return nil
}

func (s *Service[U]) Close() error {
	return common.Close(common.PtrOrNil(s.listener))
}

func (s *Service[U]) newHandler() func(conn *udpx.Conn) udpx.Handler {
	return func(conn *udpx.Conn) udpx.Handler {
		user, loaded := s.lookupUser(conn.KeyID())
		if !loaded {
			return nil
		}
		current := &serverSession[U]{
			Service:    s,
			requestCtx: auth.ContextWithUser(conn.Context(), user),
			source:     M.SocksaddrFromNet(conn.RemoteAddr()),
		}
		current.session = newSession(current.requestCtx, conn, s.logger, "from "+current.source.String(), nil, current.onUnknownChannel)
		return current
	}
}

type serverSession[U comparable] struct {
	*Service[U]
	*session
	requestCtx context.Context
	source     M.Socksaddr
}

func (s *serverSession[U]) OnStream(conn *udpx.Conn, stream *udpx.Stream) {
	if err := s.handleStream(stream); err != nil {
		_ = stream.Close()
		s.Service.logger.Debug(E.Cause(err, "handle stream request"))
	}
}

func (s *serverSession[U]) handleStream(stream *udpx.Stream) error {
	destination, err := readStreamRequest(stream)
	if err != nil {
		return err
	}
	s.handler.NewConnectionEx(s.requestCtx, &streamConn{
		stream:      stream,
		destination: destination,
	}, s.source.Unwrap(), destination, nil)
	return nil
}

func (s *serverSession[U]) onUnknownChannel(channel uint32, message udpMessage) {
	if !message.destination.IsValid() {
		return
	}
	conn := newChannelConn(s.requestCtx, s.session, channel)
	if !s.session.addChannel(conn) {
		return
	}
	s.conn.Trace("quicx:channel_opened", channelEvent{Channel: channel, Destination: message.destination.String()})
	conn.input(message)
	ctx, packetConn := canceler.NewPacketConn(conn.context, conn, s.udpTimeout)
	go s.handler.NewPacketConnectionEx(ctx, packetConn, s.source.Unwrap(), message.destination, nil)
}
