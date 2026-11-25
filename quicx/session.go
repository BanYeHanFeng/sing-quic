package quicx

import (
	"context"
	"sync"

	"github.com/sagernet/sing-quic/udpx"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

type session struct {
	context context.Context
	conn    *udpx.Conn
	logger  logger.Logger

	onUnknownChannel func(channel uint32, message udpMessage)

	access      sync.Mutex
	channels    map[uint32]*channelConn
	nextChannel uint32
	closeOnce   sync.Once
	closeErr    error
	done        chan struct{}
}

func newSession(ctx context.Context, conn *udpx.Conn, sessionLogger logger.Logger, onUnknownChannel func(channel uint32, message udpMessage)) *session {
	return &session{
		context:          ctx,
		conn:             conn,
		logger:           sessionLogger,
		onUnknownChannel: onUnknownChannel,
		channels:         make(map[uint32]*channelConn),
		done:             make(chan struct{}),
	}
}

func (s *session) run() {
	for {
		datagram, err := s.conn.ReceiveDatagram(s.conn.Context())
		if err != nil {
			s.closeWithError(err)
			return
		}
		command, destination, payload, err := parseMessage(datagram.Data)
		if err != nil {
			s.closeWithError(E.Cause(err, "handle message"))
			return
		}
		switch command {
		case CommandPacket:
			s.dispatch(datagram.Channel, udpMessage{destination: destination, data: payload})
		case CommandDissociate:
			s.dissociate(datagram.Channel)
		}
	}
}

func (s *session) channel(id uint32) *channelConn {
	s.access.Lock()
	defer s.access.Unlock()
	return s.channels[id]
}

func (s *session) addChannel(conn *channelConn) bool {
	s.access.Lock()
	defer s.access.Unlock()
	select {
	case <-s.done:
		return false
	default:
	}
	if _, loaded := s.channels[conn.channel]; loaded {
		return false
	}
	s.channels[conn.channel] = conn
	return true
}

func (s *session) removeChannel(id uint32) {
	s.access.Lock()
	conn, loaded := s.channels[id]
	delete(s.channels, id)
	s.access.Unlock()
	if loaded {
		conn.closeWithError(E.New("channel closed"))
	}
}

func (s *session) openChannel(ctx context.Context) (*channelConn, error) {
	s.access.Lock()
	select {
	case <-s.done:
		err := s.closeErr
		s.access.Unlock()
		return nil, E.Errors(err, E.New("session closed"))
	default:
	}
	id := s.nextChannel
	s.nextChannel++
	conn := newChannelConn(ctx, s, id)
	s.channels[id] = conn
	s.access.Unlock()
	return conn, nil
}

func (s *session) dispatch(id uint32, message udpMessage) {
	conn := s.channel(id)
	if conn != nil {
		conn.input(message)
		return
	}
	if s.onUnknownChannel == nil {
		return
	}
	s.onUnknownChannel(id, message)
}

func (s *session) dissociate(id uint32) {
	s.access.Lock()
	conn, loaded := s.channels[id]
	delete(s.channels, id)
	s.access.Unlock()
	if loaded {
		conn.closeWithError(E.New("remote closed"))
	}
}

func (s *session) live() bool {
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

func (s *session) closeWithError(err error) {
	s.closeOnce.Do(func() {
		s.access.Lock()
		s.closeErr = err
		close(s.done)
		channels := s.channels
		s.channels = make(map[uint32]*channelConn)
		s.access.Unlock()
		for _, conn := range channels {
			conn.closeWithError(err)
		}
		_ = s.conn.CloseWithError(err)
	})
}
