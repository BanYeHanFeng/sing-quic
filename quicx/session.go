package quicx

import (
	"context"
	"encoding/binary"
	"sync"

	"github.com/sagernet/sing-quic/udpx"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

// session 是一条连接上的 UDP 通道表，同时是 udpx 的事件接收方。
type session struct {
	ctx    context.Context
	conn   *udpx.Conn
	logger logger.Logger
	label  string

	mu          sync.Mutex
	channels    map[uint32]*channelConn
	nextChannel uint32
	newChannel  func(channel uint32, message udpMessage) // 客户端为 nil：未知通道直接丢弃

	closeErr  error
	done      chan struct{}
	closeOnce sync.Once
	onClosed  func(*session) // 服务端为 nil
}

func newSession(ctx context.Context, conn *udpx.Conn, sessionLogger logger.Logger, label string, onClosed func(*session), newChannel func(channel uint32, message udpMessage)) *session {
	return &session{
		ctx:        ctx,
		conn:       conn,
		logger:     sessionLogger,
		label:      label,
		channels:   make(map[uint32]*channelConn),
		done:       make(chan struct{}),
		onClosed:   onClosed,
		newChannel: newChannel,
	}
}

func (s *session) OnDatagram(conn *udpx.Conn, data []byte) {
	if len(data) < 4 {
		_ = conn.CloseWithError(E.New("datagram of ", len(data), " bytes has no channel"))
		return
	}
	channel := binary.BigEndian.Uint32(data)
	command, destination, payload, err := parseMessage(data[4:])
	if err != nil {
		_ = conn.CloseWithError(E.Cause(err, "handle message"))
		return
	}
	switch command {
	case CommandPacket:
		s.dispatch(channel, udpMessage{destination: destination, data: payload})
	case CommandDissociate:
		s.dissociate(channel)
	}
}

func (s *session) OnStream(conn *udpx.Conn, stream *udpx.Stream) {
	_ = stream.Close()
}

func (s *session) OnClose(conn *udpx.Conn, cause error) {
	if udpx.IsNormalClose(cause) {
		s.logger.Debug("QUICX session ", s.label, " closed: ", cause)
	} else {
		s.logger.Error("QUICX session ", s.label, " failed: ", cause)
	}
	s.close(cause)
	if s.onClosed != nil {
		s.onClosed(s)
	}
}

func (s *session) channel(id uint32) *channelConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.channels[id]
}

func (s *session) addChannel(conn *channelConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
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

func (s *session) openChannel(ctx context.Context) (*channelConn, error) {
	s.mu.Lock()
	select {
	case <-s.done:
		err := s.closeErr
		s.mu.Unlock()
		return nil, E.Errors(err, E.New("session closed"))
	default:
	}
	id := s.nextChannel
	s.nextChannel++
	conn := newChannelConn(ctx, s, id)
	s.channels[id] = conn
	s.mu.Unlock()
	return conn, nil
}

func (s *session) dispatch(id uint32, message udpMessage) {
	conn := s.channel(id)
	if conn != nil {
		conn.input(message)
		return
	}
	if s.newChannel != nil {
		s.newChannel(id, message)
	}
}

func (s *session) dissociate(id uint32) {
	s.mu.Lock()
	conn, loaded := s.channels[id]
	delete(s.channels, id)
	s.mu.Unlock()
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

// closeWithError 从外部关闭：结束所有通道，并关闭连接。
func (s *session) closeWithError(err error) {
	s.close(err)
	_ = s.conn.CloseWithError(err)
}

// close 只结束通道；连接自己结束时由 OnClose 调用，不再回头关连接。
func (s *session) close(err error) {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closeErr = err
		close(s.done)
		channels := s.channels
		s.channels = make(map[uint32]*channelConn)
		s.mu.Unlock()
		for _, conn := range channels {
			conn.closeWithError(err)
		}
	})
}
