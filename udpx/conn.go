package udpx

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-quic/udpx/internal/udpio"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

type Association interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	Context() context.Context
	CloseWithError(err error) error
	OpenStream(ctx context.Context) (*Stream, error)
	AcceptStream(ctx context.Context) (*Stream, error)
	KeyID() [keyIDLen]byte
	SendDatagram(channel uint32, data []byte) error
	ReceiveDatagram(ctx context.Context) (Datagram, error)
}

var ErrIdleTimeout = E.New("udpx: idle timeout")

var ErrProbeTimeout = E.New("udpx: probe timeout")

func IsNormalClose(err error) bool {
	if err == nil || E.IsClosedOrCanceled(err) {
		return true
	}
	return errors.Is(err, net.ErrClosed) ||
		errors.Is(err, ErrIdleTimeout) ||
		errors.Is(err, ErrProbeTimeout)
}

const (
	maxPacketSize = 1452

	maxReceiveSize = 64 * 1024

	defaultIdleTimeout = 30 * time.Second

	helloRetransmitInterval = 250 * time.Millisecond

	defaultHandshakeTimeout = 10 * time.Second

	writeDrainTimeout = 100 * time.Millisecond
)

type Options struct {
	IdleTimeout time.Duration

	KeepAlivePeriod time.Duration

	MTU int

	Logger logger.Logger
}

func (o Options) withDefaults() Options {
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = defaultIdleTimeout
	}
	if o.KeepAlivePeriod < 0 {
		o.KeepAlivePeriod = 0
	}
	return o
}

type association struct {
	conn     net.PacketConn
	batchIO  udpio.Conn
	options  Options
	logger   logger.Logger
	logTag   string
	isClient bool

	localConnID connectionID
	peerConnID  connectionID
	keyID       [keyIDLen]byte
	sendCipher  packetCipher
	recvCipher  packetCipher

	ctx    context.Context
	cancel context.CancelCauseFunc

	peerAddr   atomic.Pointer[net.Addr]
	maxPayload atomic.Int32

	txMu      sync.Mutex
	tx        txState
	txWake    chan struct{}
	txDone    chan struct{}
	closeOnce sync.Once

	fcMu sync.Mutex
	fc   flowControl

	streamsMu sync.Mutex
	streams   streamTable

	datagramMessage atomic.Uint32
	defragger       datagramDefragger
	datagrams       chan Datagram

	stats associationStats

	onClose func()
}

func newAssociation(conn net.PacketConn, batchIO udpio.Conn, result handshakeResult, peer net.Addr, options Options, isClient bool) *association {
	ctx, cancel := context.WithCancelCause(context.Background())
	if options.Logger == nil {
		options.Logger = logger.NOP()
	}
	a := &association{
		conn:        conn,
		batchIO:     batchIO,
		options:     options.withDefaults(),
		logger:      options.Logger,
		logTag:      logTagFor(result.localConnID),
		isClient:    isClient,
		localConnID: result.localConnID,
		peerConnID:  result.peerConnID,
		keyID:       result.keyID,
		sendCipher:  result.send,
		recvCipher:  result.recv,
		ctx:         ctx,
		cancel:      cancel,
		txWake:      make(chan struct{}, 1),
		txDone:      make(chan struct{}),
		fc:          newFlowControl(),
		streams:     newStreamTable(isClient),
		defragger:   newDatagramDefragger(),
		datagrams:   make(chan Datagram, datagramBacklog),
	}
	a.peerAddr.Store(&peer)
	mtu := mtuMin
	if options.MTU > 0 {
		mtu = max(mtuMin, min(options.MTU, maxPacketSize))
	}
	a.maxPayload.Store(int32(mtu - headerLen - tagLen))
	a.tx.init(a)
	a.logInfo("association up local=", a.logTag,
		" client=", isClient, " remote=", peer, " mtu=", a.mtuSize())
	return a
}

func (a *association) start() {
	go a.writeLoop()
}

func (a *association) LocalAddr() net.Addr {
	return a.conn.LocalAddr()
}

func (a *association) RemoteAddr() net.Addr {
	return *a.peerAddr.Load()
}

func (a *association) Context() context.Context {
	return a.ctx
}

func (a *association) KeyID() [keyIDLen]byte {
	return a.keyID
}

func (a *association) mtuSize() int {
	return int(a.maxPayload.Load()) + headerLen + tagLen
}

func (a *association) CloseWithError(err error) error {
	a.shutdown(err, true)
	return nil
}

func (a *association) shutdown(cause error, notifyPeer bool) {
	a.closeOnce.Do(func() {
		if cause == nil {
			cause = net.ErrClosed
		}
		a.txMu.Lock()
		a.tx.closeLocked(cause, notifyPeer)
		a.txMu.Unlock()
		a.wake()
		select {
		case <-a.txDone:
		case <-time.After(writeDrainTimeout):
		}
		a.cancel(cause)
		if a.isClient {
			_ = a.conn.SetReadDeadline(time.Now())
		}
		a.closeStreams(cause)
		if a.onClose != nil {
			a.onClose()
		}
	})
}

func (a *association) closeStreams(cause error) {
	a.streamsMu.Lock()
	streams := make([]*Stream, 0, len(a.streams.table))
	for _, stream := range a.streams.table {
		streams = append(streams, stream)
	}
	a.streams.table = make(map[uint32]*Stream)
	a.streamsMu.Unlock()
	for _, stream := range streams {
		stream.end(cause)
	}
}

func (a *association) wake() {
	select {
	case a.txWake <- struct{}{}:
	default:
	}
}

func Dial(ctx context.Context, conn net.PacketConn, remote net.Addr, credential Credential, options Options) (Association, error) {
	if _, loaded := ctx.Deadline(); !loaded {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultHandshakeTimeout)
		defer cancel()
	}
	handshake, err := newClientHandshake(credential)
	if err != nil {
		return nil, err
	}
	result, err := exchangeHello(ctx, conn, remote, handshake)
	if err != nil {
		return nil, err
	}
	batchIO := udpio.New(conn, udpio.Options{GRO: true})
	a := newAssociation(conn, batchIO, result, remote, options, true)
	a.start()
	go a.readLoop()
	return a, nil
}

func exchangeHello(ctx context.Context, conn net.PacketConn, remote net.Addr, handshake *clientHandshake) (handshakeResult, error) {
	buffer := make([]byte, maxPacketSize)
	hello := handshake.hello()
	for {
		_, err := conn.WriteTo(hello, remote)
		if err != nil {
			return handshakeResult{}, E.Cause(err, "write hello")
		}
		deadline := time.Now().Add(helloRetransmitInterval)
		if contextDeadline, loaded := ctx.Deadline(); loaded && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		err = conn.SetReadDeadline(deadline)
		if err != nil {
			return handshakeResult{}, E.Cause(err, "set read deadline")
		}
		for {
			n, source, readErr := conn.ReadFrom(buffer)
			if readErr != nil {
				select {
				case <-ctx.Done():
					return handshakeResult{}, context.Cause(ctx)
				default:
				}
				if isTimeout(readErr) {
					break
				}
				return handshakeResult{}, E.Cause(readErr, "read hello answer")
			}
			if source.String() != remote.String() {
				continue
			}
			packetHeader, parseErr := parseHeader(buffer[:n])
			if parseErr != nil || packetHeader.Type != packetTypeHandshake {
				continue
			}
			result, handleErr := handshake.handleResponse(buffer[:n])
			if handleErr != nil {
				continue
			}
			err = conn.SetReadDeadline(time.Time{})
			if err != nil {
				return handshakeResult{}, E.Cause(err, "clear read deadline")
			}
			return result, nil
		}
	}
}

func (a *association) readLoop() {
	buffer := make([]byte, maxReceiveSize)
	for {
		packets, err := a.batchIO.ReadPackets([][]byte{buffer})
		if err != nil {
			if a.ctx.Err() != nil {
				return
			}
			if isClosed(err) {
				a.shutdown(err, false)
				return
			}
			continue
		}
		for _, packet := range packets {
			packet.ForEach(func(datagram []byte) {
				_ = a.handlePacket(datagram, packet.Addr)
			})
			if a.ctx.Err() != nil {
				return
			}
		}
	}
}

func isTimeout(err error) bool {
	netErr, isNetErr := err.(net.Error)
	return isNetErr && netErr.Timeout()
}

func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed)
}
