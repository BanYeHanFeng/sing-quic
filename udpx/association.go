package udpx

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-quic/congestion"
	"github.com/sagernet/sing-quic/udpio"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

type Association interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	Reachable() bool
	Context() context.Context
	CloseWithError(err error) error
	OpenStream(ctx context.Context) (*Stream, error)
	AcceptStream(ctx context.Context) (*Stream, error)
	KeyID() [keyIDLen]byte
	Offload() (gso, gro bool)
	SendDatagram(channel uint32, data []byte) error
	ReceiveDatagram(ctx context.Context) (Datagram, error)
}

var ErrIdleTimeout = E.New("udpx: idle timeout")

var ErrProbeTimeout = E.New("udpx: probe timeout")

const (
	windowUpdateInterval = time.Second

	maxParseFailures = 8

	maxPacketSize = 1452

	maxReceiveSize = 64 * 1024

	defaultIdleTimeout = 30 * time.Second

	helloRetransmitInterval = 250 * time.Millisecond

	defaultHandshakeTimeout = 10 * time.Second
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

type associationTimers struct {
	idle *time.Timer
	ack  *time.Timer
	pto  *time.Timer
}

type association struct {
	localConnID connectionID
	peerConnID  connectionID
	keyID       [keyIDLen]byte
	conn        net.PacketConn
	options     Options
	logger      logger.Logger
	logTag      string
	stats       associationStats
	ctx         context.Context
	cancel      context.CancelCauseFunc

	peerAddr atomic.Pointer[net.Addr]

	sendMu        sync.Mutex
	sendCipher    packetCipher
	sendPacket    uint32
	batchIO       udpio.Conn
	batch         *batch
	mtu           int
	mtuCandidates []int
	mtuProbe      mtuProbeState
	writingProbe  atomic.Bool
	probeRefused  atomic.Bool
	pumpMu        sync.Mutex
	sendWake      chan struct{}
	sendDone      chan struct{}
	probeCredits  int
	closing       atomic.Bool
	queue         frameQueue
	maxPayload    int

	recvCipher    packetCipher
	parseFailures int

	timers atomic.Pointer[associationTimers]

	ackMu sync.Mutex
	ack   ackScheduler

	flightMu   sync.Mutex
	inFlight   sentPackets
	rtt        rttEstimator
	probes     int
	probeSince time.Time

	ccMu     sync.Mutex
	cc       congestion.Controller
	rttStats rttSnapshot

	streamsMu       sync.Mutex
	streams         map[uint32]*Stream
	endedStreams    endedStreams
	acceptStream    chan *Stream
	nextStreamID    uint32
	openCredit      uint32
	peerStreamLimit uint32
	streamCredit    chan struct{}

	datagramMu      sync.Mutex
	datagramMessage uint16
	defragger       datagramDefragger
	datagrams       chan Datagram

	fcMu         sync.Mutex
	sendCredit   credit
	recvLimit    uint64
	recvWindow   uint64
	recvRead     uint64
	recvReceived uint64

	isClient bool

	ownsConn bool

	onClose   func()
	closeOnce sync.Once
}

func newAssociation(conn net.PacketConn, result handshakeResult, peer net.Addr, options Options, isClient, ownsConn bool) *association {
	ctx, cancel := context.WithCancelCause(context.Background())
	a := &association{
		localConnID:     result.localConnID,
		peerConnID:      result.peerConnID,
		keyID:           result.keyID,
		conn:            conn,
		options:         options.withDefaults(),
		logger:          options.Logger,
		logTag:          logTagFor(result.localConnID),
		ctx:             ctx,
		cancel:          cancel,
		sendCipher:      result.send,
		recvCipher:      result.recv,
		batchIO:         udpio.New(conn, udpio.Options{GRO: true}),
		sendWake:        make(chan struct{}, 1),
		sendDone:        make(chan struct{}),
		maxPayload:      maxPacketSize - headerLen - tagLen,
		streams:         make(map[uint32]*Stream),
		acceptStream:    make(chan *Stream, streamBudget),
		defragger:       newDatagramDefragger(),
		datagrams:       make(chan Datagram, datagramBacklog),
		sendCredit:      credit{limit: initialConnectionWindow},
		recvLimit:       initialConnectionWindow,
		recvWindow:      connectionWindow,
		openCredit:      initialStreams,
		peerStreamLimit: initialStreams,
		streamCredit:    make(chan struct{}),
		isClient:        isClient,
		ownsConn:        ownsConn,
	}
	a.mtuCandidates = mtuCandidatesFor(peer)
	a.mtu = mtuMin
	if options.MTU > 0 {
		a.mtu = max(mtuMin, min(options.MTU, a.mtuCandidates[0]))
	}
	a.updatePayloadLocked()
	a.cc = newCongestionController()
	a.cc.SetRTTStatsProvider(&a.rttStats)
	a.peerAddr.Store(&peer)
	a.batch = newBatch()
	timers := &associationTimers{
		idle: time.AfterFunc(time.Hour, func() { a.shutdown(ErrIdleTimeout, true) }),
		ack:  time.AfterFunc(time.Hour, a.flushAck),
		pto:  time.AfterFunc(time.Hour, a.probe),
	}
	timers.ack.Stop()
	timers.pto.Stop()
	a.timers.Store(timers)
	timers.idle.Reset(a.options.IdleTimeout)
	gso, gro := a.Offload()
	a.logInfo("association up local=", hex.EncodeToString(a.localConnID[:]),
		" peer=", hex.EncodeToString(a.peerConnID[:]), " client=", isClient,
		" remote=", peer, " gso=", gso, " gro=", gro, " mtu=", a.maxPacketSize())
	return a
}

func (a *association) start() {
	go a.sendLoop()
	go a.windowLoop()
	if a.options.KeepAlivePeriod > 0 {
		go a.keepAliveLoop()
	}
	if a.logger != nil {
		go a.statsLoop()
	}
}

func (a *association) windowLoop() {
	ticker := time.NewTicker(windowUpdateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.sendWindowUpdates()
		}
	}
}

func (a *association) sendWindowUpdates() {
	var payload []byte
	if limit, moved := a.extendWindow(); moved {
		payload = appendMaxData(payload, limit)
	}
	a.streamsMu.Lock()
	var updates []streamWindowUpdate
	for _, stream := range a.streams {
		limit, moved := stream.extendWindow()
		if moved {
			updates = append(updates, streamWindowUpdate{id: stream.id, limit: limit})
		}
	}
	a.streamsMu.Unlock()
	for _, update := range updates {
		if len(payload) > 0 && len(payload)+maxStreamDataFrameLen > a.maxPayload {
			_ = a.send(payload)
			payload = nil
		}
		payload = appendMaxStreamData(payload, update.id, update.limit)
	}
	if len(payload) > 0 {
		_ = a.send(payload)
	}
}

type streamWindowUpdate struct {
	id    uint32
	limit uint64
}

func (a *association) extendWindow() (uint64, bool) {
	a.fcMu.Lock()
	defer a.fcMu.Unlock()
	limit := min(a.recvReceived+a.recvWindow, a.recvRead+2*a.recvWindow)
	if limit <= a.recvLimit {
		return 0, false
	}
	a.recvLimit = limit
	return limit, true
}

func (a *association) maxPacketSize() int {
	return a.mtu
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

func (a *association) Offload() (gso, gro bool) {
	return a.batchIO.Offload()
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
		if notifyPeer {
			a.closing.Store(true)
			a.sendMu.Lock()
			a.queue.frames = nil
			a.queue.push(outFrame{payload: appendClose(nil, closeCodeOf(cause)), ackEliciting: true})
			a.sendMu.Unlock()
			a.wake()
			select {
			case <-a.sendDone:
			case <-time.After(writeDrainTimeout):
			}
		}
		timers := a.timers.Load()
		timers.idle.Stop()
		timers.ack.Stop()
		timers.pto.Stop()
		a.cancel(cause)
		a.closeStreams(cause)
		if a.ownsConn {
			_ = a.conn.Close()
		}
		select {
		case <-a.sendDone:
		case <-time.After(writeDrainTimeout):
		}
		if a.onClose != nil {
			a.onClose()
		}
	})
}

func (a *association) send(frame []byte) error {
	select {
	case <-a.ctx.Done():
		return context.Cause(a.ctx)
	default:
	}
	a.queueFrame(frame)
	a.wake()
	return nil
}

func (a *association) queueFrame(frame []byte) {
	entry := outFrame{
		payload:      frame,
		ackEliciting: frameType(frame[0]) != frameTypeAck,
	}
	a.sendMu.Lock()
	if entry.ackEliciting {
		a.queue.push(entry)
	} else {
		a.queue.pushFront([]outFrame{entry})
	}
	a.sendMu.Unlock()
}

func (a *association) queueStreamFrame(frame streamFrame) {
	a.sendMu.Lock()
	a.queue.push(outFrame{
		streamFrame:  frame,
		ackEliciting: true,
	})
	a.sendMu.Unlock()
}

func (a *association) handlePacket(packet []byte, source net.Addr) error {
	packetHeader, err := parseHeader(packet)
	if err != nil {
		return err
	}
	a.stats.recvPackets.Add(1)
	a.stats.recvBytes.Add(int64(len(packet)))
	if packetHeader.ConnectionID != a.localConnID {
		return errAuthentication
	}
	_, payload, err := a.recvCipher.open(packet)
	if err != nil {
		return err
	}
	a.peerAddr.Store(&source)
	a.resetIdle()
	ackEliciting := false
	for len(payload) > 0 {
		var f frame
		f, payload, err = nextFrame(payload)
		if err != nil {
			a.parseFailures++
			if a.parseFailures >= maxParseFailures {
				a.shutdown(err, true)
				return err
			}
			a.logDebug("drop packet ", packetHeader.PacketNumber, " of ", len(packet), " bytes: ", err)
			return err
		}
		a.parseFailures = 0
		switch f.frameType {
		case frameTypePing:
			ackEliciting = true
		case frameTypeClose:
			a.shutdown(f.closeCode().err(), false)
			return nil
		case frameTypeAck:
			a.handleAck(f.body, time.Now())
		case frameTypeStream:
			ackEliciting = true
			err = a.handleStreamFrame(f.stream())
			if err != nil {
				a.shutdown(err, true)
				return err
			}
		case frameTypeMaxData:
			ackEliciting = true
			a.handleMaxData(binary.BigEndian.Uint64(f.body))
		case frameTypeMaxStreamData:
			ackEliciting = true
			a.handleMaxStreamData(binary.BigEndian.Uint32(f.body), binary.BigEndian.Uint64(f.body[4:]))
		case frameTypeResetStream:
			ackEliciting = true
			a.handleResetStream(f.streamReset())
		case frameTypeDatagram:
			ackEliciting = true
			err = a.handleDatagram(f.datagram())
			if err != nil {
				a.shutdown(err, true)
				return err
			}
		case frameTypeMaxStreams:
			ackEliciting = true
			a.handleMaxStreams(binary.BigEndian.Uint32(f.body))
		case frameTypePadding:
		}
	}
	if ackEliciting {
		a.scheduleAck(packetHeader.PacketNumber, time.Now())
	}
	return nil
}

func (a *association) scheduleAck(packetNumber uint32, now time.Time) {
	a.ackMu.Lock()
	immediate := a.ack.received(packetNumber, now)
	var acknowledgement []byte
	if immediate {
		acknowledgement = a.ack.pack(now)
	}
	a.ackMu.Unlock()
	if immediate {
		if len(acknowledgement) > 0 {
			_ = a.send(acknowledgement)
		}
		return
	}
	a.timers.Load().ack.Reset(a.ackDelay())
}

func (a *association) ackDelay() time.Duration {
	rtt, measured := a.roundTrip()
	if !measured {
		return maxAckDelay
	}
	return min(maxAckDelay, max(minAckDelay, rtt/8))
}

func (a *association) flushAck() {
	a.ackMu.Lock()
	acknowledgement := a.ack.pack(time.Now())
	a.ackMu.Unlock()
	if len(acknowledgement) == 0 {
		return
	}
	_ = a.send(acknowledgement)
}

func (a *association) roundTrip() (time.Duration, bool) {
	a.flightMu.Lock()
	defer a.flightMu.Unlock()
	if !a.rtt.sampled {
		return 0, false
	}
	return a.rtt.smoothed, true
}

func (a *association) resetIdle() {
	a.timers.Load().idle.Reset(a.options.IdleTimeout)
}

func (a *association) keepAliveLoop() {
	ticker := time.NewTicker(a.options.KeepAlivePeriod)
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			err := a.send(appendPing(nil))
			if err != nil {
				return
			}
		}
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
	a := newAssociation(conn, result, remote, options, true, true)
	a.start()
	go a.readLoop()
	go a.startMTUProbe()
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
