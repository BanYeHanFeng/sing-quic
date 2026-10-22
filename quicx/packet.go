package quicx

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/cache"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

var udpMessagePool = sync.Pool{
	New: func() interface{} {
		return new(udpMessage)
	},
}

func releaseDatagramOwner(owner quic.DatagramBufferOwner) {
	if owner != nil {
		owner.ReleaseDatagramBuffer()
	}
}

func allocMessage() *udpMessage {
	message := udpMessagePool.Get().(*udpMessage)
	message.referenced = true
	return message
}

func releaseMessages(messages []*udpMessage) {
	for _, message := range messages {
		if message != nil {
			message.releaseMessage()
		}
	}
}

type udpMessage struct {
	sessionID     uint16
	packetID      uint16
	fragmentTotal uint8
	fragmentID    uint8
	fec           bool
	destination   M.Socksaddr
	// data is the payload of the message.
	//
	// On the receive path it points into a payload buffer of quic-go, which is
	// released through owner once the message is done with. On the send path it
	// points into the buffer the caller handed over, which is released through
	// buffer. Neither is copied: a forwarded datagram used to be copied into a
	// buf.Buffer of its own only to be copied again by quic-go.
	data       []byte
	buffer     *buf.Buffer
	owner      quic.DatagramBufferOwner
	referenced bool
}

func (m *udpMessage) release() {
	if !m.referenced {
		return
	}
	*m = udpMessage{}
	udpMessagePool.Put(m)
}

func (m *udpMessage) releaseMessage() {
	if m.buffer != nil {
		m.buffer.Release()
		m.buffer = nil
	}
	if m.owner != nil {
		m.owner.ReleaseDatagramBuffer()
		m.owner = nil
	}
	m.release()
}

// wireBuffer is a pooled packet buffer.
//
// It holds the serialized UDP message, and it is handed over to quic-go as the
// owner of the DATAGRAM payload: quic-go returns it to the pool once the
// datagram was sent out or dropped, which is what keeps the send path free of
// per-packet allocations. Reassembly uses the same type for the buffer holding
// a reassembled payload.
type wireBuffer struct {
	data []byte
}

var wireBufferPool = sync.Pool{
	New: func() interface{} {
		return new(wireBuffer)
	},
}

func getWireBuffer(size int) *wireBuffer {
	buffer := wireBufferPool.Get().(*wireBuffer)
	buffer.data = buf.Get(size)
	if buffer.data == nil {
		buffer.data = make([]byte, size)
	}
	return buffer
}

// ReleaseDatagramBuffer implements quic.DatagramBufferOwner.
func (b *wireBuffer) ReleaseDatagramBuffer() {
	if b.data != nil {
		_ = buf.Put(b.data)
		b.data = nil
	}
	wireBufferPool.Put(b)
}

func (m *udpMessage) pack() *wireBuffer {
	buffer := getWireBuffer(2 + m.bodySize())
	data := buffer.data
	data[0] = Version
	data[1] = CommandPacket
	m.writeBody(data[2:])
	return buffer
}

func (m *udpMessage) bodySize() int {
	return udpMessageBodyHeaderLen + AddressSerializer.AddrPortLen(m.destination) + len(m.data)
}

func (m *udpMessage) writeBody(data []byte) int {
	binary.BigEndian.PutUint16(data[0:2], m.sessionID)
	binary.BigEndian.PutUint16(data[2:4], m.packetID)
	total := m.fragmentTotal
	if m.fec {
		total |= fecFragmentFlag
	}
	data[4] = total
	data[5] = m.fragmentID
	binary.BigEndian.PutUint16(data[6:8], uint16(len(m.data)))
	addressLen := writeAddrPort(data[udpMessageBodyHeaderLen:], m.destination)
	return udpMessageBodyHeaderLen + addressLen + copy(data[udpMessageBodyHeaderLen+addressLen:], m.data)
}

// udpMessageBodyHeaderLen is the size of the fixed part of a packet message
// after the leading version and command bytes, which the caller already
// consumed.
const udpMessageBodyHeaderLen = udpMessageHeaderLen - 2

// udpMessageHeaderLen is the size of the fixed part of a packet message:
// [version(1)][command(1)][session id(2)][packet id(2)][fragment total(1)]
// [fragment id(1)][data length(2)].
const udpMessageHeaderLen = 10

func (m *udpMessage) headerSize() int {
	return udpMessageHeaderLen + AddressSerializer.AddrPortLen(m.destination)
}

const (
	// initialUDPMTU is the packet size used before the peer reported its own
	// DATAGRAM limit. It matches the QUIC minimum initial packet size.
	initialUDPMTU = 1200 - udpMTUSafetyMargin
	// udpMTUSafetyMargin is subtracted from the size reported by quic-go, as
	// the reported maximum payload is only a conservative estimate.
	udpMTUSafetyMargin = 3
	// maxFragmentCount is the maximum number of fragments a UDP message may be
	// split into: fragmentTotal is a single byte on the wire.
	maxFragmentCount = 255
	// maxDefragmentSize is the maximum size of a reassembled UDP message. The
	// length field of a UDP message is a uint16, so larger messages cannot be
	// represented on the wire.
	maxDefragmentSize = 0xffff
	// maxDefragmentEntries bounds the number of incomplete reassemblies tracked
	// per packet connection. Without a bound an authenticated peer could
	// allocate unbounded state by sending fragments under many packet IDs.
	maxDefragmentEntries = 256
)

// fragUDPMessage splits message so that every fragment fits into maxPacketSize
// bytes. maxPacketSize is derived from the peer-reported DATAGRAM limit, which
// is attacker-controlled: a value which cannot even carry the fragment header
// would make the slicing below panic or the loop below run forever, so it is
// rejected instead.
func fragUDPMessage(message *udpMessage, maxPacketSize int) ([]*udpMessage, error) {
	headerSize := message.headerSize()
	udpMTU := maxPacketSize - headerSize
	if udpMTU <= 0 {
		return nil, E.New("invalid UDP packet size ", maxPacketSize, " for header size ", headerSize)
	}
	if len(message.data) <= udpMTU {
		return []*udpMessage{message}, nil
	}
	fragmentCount := (len(message.data) + udpMTU - 1) / udpMTU
	if fragmentCount > maxFragmentCount {
		return nil, E.New("UDP message of ", len(message.data), " bytes requires ", fragmentCount, " fragments with packet size ", maxPacketSize)
	}
	fragments := make([]*udpMessage, 0, fragmentCount)
	originPacket := message.data
	for remaining := len(originPacket); remaining > 0; remaining -= udpMTU {
		fragment := allocMessage()
		*fragment = *message
		// The payload buffer and its owner stay with the message the fragments
		// were cut from: every fragment points into that buffer, so releasing it
		// with one of them would return memory the others still use. The message
		// is released by its sender once all fragments have been packed.
		fragment.buffer = nil
		fragment.owner = nil
		if remaining > udpMTU {
			fragment.data = originPacket[:udpMTU]
			originPacket = originPacket[udpMTU:]
		} else {
			fragment.data = originPacket
			originPacket = nil
		}
		fragments = append(fragments, fragment)
	}
	// Every fragment keeps the destination of the message it belongs to.
	// Fragments used to carry it in the head fragment only, while the peer
	// creates its session — and makes the routing decision for it — from the
	// first DATAGRAM it receives. DATAGRAM frames are neither retransmitted nor
	// reordered back into place, so the first fragment to arrive may well be a
	// tail one, and the session was then created with an empty destination
	// (":0") and routed by it: with per-destination routing rules in place, such
	// a session ends up on the wrong outbound.
	for index, fragment := range fragments {
		fragment.fragmentID = uint8(index)
		fragment.fragmentTotal = uint8(len(fragments))
	}
	return fragments, nil
}

// datagramMTU converts the maximum DATAGRAM payload size reported by quic-go
// into the packet size used for fragmentation. The peer declares that limit in
// its max_datagram_frame_size transport parameter, so it may be zero, negative
// or too small to carry even a fragment header.
func datagramMTU(maxDatagramPayloadSize int64, headerSize int) (int, error) {
	if maxDatagramPayloadSize <= 0 || maxDatagramPayloadSize > math.MaxInt32 {
		return 0, E.New("invalid datagram payload size reported by peer: ", maxDatagramPayloadSize)
	}
	udpMTU := int(maxDatagramPayloadSize) - udpMTUSafetyMargin
	if udpMTU <= headerSize {
		return 0, E.New("datagram payload size reported by peer (", maxDatagramPayloadSize, ") cannot carry the fragmentation header (", headerSize, ")")
	}
	return udpMTU, nil
}

// initialUDPPacketSize seeds the packet size used for fragmentation from the
// DATAGRAM payload limit the connection reports for the peer. Without it every
// session starts at the QUIC minimum of 1200 bytes and learns the real limit
// only from a rejected DATAGRAM: a path which can carry 1400 bytes then keeps
// splitting every message above ~1180 bytes into two frames for its whole
// lifetime. A limit which cannot carry the fragment header is ignored, and the
// per-message validation in writeMessage rejects it if the peer reported it
// anyway.
func initialUDPPacketSize(maxDatagramPayloadSize int64) int {
	if maxDatagramPayloadSize <= 0 {
		return initialUDPMTU
	}
	udpMTU := int(maxDatagramPayloadSize) - udpMTUSafetyMargin
	if udpMTU <= 0 {
		return initialUDPMTU
	}
	return udpMTU
}

var (
	_ N.NetPacketConn    = (*udpPacketConn)(nil)
	_ N.PacketReadWaiter = (*udpPacketConn)(nil)
)

type udpPacketConn struct {
	ctx             context.Context
	cancel          context.CancelCauseFunc
	sessionID       uint16
	quicConn        *quic.Conn
	data            chan *udpMessage
	udpMTU          atomic.Int64
	packetId        atomic.Uint32
	closeOnce       sync.Once
	isServer        bool
	fec             *fecState
	fecBlock        *fecBlockEncoder
	fecAccess       sync.Mutex
	fecDecoder      *fecBlockDecoder
	defragger       *udpDefragger
	onDestroy       func()
	readWaitOptions N.ReadWaitOptions
	readDeadline    pipe.Deadline
	// addrCache holds the *net.UDPAddr of the last destination handed out by
	// ReadFrom. Converting a Socksaddr allocates the address and its IP slice, and
	// a session that keeps sending to the same destination would pay for it once
	// per received packet. The cached object is only reused for an identical
	// destination, so a caller never sees it change under it.
	addrCache struct {
		destination M.Socksaddr
		addr        *net.UDPAddr
	}
}

func newUDPPacketConn(ctx context.Context, quicConn *quic.Conn, sessionID uint16, isServer bool, fec *fecState, onDestroy func()) *udpPacketConn {
	ctx, cancel := context.WithCancelCause(ctx)
	packetConn := &udpPacketConn{
		ctx:          ctx,
		cancel:       cancel,
		sessionID:    sessionID,
		quicConn:     quicConn,
		data:         make(chan *udpMessage, 64),
		isServer:     isServer,
		fec:          fec,
		defragger:    newUDPDefragger(),
		onDestroy:    onDestroy,
		readDeadline: pipe.MakeDeadline(),
	}
	packetConn.udpMTU.Store(int64(initialUDPPacketSize(quicConn.MaxDatagramPayloadSize())))
	if fec != nil && fec.config.block {
		packetConn.fecBlock = newFECBlockEncoder(fec.config)
	}
	return packetConn
}

// refreshUDPMTU adopts the DATAGRAM payload limit of the connection when it
// grew, which is how a session follows path MTU discovery: the estimate only
// rises while the path is probed, and a limit which shrank is still handled by
// the DatagramTooLargeError retry in writeMessage. The peer's own DATAGRAM
// limit is fixed for the connection, so the connection's limit never falls
// below the value seeded at session creation unless the path changed.
func (c *udpPacketConn) refreshUDPMTU() {
	udpMTU := initialUDPPacketSize(c.quicConn.MaxDatagramPayloadSize())
	if udpMTU > int(c.udpMTU.Load()) {
		c.udpMTU.Store(int64(udpMTU))
	}
}

func (c *udpPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	select {
	case p := <-c.data:
		_, err = buffer.Write(p.data)
		destination = p.destination
		p.releaseMessage()
		return
	case <-c.ctx.Done():
		return M.Socksaddr{}, io.ErrClosedPipe
	case <-c.readDeadline.Wait():
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}

func (c *udpPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case pkt := <-c.data:
		n = copy(p, pkt.data)
		if pkt.destination.IsDomain() {
			addr = pkt.destination
		} else {
			addr = c.destinationAddr(pkt.destination)
		}
		pkt.releaseMessage()
		return n, addr, nil
	case <-c.ctx.Done():
		return 0, nil, io.ErrClosedPipe
	case <-c.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}

// destinationAddr returns the *net.UDPAddr of destination, reusing the previous
// one when the destination did not change.
func (c *udpPacketConn) destinationAddr(destination M.Socksaddr) *net.UDPAddr {
	if c.addrCache.addr != nil && c.addrCache.destination == destination {
		return c.addrCache.addr
	}
	addr := destination.UDPAddr()
	c.addrCache.destination = destination
	c.addrCache.addr = addr
	return addr
}

func (c *udpPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	select {
	case <-c.ctx.Done():
		buffer.Release()
		return net.ErrClosed
	default:
	}
	if buffer.Len() > 0xffff {
		buffer.Release()
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 0xffff}
	}
	if !destination.IsValid() {
		buffer.Release()
		return E.New("invalid destination address")
	}
	packetId := uint16(c.packetId.Add(1) % math.MaxUint16)
	message := allocMessage()
	// The buffer is taken over by the message: it holds the payload until the
	// message was packed, and releaseMessage returns it to the pool.
	*message = udpMessage{
		sessionID:     c.sessionID,
		packetID:      packetId,
		fragmentTotal: 1,
		destination:   destination,
		data:          buffer.Bytes(),
		buffer:        buffer,
	}
	defer message.releaseMessage()
	return c.writeMessage(message)
}

func (c *udpPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	select {
	case <-c.ctx.Done():
		return 0, net.ErrClosed
	default:
	}
	if len(p) > 0xffff {
		return 0, &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 0xffff}
	}
	destination := M.SocksaddrFromNet(addr)
	if !destination.IsValid() {
		return 0, E.New("invalid destination address")
	}
	packetId := uint16(c.packetId.Add(1) % math.MaxUint16)
	message := allocMessage()
	*message = udpMessage{
		sessionID:     c.sessionID,
		packetID:      packetId,
		fragmentTotal: 1,
		destination:   destination,
		data:          p,
	}
	defer message.releaseMessage()
	err = c.writeMessage(message)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// writeMessage sends message, fragmenting it when it does not fit into the
// current MTU, and retries once with the MTU reported by quic-go when the
// DATAGRAM was rejected as too large.
func (c *udpPacketConn) writeMessage(message *udpMessage) error {
	c.refreshUDPMTU()
	udpMTU := int(c.udpMTU.Load())
	if c.fec.blockEnabled() && c.fecBlock != nil && c.fecBlock.currentParity() > 0 && len(message.data)+message.headerSize()+fecBlockHeaderLen <= udpMTU {
		return c.writeFECBlockMessage(message)
	}
	var err error
	if len(message.data) > udpMTU-message.headerSize() {
		err = c.writeFragments(message, udpMTU)
	} else {
		err = c.writePacket(message)
	}
	if err == nil {
		return nil
	}
	var tooLargeErr *quic.DatagramTooLargeError
	if !errors.As(err, &tooLargeErr) {
		return err
	}
	udpMTU, mtuErr := datagramMTU(tooLargeErr.MaxDatagramPayloadSize, message.headerSize())
	if mtuErr != nil {
		return E.Errors(err, mtuErr)
	}
	c.udpMTU.Store(int64(udpMTU))
	return c.writeFragments(message, udpMTU)
}

func (c *udpPacketConn) writeFragments(message *udpMessage, udpMTU int) error {
	fragSize := udpMTU
	if c.fec.intraMessageEnabled() {
		fragSize -= fecParityLengthLen
	}
	fragments, err := fragUDPMessage(message, fragSize)
	if err != nil {
		return err
	}
	if c.fec.intraMessageEnabled() {
		parity, parityErr := buildParityFragment(fragments)
		if parityErr != nil {
			releaseMessages(fragments)
			return parityErr
		}
		if parity != nil {
			fragments = append(fragments, parity)
		}
	}
	return c.writePackets(fragments)
}

func (c *udpPacketConn) inputPacket(message *udpMessage) error {
	if !message.fec && message.fragmentTotal <= 1 {
		select {
		case c.data <- message:
		default:
			message.releaseMessage()
		}
		return nil
	}
	newMessage, err := c.defragger.feed(message)
	if err != nil {
		return err
	}
	if newMessage != nil {
		select {
		case c.data <- newMessage:
		default:
			newMessage.releaseMessage()
		}
	}
	return nil
}

func (c *udpPacketConn) writePackets(messages []*udpMessage) error {
	defer releaseMessages(messages)
	for _, message := range messages {
		err := c.writePacket(message)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *udpPacketConn) writePacket(message *udpMessage) error {
	// The packed message is handed over to quic-go instead of being copied into
	// a datagram: quic-go writes it into the packet as it is and returns the
	// buffer to the pool once the datagram was sent out or dropped.
	buffer := message.pack()
	return c.quicConn.SendDatagramOwned(buffer.data, buffer)
}
func (c *udpPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeWithError(os.ErrClosed)
		c.onDestroy()
	})
	return nil
}

func (c *udpPacketConn) closeWithError(err error) {
	c.cancel(err)
	if !c.isServer {
		buffer := buf.NewSize(4)
		defer buffer.Release()
		buffer.WriteByte(Version)
		buffer.WriteByte(CommandDissociate)
		binary.Write(buffer, binary.BigEndian, c.sessionID)
		sendStream, openErr := c.quicConn.OpenUniStream()
		if openErr != nil {
			return
		}
		defer sendStream.Close()
		sendStream.Write(buffer.Bytes())
	}
}

func (c *udpPacketConn) LocalAddr() net.Addr {
	return c.quicConn.LocalAddr()
}

func (c *udpPacketConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *udpPacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

func (c *udpPacketConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

type udpDefragger struct {
	packetMap *cache.LruCache[uint16, *packetItem]
}

func newUDPDefragger() *udpDefragger {
	return &udpDefragger{
		packetMap: cache.New(
			cache.WithAge[uint16, *packetItem](10),
			cache.WithUpdateAgeOnGet[uint16, *packetItem](),
			// Reassembly state is created from peer-controlled packet IDs, so
			// both the number of tracked packets and the size of a single
			// reassembly are bounded.
			cache.WithSize[uint16, *packetItem](maxDefragmentEntries),
			cache.WithEvict[uint16, *packetItem](func(_ uint16, value *packetItem) {
				releasePacketItem(value)
			}),
		),
	}
}

// releasePacketItem drops the messages buffered by an evicted or aborted
// reassembly. The eviction callback runs while the cache lock is held, so it
// must not call back into the cache, and it takes the item lock to stay safe
// against a concurrent feed.
func releasePacketItem(item *packetItem) {
	item.access.Lock()
	messages := item.messages
	item.messages = nil
	parity := item.parity
	item.parity = nil
	item.count = 0
	item.length = 0
	item.access.Unlock()
	releaseMessages(messages)
	if parity != nil {
		parity.releaseMessage()
	}
}

type packetItem struct {
	access   sync.Mutex
	messages []*udpMessage
	parity   *udpMessage
	fec      bool
	count    uint8
	length   int
}

func (i *packetItem) resetLocked() {
	releaseMessages(i.messages)
	i.messages = nil
	if i.parity != nil {
		i.parity.releaseMessage()
		i.parity = nil
	}
	i.count = 0
	i.length = 0
}

// feed adds a fragment to its reassembly buffer and returns the complete
// message once the last fragment arrived, or the repaired message once a
// parity fragment filled the single hole. Every error is a protocol violation
// reported by the peer.
func (d *udpDefragger) feed(m *udpMessage) (*udpMessage, error) {
	dataTotal := m.fragmentTotal
	fec := m.fec
	if !fec && dataTotal <= 1 {
		return m, nil
	}
	packetID := m.packetID
	fragmentID := m.fragmentID
	if fec {
		if dataTotal < 2 || dataTotal > fecMaxDataFragments {
			m.releaseMessage()
			return nil, E.New("invalid fec fragment count ", dataTotal)
		}
		if fragmentID > dataTotal {
			m.releaseMessage()
			return nil, E.New("invalid fec fragment ", fragmentID, " of ", dataTotal)
		}
	} else if fragmentID >= dataTotal {
		m.releaseMessage()
		return nil, E.New("invalid fragment ", fragmentID, " of ", dataTotal)
	}
	item, _ := d.packetMap.LoadOrStore(packetID, newPacketItem)
	item.access.Lock()
	if item.fec != fec || len(item.messages) != int(dataTotal) {
		item.resetLocked()
		item.fec = fec
		item.messages = make([]*udpMessage, dataTotal)
	}
	if fragmentID == dataTotal {
		if item.parity != nil {
			item.access.Unlock()
			m.releaseMessage()
			return nil, nil
		}
		if len(m.data) < fecParityLengthLen {
			item.access.Unlock()
			m.releaseMessage()
			return nil, E.New("invalid fec parity fragment")
		}
		item.parity = m
		if int(item.count) != int(dataTotal)-1 {
			item.access.Unlock()
			return nil, nil
		}
		return d.recoverLocked(item, packetID)
	}
	if item.messages[fragmentID] != nil {
		item.access.Unlock()
		m.releaseMessage()
		return nil, nil
	}
	if item.length+len(m.data) > maxDefragmentSize {
		item.resetLocked()
		item.access.Unlock()
		d.packetMap.Delete(packetID)
		m.releaseMessage()
		return nil, E.New("reassembled UDP message exceeds ", maxDefragmentSize, " bytes")
	}
	item.messages[fragmentID] = m
	item.count++
	item.length += len(m.data)
	if int(item.count) == len(item.messages) {
		return d.completeLocked(item, packetID)
	}
	if fec && item.parity != nil && int(item.count) == len(item.messages)-1 {
		return d.recoverLocked(item, packetID)
	}
	item.access.Unlock()
	return nil, nil
}

func (d *udpDefragger) completeLocked(item *packetItem, packetID uint16) (*udpMessage, error) {
	newMessage := allocMessage()
	*newMessage = *item.messages[0]
	newMessage.fragmentTotal = 1
	newMessage.fragmentID = 0
	newMessage.fec = false
	newMessage.buffer = nil
	reassembled := getWireBuffer(item.length)
	newMessage.owner = reassembled
	newMessage.data = reassembled.data[:0]
	for _, message := range item.messages {
		newMessage.data = append(newMessage.data, message.data...)
		message.releaseMessage()
	}
	parity := item.parity
	item.messages = nil
	item.parity = nil
	item.count = 0
	item.length = 0
	item.access.Unlock()
	if parity != nil {
		parity.releaseMessage()
	}
	d.packetMap.Delete(packetID)
	return newMessage, nil
}

func (d *udpDefragger) recoverLocked(item *packetItem, packetID uint16) (*udpMessage, error) {
	parity := item.parity
	if parity == nil || len(parity.data) < fecParityLengthLen {
		item.resetLocked()
		item.access.Unlock()
		d.packetMap.Delete(packetID)
		return nil, E.New("invalid fec parity fragment")
	}
	totalLen := int(binary.BigEndian.Uint16(parity.data[:fecParityLengthLen]))
	body := parity.data[fecParityLengthLen:]
	missing := -1
	presentLen := 0
	var template *udpMessage
	for index, message := range item.messages {
		if message == nil {
			if missing >= 0 {
				item.resetLocked()
				item.access.Unlock()
				d.packetMap.Delete(packetID)
				return nil, nil
			}
			missing = index
			continue
		}
		if template == nil {
			template = message
		}
		presentLen += len(message.data)
	}
	if template == nil {
		item.resetLocked()
		item.access.Unlock()
		d.packetMap.Delete(packetID)
		return nil, E.New("fec reassembly has no buffered fragment")
	}
	missingLen := totalLen - presentLen
	if missingLen <= 0 || missingLen > len(body) {
		item.resetLocked()
		item.access.Unlock()
		d.packetMap.Delete(packetID)
		return nil, E.New("fec parity does not match the buffered fragments")
	}
	recovered := getWireBuffer(missingLen)
	copy(recovered.data, body[:missingLen])
	for _, message := range item.messages {
		if message != nil {
			xorBytes(recovered.data, message.data)
		}
	}
	reassembled := getWireBuffer(totalLen)
	reassembled.data = reassembled.data[:0]
	for index, message := range item.messages {
		if index == missing {
			reassembled.data = append(reassembled.data, recovered.data...)
			continue
		}
		reassembled.data = append(reassembled.data, message.data...)
	}
	recovered.ReleaseDatagramBuffer()
	newMessage := allocMessage()
	*newMessage = *template
	newMessage.fragmentTotal = 1
	newMessage.fragmentID = 0
	newMessage.fec = false
	newMessage.buffer = nil
	newMessage.owner = reassembled
	newMessage.data = reassembled.data
	releaseMessages(item.messages)
	item.messages = nil
	item.parity = nil
	item.count = 0
	item.length = 0
	item.access.Unlock()
	parity.releaseMessage()
	d.packetMap.Delete(packetID)
	return newMessage, nil
}

func newPacketItem() *packetItem {
	return new(packetItem)
}

// decodeUDPMessage parses the payload of a packet message, which is the message
// carrying one forwarded UDP packet.
//
// It is parsed by offset instead of through binary.Read on a bytes.Reader: that
// decoder is reflection based, allocates a reader plus one allocation per field
// and showed up as the single largest QUICX cost in a datagram forwarding
// profile (around 8% of the client CPU, most of it in the address parser).
func decodeUDPMessage(message *udpMessage, data []byte, owner quic.DatagramBufferOwner) error {
	// The payload owner is taken over right away, so that every error path below
	// releases it together with the message.
	message.owner = owner
	if len(data) < udpMessageBodyHeaderLen {
		return io.ErrUnexpectedEOF
	}
	message.sessionID = binary.BigEndian.Uint16(data[0:2])
	message.packetID = binary.BigEndian.Uint16(data[2:4])
	message.fragmentTotal, message.fec = fecDataFragmentCount(data[4])
	message.fragmentID = data[5]
	dataLength := int(binary.BigEndian.Uint16(data[6:8]))
	destination, addressLen, err := decodeAddrPort(data[udpMessageBodyHeaderLen:])
	if err != nil {
		return err
	}
	payload := data[udpMessageBodyHeaderLen+addressLen:]
	if len(payload) != dataLength {
		return io.ErrUnexpectedEOF
	}
	message.destination = destination
	message.data = payload
	return nil
}

// Address family bytes of AddressSerializer, see the serializer options in
// address.go.
const (
	addressFamilyFqdn  = 0x00
	addressFamilyIPv4  = 0x01
	addressFamilyIPv6  = 0x02
	addressFamilyEmpty = 0xff
)

// decodeAddrPort parses a serialized destination and reports how many bytes it
// consumed. The encoding is the one AddressSerializer writes: an address family
// byte, the address, and a port when the address is valid.
func decodeAddrPort(data []byte) (M.Socksaddr, int, error) {
	if len(data) < 1 {
		return M.Socksaddr{}, 0, io.ErrUnexpectedEOF
	}
	switch data[0] {
	case addressFamilyIPv4:
		if len(data) < 1+4+2 {
			return M.Socksaddr{}, 0, io.ErrUnexpectedEOF
		}
		var address [4]byte
		copy(address[:], data[1:5])
		return M.Socksaddr{Addr: netip.AddrFrom4(address), Port: binary.BigEndian.Uint16(data[5:7])}, 7, nil
	case addressFamilyIPv6:
		if len(data) < 1+16+2 {
			return M.Socksaddr{}, 0, io.ErrUnexpectedEOF
		}
		var address [16]byte
		copy(address[:], data[1:17])
		return M.Socksaddr{Addr: netip.AddrFrom16(address), Port: binary.BigEndian.Uint16(data[17:19])}.Unwrap(), 19, nil
	case addressFamilyFqdn:
		if len(data) < 2 {
			return M.Socksaddr{}, 0, io.ErrUnexpectedEOF
		}
		fqdnLen := int(data[1])
		if len(data) < 2+fqdnLen+2 {
			return M.Socksaddr{}, 0, io.ErrUnexpectedEOF
		}
		fqdn := string(data[2 : 2+fqdnLen])
		port := binary.BigEndian.Uint16(data[2+fqdnLen : 4+fqdnLen])
		return M.ParseSocksaddrHostPort(fqdn, port), 4 + fqdnLen, nil
	case addressFamilyEmpty:
		return M.Socksaddr{}, 1, nil
	default:
		return M.Socksaddr{}, 0, E.New("unknown address family ", data[0])
	}
}
