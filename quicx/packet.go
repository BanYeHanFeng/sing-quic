package quicx

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common"
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
	destination   M.Socksaddr
	data          *buf.Buffer
	referenced    bool
}

func (m *udpMessage) release() {
	if !m.referenced {
		return
	}
	*m = udpMessage{}
	udpMessagePool.Put(m)
}

func (m *udpMessage) releaseMessage() {
	m.data.Release()
	m.release()
}

func (m *udpMessage) pack() *buf.Buffer {
	buffer := buf.NewSize(m.headerSize() + m.data.Len())
	common.Must(
		buffer.WriteByte(Version),
		buffer.WriteByte(CommandPacket),
		binary.Write(buffer, binary.BigEndian, m.sessionID),
		binary.Write(buffer, binary.BigEndian, m.packetID),
		binary.Write(buffer, binary.BigEndian, m.fragmentTotal),
		binary.Write(buffer, binary.BigEndian, m.fragmentID),
		binary.Write(buffer, binary.BigEndian, uint16(m.data.Len())),
		AddressSerializer.WriteAddrPort(buffer, m.destination),
		common.Error(buffer.Write(m.data.Bytes())),
	)
	return buffer
}

func (m *udpMessage) headerSize() int {
	return 10 + AddressSerializer.AddrPortLen(m.destination)
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
	if message.data.Len() <= udpMTU {
		return []*udpMessage{message}, nil
	}
	fragmentCount := (message.data.Len() + udpMTU - 1) / udpMTU
	if fragmentCount > maxFragmentCount {
		return nil, E.New("UDP message of ", message.data.Len(), " bytes requires ", fragmentCount, " fragments with packet size ", maxPacketSize)
	}
	fragments := make([]*udpMessage, 0, fragmentCount)
	originPacket := message.data.Bytes()
	for remaining := len(originPacket); remaining > 0; remaining -= udpMTU {
		fragment := allocMessage()
		*fragment = *message
		if remaining > udpMTU {
			fragment.data = buf.As(originPacket[:udpMTU])
			originPacket = originPacket[udpMTU:]
		} else {
			fragment.data = buf.As(originPacket)
			originPacket = nil
		}
		fragments = append(fragments, fragment)
	}
	for index, fragment := range fragments {
		fragment.fragmentID = uint8(index)
		fragment.fragmentTotal = uint8(len(fragments))
		if index > 0 {
			fragment.destination = M.Socksaddr{}
		}
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
	udpMTU          int
	packetId        atomic.Uint32
	closeOnce       sync.Once
	isServer        bool
	defragger       *udpDefragger
	onDestroy       func()
	readWaitOptions N.ReadWaitOptions
	readDeadline    pipe.Deadline
}

func newUDPPacketConn(ctx context.Context, quicConn *quic.Conn, isServer bool, onDestroy func()) *udpPacketConn {
	ctx, cancel := context.WithCancelCause(ctx)
	return &udpPacketConn{
		ctx:          ctx,
		cancel:       cancel,
		quicConn:     quicConn,
		data:         make(chan *udpMessage, 64),
		isServer:     isServer,
		defragger:    newUDPDefragger(),
		onDestroy:    onDestroy,
		udpMTU:       initialUDPMTU,
		readDeadline: pipe.MakeDeadline(),
	}
}

func (c *udpPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	select {
	case p := <-c.data:
		_, err = buffer.ReadOnceFrom(p.data)
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
		n = copy(p, pkt.data.Bytes())
		if pkt.destination.IsDomain() {
			addr = pkt.destination
		} else {
			addr = pkt.destination.UDPAddr()
		}
		pkt.releaseMessage()
		return n, addr, nil
	case <-c.ctx.Done():
		return 0, nil, io.ErrClosedPipe
	case <-c.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *udpPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	select {
	case <-c.ctx.Done():
		return net.ErrClosed
	default:
	}
	if buffer.Len() > 0xffff {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 0xffff}
	}
	if !destination.IsValid() {
		return E.New("invalid destination address")
	}
	packetId := uint16(c.packetId.Add(1) % math.MaxUint16)
	message := allocMessage()
	*message = udpMessage{
		sessionID:     c.sessionID,
		packetID:      packetId,
		fragmentTotal: 1,
		destination:   destination,
		data:          buffer,
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
		data:          buf.As(p),
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
	udpMTU := c.udpMTU
	var err error
	if message.data.Len() > udpMTU-message.headerSize() {
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
	c.udpMTU = udpMTU
	return c.writeFragments(message, udpMTU)
}

func (c *udpPacketConn) writeFragments(message *udpMessage, udpMTU int) error {
	fragments, err := fragUDPMessage(message, udpMTU)
	if err != nil {
		return err
	}
	return c.writePackets(fragments)
}

func (c *udpPacketConn) inputPacket(message *udpMessage) error {
	if message.fragmentTotal <= 1 {
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
	buffer := message.pack()
	err := c.quicConn.SendDatagram(buffer.Bytes())
	buffer.Release()
	return err
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
			cache.WithEvict[uint16, *packetItem](func(key uint16, value *packetItem) {
				releaseMessages(value.messages)
			}),
		),
	}
}

type packetItem struct {
	access   sync.Mutex
	messages []*udpMessage
	count    uint8
	length   int
}

// feed adds a fragment to its reassembly buffer and returns the complete
// message once the last fragment arrived. Every error is a protocol violation
// reported by the peer.
func (d *udpDefragger) feed(m *udpMessage) (*udpMessage, error) {
	if m.fragmentTotal <= 1 {
		return m, nil
	}
	// The message is returned to the pool as soon as it was buffered, so every
	// field which is used afterwards has to be captured first.
	packetID := m.packetID
	fragmentID := m.fragmentID
	fragmentTotal := m.fragmentTotal
	if fragmentID >= fragmentTotal {
		m.releaseMessage()
		return nil, E.New("invalid fragment ", fragmentID, " of ", fragmentTotal)
	}
	item, _ := d.packetMap.LoadOrStore(packetID, newPacketItem)
	item.access.Lock()
	if len(item.messages) != int(fragmentTotal) {
		releaseMessages(item.messages)
		item.messages = make([]*udpMessage, fragmentTotal)
		item.count = 0
		item.length = 0
	}
	if item.messages[fragmentID] != nil {
		item.access.Unlock()
		m.releaseMessage()
		return nil, nil
	}
	if item.length+m.data.Len() > maxDefragmentSize {
		// The reassembled message cannot be represented by the uint16 length
		// field of the wire format. Drop the whole entry instead of
		// accumulating further fragments.
		releaseMessages(item.messages)
		item.messages = nil
		item.count = 0
		item.length = 0
		item.access.Unlock()
		m.releaseMessage()
		return nil, E.New("reassembled UDP message exceeds ", maxDefragmentSize, " bytes")
	}
	item.messages[fragmentID] = m
	item.count++
	item.length += m.data.Len()
	if int(item.count) != len(item.messages) {
		item.access.Unlock()
		return nil, nil
	}
	newMessage := allocMessage()
	*newMessage = *item.messages[0]
	newMessage.fragmentTotal = 1
	newMessage.fragmentID = 0
	// The accumulated length was bounded above, so this allocation fits every
	// fragment.
	newMessage.data = buf.NewSize(item.length)
	var writeErr error
	for _, message := range item.messages {
		if writeErr == nil {
			_, writeErr = newMessage.data.Write(message.data.Bytes())
		}
		message.releaseMessage()
	}
	item.messages = nil
	item.count = 0
	item.length = 0
	item.access.Unlock()
	if writeErr != nil {
		newMessage.releaseMessage()
		return nil, E.Cause(writeErr, "reassemble UDP message")
	}
	return newMessage, nil
}

func newPacketItem() *packetItem {
	return new(packetItem)
}

func readUDPMessage(message *udpMessage, reader io.Reader) error {
	err := binary.Read(reader, binary.BigEndian, &message.sessionID)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.BigEndian, &message.packetID)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.BigEndian, &message.fragmentTotal)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.BigEndian, &message.fragmentID)
	if err != nil {
		return err
	}
	var dataLength uint16
	err = binary.Read(reader, binary.BigEndian, &dataLength)
	if err != nil {
		return err
	}
	message.destination, err = AddressSerializer.ReadAddrPort(reader)
	if err != nil {
		return err
	}
	message.data = buf.NewSize(int(dataLength))
	_, err = message.data.ReadFullFrom(reader, message.data.FreeLen())
	if err != nil {
		return err
	}
	return nil
}

func decodeUDPMessage(message *udpMessage, data []byte) error {
	reader := bytes.NewReader(data)
	err := binary.Read(reader, binary.BigEndian, &message.sessionID)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.BigEndian, &message.packetID)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.BigEndian, &message.fragmentTotal)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.BigEndian, &message.fragmentID)
	if err != nil {
		return err
	}
	var dataLength uint16
	err = binary.Read(reader, binary.BigEndian, &dataLength)
	if err != nil {
		return err
	}
	message.destination, err = AddressSerializer.ReadAddrPort(reader)
	if err != nil {
		return err
	}
	if reader.Len() != int(dataLength) {
		return io.ErrUnexpectedEOF
	}
	message.data = buf.As(data[len(data)-reader.Len():])
	return nil
}
