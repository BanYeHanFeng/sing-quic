package quicx

import (
	"encoding/binary"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/reedsolomon"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	fecParityShardFlag = 0x80
	fecShardIndexMask  = 0x7f
	fecBlockHeaderLen  = 9
	fecBlockTTL        = 2 * time.Second
	maxFECBlocks       = 16
	fecReportBlocks    = 16
	fecReportInterval  = 250 * time.Millisecond
	fecParityFactor    = 2
)

type fecFrame struct {
	shardIndex uint8
	k          uint8
	m          uint8
	payload    []byte
}

type fecEmitFunc func(blockID uint16, frame fecFrame) error

type fecPacket struct {
	sessionID  uint16
	blockID    uint16
	shardIndex uint8
	k          uint8
	m          uint8
	payload    []byte
}

var fecEncoderCache sync.Map

func fecEncoder(k, m int) (reedsolomon.Encoder, error) {
	key := uint16(k)<<8 | uint16(m)
	if cached, loaded := fecEncoderCache.Load(key); loaded {
		return cached.(reedsolomon.Encoder), nil
	}
	encoder, err := reedsolomon.New(k, m)
	if err != nil {
		return nil, err
	}
	actual, _ := fecEncoderCache.LoadOrStore(key, encoder)
	return actual.(reedsolomon.Encoder), nil
}

func fecParityForLoss(k int, lossPerMille uint16, maxParity int) int {
	if lossPerMille == 0 || k < 2 {
		return 0
	}
	if lossPerMille >= 1000 {
		return maxParity
	}
	loss := float64(lossPerMille) / 1000
	parity := int(math.Ceil(float64(k) * loss / (1 - loss) * fecParityFactor))
	if parity < 1 {
		parity = 1
	}
	if parity > maxParity {
		parity = maxParity
	}
	return parity
}

func fecTrimBody(body []byte) ([]byte, error) {
	if len(body) < 9 {
		return nil, io.ErrUnexpectedEOF
	}
	dataLen := int(binary.BigEndian.Uint16(body[6:8]))
	var addressLen int
	switch body[8] {
	case addressFamilyIPv4:
		addressLen = 7
	case addressFamilyIPv6:
		addressLen = 19
	case addressFamilyFqdn:
		if len(body) < 10 {
			return nil, io.ErrUnexpectedEOF
		}
		addressLen = 4 + int(body[9])
	case addressFamilyEmpty:
		addressLen = 1
	default:
		return nil, E.New("unknown address family ", body[8])
	}
	total := udpMessageBodyHeaderLen + addressLen + dataLen
	if total > len(body) {
		return nil, io.ErrUnexpectedEOF
	}
	return body[:total], nil
}

type fecEncodeBlock struct {
	id     uint16
	bodies [][]byte
	timer  *time.Timer
}

func (b *fecEncodeBlock) reset() {
	b.bodies = nil
}

type fecBlockEncoder struct {
	access  sync.Mutex
	config  fecConfig
	blocks  []*fecEncodeBlock
	seq     uint64
	blockID uint16
	parity  atomic.Int32
	closed  bool
}

func newFECBlockEncoder(config fecConfig) *fecBlockEncoder {
	encoder := &fecBlockEncoder{
		config: config,
		blocks: make([]*fecEncodeBlock, config.interleave),
	}
	for index := range encoder.blocks {
		encoder.blocks[index] = new(fecEncodeBlock)
	}
	encoder.parity.Store(int32(config.parity))
	return encoder
}

func (e *fecBlockEncoder) currentParity() int {
	return int(e.parity.Load())
}

func (e *fecBlockEncoder) setParity(parity int) {
	if parity < 0 {
		parity = 0
	}
	if parity > e.config.maxParity {
		parity = e.config.maxParity
	}
	e.parity.Store(int32(parity))
}

func (e *fecBlockEncoder) write(body []byte, emit fecEmitFunc) error {
	e.access.Lock()
	defer e.access.Unlock()
	if e.closed {
		return io.ErrClosedPipe
	}
	block := e.blocks[e.seq%uint64(len(e.blocks))]
	e.seq++
	if len(block.bodies) == 0 {
		e.blockID++
		block.id = e.blockID
		block.timer = time.AfterFunc(e.config.blockTimeout, func() {
			e.flushBlock(block, emit)
		})
	}
	index := len(block.bodies)
	stored := make([]byte, len(body))
	copy(stored, body)
	block.bodies = append(block.bodies, stored)
	err := emit(block.id, fecFrame{shardIndex: uint8(index), k: uint8(e.config.blockSize), m: uint8(e.currentParity()), payload: body})
	if len(block.bodies) >= e.config.blockSize {
		flushErr := e.flushLocked(block, emit)
		if err == nil {
			err = flushErr
		}
	}
	return err
}

func (e *fecBlockEncoder) flushBlock(block *fecEncodeBlock, emit fecEmitFunc) {
	e.access.Lock()
	defer e.access.Unlock()
	if len(block.bodies) == 0 {
		return
	}
	_ = e.flushLocked(block, emit)
}

func (e *fecBlockEncoder) flushLocked(block *fecEncodeBlock, emit fecEmitFunc) error {
	if block.timer != nil {
		block.timer.Stop()
		block.timer = nil
	}
	count := len(block.bodies)
	parity := e.currentParity()
	if count < 2 || parity < 1 {
		err := emit(block.id, fecFrame{shardIndex: fecParityShardFlag, k: uint8(count), m: 0})
		block.reset()
		return err
	}
	maxLen := 0
	for _, body := range block.bodies {
		if len(body) > maxLen {
			maxLen = len(body)
		}
	}
	encoder, err := fecEncoder(count, parity)
	if err != nil {
		emit(block.id, fecFrame{shardIndex: fecParityShardFlag, k: uint8(count), m: 0})
		block.reset()
		return err
	}
	shards := make([][]byte, count+parity)
	for index := 0; index < count; index++ {
		shard := make([]byte, maxLen)
		copy(shard, block.bodies[index])
		shards[index] = shard
	}
	for index := count; index < count+parity; index++ {
		shards[index] = make([]byte, maxLen)
	}
	if err = encoder.Encode(shards); err != nil {
		emit(block.id, fecFrame{shardIndex: fecParityShardFlag, k: uint8(count), m: 0})
		block.reset()
		return err
	}
	for index := 0; index < parity; index++ {
		emitErr := emit(block.id, fecFrame{
			shardIndex: fecParityShardFlag | uint8(index),
			k:          uint8(count),
			m:          uint8(parity),
			payload:    shards[count+index],
		})
		if emitErr != nil {
			err = emitErr
		}
	}
	block.reset()
	return err
}

type fecDecodeBlock struct {
	id        uint16
	kCapacity int
	k         int
	m         int
	data      [][]byte
	parity    [][]byte
	payloads  int
	created   time.Time
}

type fecBlockDecoder struct {
	access       sync.Mutex
	config       fecConfig
	blocks       map[uint16]*fecDecodeBlock
	order        []uint16
	lost         int
	total        int
	closedBlocks int
	lastReport   time.Time
	report       func(lossPerMille uint16)
}

type fecDeliverFunc func(body []byte) error

func newFECBlockDecoder(config fecConfig, report func(lossPerMille uint16)) *fecBlockDecoder {
	return &fecBlockDecoder{
		config:     config,
		blocks:     make(map[uint16]*fecDecodeBlock),
		report:     report,
		lastReport: time.Now(),
	}
}

func (d *fecBlockDecoder) input(blockID uint16, shardIndex, k, m uint8, payload []byte, deliver fecDeliverFunc) error {
	d.access.Lock()
	defer d.access.Unlock()
	parityShard := shardIndex&fecParityShardFlag != 0
	block := d.blocks[blockID]
	if block == nil {
		block = &fecDecodeBlock{
			id:        blockID,
			kCapacity: int(k),
			k:         int(k),
			m:         int(m),
			created:   time.Now(),
		}
		if block.kCapacity < 1 || block.kCapacity > maxFECBlockSize || int(m) > maxFECParity {
			return E.New("invalid fec block header ", k, "/", m)
		}
		d.storeLocked(block)
	}
	if parityShard {
		if int(m) == 0 {
			block.k = int(k)
			block.m = 0
			if block.k < 1 || block.k > block.kCapacity {
				d.closeLocked(block)
				return E.New("invalid fec block size ", k)
			}
			return d.finishLocked(block, deliver)
		}
		if int(m) > maxFECParity || int(k) > block.kCapacity || int(k) < 1 {
			return E.New("invalid fec parity header ", k, "/", m)
		}
		block.k = int(k)
		block.m = int(m)
		if block.parity == nil {
			block.parity = make([][]byte, block.m)
		}
		index := int(shardIndex & fecShardIndexMask)
		if index >= block.m {
			return E.New("invalid fec parity index ", index)
		}
		if block.parity[index] == nil {
			block.parity[index] = copyFECPayload(payload)
			block.payloads += len(payload)
		}
		return d.finishLocked(block, deliver)
	}
	index := int(shardIndex & fecShardIndexMask)
	if index >= block.kCapacity {
		return E.New("invalid fec shard index ", index)
	}
	if block.data == nil {
		block.data = make([][]byte, block.kCapacity)
	}
	if block.data[index] != nil {
		return nil
	}
	stored := copyFECPayload(payload)
	block.data[index] = stored
	block.payloads += len(payload)
	if err := deliver(stored); err != nil {
		return err
	}
	return d.finishLocked(block, deliver)
}

func copyFECPayload(payload []byte) []byte {
	body := make([]byte, len(payload))
	copy(body, payload)
	return body
}

func (d *fecBlockDecoder) storeLocked(block *fecDecodeBlock) {
	d.expireLocked()
	d.blocks[block.id] = block
	d.order = append(d.order, block.id)
	for len(d.order) > maxFECBlocks {
		oldest := d.order[0]
		d.order = d.order[1:]
		if evicted, loaded := d.blocks[oldest]; loaded {
			d.closeLocked(evicted)
		}
	}
}

func (d *fecBlockDecoder) expireLocked() {
	now := time.Now()
	for id, block := range d.blocks {
		if now.Sub(block.created) > fecBlockTTL {
			d.closeLocked(block)
			delete(d.blocks, id)
		}
	}
}

func (d *fecBlockDecoder) finishLocked(block *fecDecodeBlock, deliver fecDeliverFunc) error {
	if block.k <= 0 {
		return nil
	}
	dataReceived := 0
	missing := 0
	for index := 0; index < block.k; index++ {
		if block.data != nil && index < len(block.data) && block.data[index] != nil {
			dataReceived++
		} else {
			missing++
		}
	}
	if missing == 0 {
		d.closeLocked(block)
		return nil
	}
	parityReceived := 0
	for index := 0; index < block.m; index++ {
		if block.parity != nil && index < len(block.parity) && block.parity[index] != nil {
			parityReceived++
		}
	}
	if block.m < 1 || dataReceived+parityReceived < block.k {
		return nil
	}
	encoder, err := fecEncoder(block.k, block.m)
	if err != nil {
		d.closeLocked(block)
		return nil
	}
	shards := make([][]byte, block.k+block.m)
	for index := 0; index < block.k; index++ {
		if block.data != nil && index < len(block.data) {
			shards[index] = block.data[index]
		}
	}
	for index := 0; index < block.m; index++ {
		if block.parity != nil && index < len(block.parity) {
			shards[block.k+index] = block.parity[index]
		}
	}
	if err = encoder.Reconstruct(shards); err != nil {
		d.closeLocked(block)
		return nil
	}
	for index := 0; index < block.k; index++ {
		if block.data != nil && index < len(block.data) && block.data[index] != nil {
			continue
		}
		body, trimErr := fecTrimBody(shards[index])
		if trimErr != nil {
			continue
		}
		if err = deliver(body); err != nil {
			return err
		}
	}
	d.closeLocked(block)
	return nil
}

func (d *fecBlockDecoder) closeLocked(block *fecDecodeBlock) {
	dataReceived := 0
	missing := 0
	for index := 0; index < block.k; index++ {
		if block.data == nil || index >= len(block.data) || block.data[index] == nil {
			missing++
		} else {
			dataReceived++
		}
	}
	delete(d.blocks, block.id)
	if dataReceived == 0 {
		return
	}
	d.total += block.k
	d.lost += missing
	d.closedBlocks++
	if d.report != nil && d.total > 0 {
		if d.closedBlocks >= fecReportBlocks || time.Since(d.lastReport) >= fecReportInterval {
			lossPerMille := uint16(1000 * d.lost / d.total)
			d.report(lossPerMille)
			d.lost = 0
			d.total = 0
			d.closedBlocks = 0
			d.lastReport = time.Now()
		}
	}
}
