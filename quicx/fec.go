package quicx

import (
	"encoding/binary"
	"sync/atomic"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	fecFragmentFlag     = 0x80
	fecFragmentMask     = 0x7f
	fecMaxDataFragments = fecFragmentMask - 1
	fecParityLengthLen  = 2
)

const (
	capabilityIntraMessageFEC = 1 << 0
	capabilityBlockFEC        = 1 << 1
)

const (
	defaultFECBlockSize    = 10
	defaultFECParity       = 2
	defaultFECMaxParity    = 4
	defaultFECInterleave   = 4
	defaultFECBlockTimeout = 10 * time.Millisecond
	maxFECBlockSize        = 32
	maxFECParity           = 8
	maxFECInterleave       = 16
)

type FECOptions struct {
	Enabled      bool
	Block        bool
	BlockSize    int
	Parity       int
	MaxParity    int
	Interleave   int
	BlockTimeout time.Duration
}

type fecConfig struct {
	enabled      bool
	block        bool
	blockSize    int
	parity       int
	maxParity    int
	interleave   int
	blockTimeout time.Duration
}

func (o FECOptions) build() fecConfig {
	config := fecConfig{
		enabled:      o.Enabled,
		block:        o.Block,
		blockSize:    o.BlockSize,
		parity:       o.Parity,
		maxParity:    o.MaxParity,
		interleave:   o.Interleave,
		blockTimeout: o.BlockTimeout,
	}
	if !config.enabled {
		return fecConfig{}
	}
	if config.blockSize <= 0 {
		config.blockSize = defaultFECBlockSize
	}
	if config.blockSize > maxFECBlockSize {
		config.blockSize = maxFECBlockSize
	}
	if config.parity <= 0 {
		config.parity = defaultFECParity
	}
	if config.maxParity <= 0 {
		config.maxParity = defaultFECMaxParity
	}
	if config.maxParity < config.parity {
		config.maxParity = config.parity
	}
	if config.maxParity > maxFECParity {
		config.maxParity = maxFECParity
	}
	if config.interleave <= 0 {
		config.interleave = defaultFECInterleave
	}
	if config.interleave > maxFECInterleave {
		config.interleave = maxFECInterleave
	}
	if config.blockTimeout <= 0 {
		config.blockTimeout = defaultFECBlockTimeout
	}
	return config
}

func (c fecConfig) capabilities() uint8 {
	if !c.enabled {
		return 0
	}
	flags := uint8(capabilityIntraMessageFEC)
	if c.block {
		flags |= capabilityBlockFEC
	}
	return flags
}

type fecState struct {
	config fecConfig
	peer   atomic.Uint32
	ready  atomic.Bool
}

func newFECState(config fecConfig) *fecState {
	return &fecState{config: config}
}

func (s *fecState) setPeerCapabilities(flags uint8) {
	s.peer.Store(uint32(flags))
	s.ready.Store(true)
}

func (s *fecState) intraMessageEnabled() bool {
	if s == nil || !s.config.enabled {
		return false
	}
	return s.ready.Load() && s.peer.Load()&capabilityIntraMessageFEC != 0
}

func (s *fecState) blockEnabled() bool {
	if s == nil || !s.config.block {
		return false
	}
	return s.ready.Load() && s.peer.Load()&capabilityBlockFEC != 0
}

func fecDataFragmentCount(total uint8) (uint8, bool) {
	return total & fecFragmentMask, total&fecFragmentFlag != 0
}

func xorBytes(dst, src []byte) {
	n := len(src)
	if len(dst) < n {
		n = len(dst)
	}
	i := 0
	for ; i+8 <= n; i += 8 {
		binary.BigEndian.PutUint64(dst[i:i+8], binary.BigEndian.Uint64(dst[i:i+8])^binary.BigEndian.Uint64(src[i:i+8]))
	}
	for ; i < n; i++ {
		dst[i] ^= src[i]
	}
}

func buildParityFragment(fragments []*udpMessage) (*udpMessage, error) {
	count := len(fragments)
	if count < 2 || count > fecMaxDataFragments {
		return nil, nil
	}
	maxLen := 0
	totalLen := 0
	for _, fragment := range fragments {
		if len(fragment.data) > maxLen {
			maxLen = len(fragment.data)
		}
		totalLen += len(fragment.data)
	}
	if maxLen == 0 {
		return nil, nil
	}
	if totalLen > maxDefragmentSize {
		return nil, E.New("message of ", totalLen, " bytes cannot carry a parity fragment")
	}
	buffer := getWireBuffer(fecParityLengthLen + maxLen)
	data := buffer.data
	binary.BigEndian.PutUint16(data[:fecParityLengthLen], uint16(totalLen))
	body := data[fecParityLengthLen:]
	clear(body)
	for _, fragment := range fragments {
		xorBytes(body, fragment.data)
	}
	parity := allocMessage()
	*parity = *fragments[0]
	parity.buffer = nil
	parity.owner = buffer
	parity.data = data
	parity.fragmentTotal = uint8(count)
	parity.fragmentID = uint8(count)
	parity.fec = true
	for _, fragment := range fragments {
		fragment.fec = true
		fragment.fragmentTotal = uint8(count)
	}
	return parity, nil
}
