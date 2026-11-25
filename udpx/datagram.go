package udpx

import (
	"context"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	maxDatagramFragments = 255

	maxDatagramSize = 0xffff

	datagramBacklog = 1024

	maxDatagramReassemblyCount = 64
	maxDatagramReassemblyBytes = 256 * 1024

	datagramReassemblyAge = 4 * time.Second
)

type datagramKey uint16

type datagramReassembly struct {
	parts  [][]byte
	added  time.Time
	size   int
	filled int
}

type datagramDefragger struct {
	entries map[datagramKey]*datagramReassembly
	order   []datagramKey
	bytes   int
}

func newDatagramDefragger() datagramDefragger {
	return datagramDefragger{entries: make(map[datagramKey]*datagramReassembly)}
}

func (d *datagramDefragger) feed(data datagramData, now time.Time) ([]byte, bool, error) {
	if data.total == 0 || data.index >= data.total {
		return nil, false, E.New("invalid datagram fragment ", int(data.index), " of ", int(data.total))
	}
	if data.total == 1 {
		return append(make([]byte, 0, len(data.data)), data.data...), true, nil
	}
	d.expire(now)
	key := datagramKey(data.message)
	reassembly, loaded := d.entries[key]
	if !loaded || len(reassembly.parts) != int(data.total) {
		if loaded {
			d.remove(key)
		}
		reassembly = &datagramReassembly{
			parts: make([][]byte, int(data.total)),
			added: now,
		}
		d.entries[key] = reassembly
		d.order = append(d.order, key)
	}
	if reassembly.parts[data.index] != nil {
		return nil, false, nil
	}
	if reassembly.size+len(data.data) > maxDatagramSize {
		d.remove(key)
		return nil, false, E.New("reassembled datagram exceeds ", maxDatagramSize, " bytes")
	}
	reassembly.parts[data.index] = append([]byte(nil), data.data...)
	reassembly.size += len(data.data)
	reassembly.filled++
	d.bytes += len(data.data)
	for len(d.entries) > maxDatagramReassemblyCount || d.bytes > maxDatagramReassemblyBytes {
		if !d.evictOldest() {
			break
		}
	}
	if reassembly.filled != len(reassembly.parts) {
		return nil, false, nil
	}
	datagram := make([]byte, 0, reassembly.size)
	for _, part := range reassembly.parts {
		datagram = append(datagram, part...)
	}
	d.remove(key)
	return datagram, true, nil
}

func (d *datagramDefragger) expire(now time.Time) {
	for key, reassembly := range d.entries {
		if now.Sub(reassembly.added) >= datagramReassemblyAge {
			d.remove(key)
		}
	}
}

func (d *datagramDefragger) evictOldest() bool {
	for len(d.order) > 0 {
		key := d.order[0]
		d.order = d.order[1:]
		if _, loaded := d.entries[key]; loaded {
			d.remove(key)
			return true
		}
	}
	return false
}

func (d *datagramDefragger) remove(key datagramKey) {
	reassembly, loaded := d.entries[key]
	if !loaded {
		return
	}
	d.bytes -= reassembly.size
	delete(d.entries, key)
}

func (c *Conn) SendDatagram(data []byte) error {
	select {
	case <-c.ctx.Done():
		return context.Cause(c.ctx)
	default:
	}
	if len(data) > maxDatagramSize {
		return E.New("datagram of ", len(data), " bytes is larger than ", maxDatagramSize)
	}
	message := uint16(c.datagramMessage.Add(1))
	c.sendMu.Lock()
	fragmentLen := c.send.payloadSize() - datagramHeaderLen
	fragmentCount := max((len(data)+fragmentLen-1)/fragmentLen, 1)
	if fragmentCount > maxDatagramFragments {
		c.sendMu.Unlock()
		return E.New("datagram of ", len(data), " bytes does not fit in ", maxDatagramFragments, " fragments")
	}
	for index := range fragmentCount {
		start := index * fragmentLen
		end := min(start+fragmentLen, len(data))
		payload := appendDatagramHeader(nil, message, uint8(index), uint8(fragmentCount), end-start)
		payload = append(payload, data[start:end]...)
		c.send.queueData(outFrame{payload: payload})
	}
	c.sendMu.Unlock()
	c.wake()
	return nil
}

func (c *Conn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case datagram := <-c.datagrams:
		return datagram, nil
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-c.ctx.Done():
		return nil, context.Cause(c.ctx)
	}
}

func (c *Conn) handleDatagram(body []byte) error {
	if len(body) < 4 {
		return errShortFrame
	}
	data := parseDatagram(body)
	message, complete, err := c.defragger.feed(data, time.Now())
	if err != nil {
		return err
	}
	if !complete {
		return nil
	}
	select {
	case c.datagrams <- message:
	default:
	}
	return nil
}
