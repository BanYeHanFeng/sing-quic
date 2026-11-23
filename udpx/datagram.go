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

type Datagram struct {
	Channel uint32
	Data    []byte
}

type datagramKey struct {
	channel uint32
	message uint16
}

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
	return datagramDefragger{
		entries: make(map[datagramKey]*datagramReassembly),
	}
}

func (d *datagramDefragger) feed(data datagramData, now time.Time) ([]byte, bool, error) {
	if data.total == 0 || data.index >= data.total {
		return nil, false, E.New("invalid datagram fragment ", int(data.index), " of ", int(data.total))
	}
	if data.total == 1 {
		return append(make([]byte, 0, len(data.data)), data.data...), true, nil
	}
	d.expire(now)
	key := datagramKey{channel: data.channel, message: data.message}
	reassembly, loaded := d.entries[key]
	if !loaded {
		reassembly = &datagramReassembly{
			parts: make([][]byte, int(data.total)),
			added: now,
		}
		d.entries[key] = reassembly
		d.order = append(d.order, key)
	} else if len(reassembly.parts) != int(data.total) {
		d.remove(key)
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

func (a *association) datagramDataLen() int {
	return a.maxPayload - datagramFixedLen
}

func (a *association) SendDatagram(channel uint32, data []byte) error {
	select {
	case <-a.ctx.Done():
		return context.Cause(a.ctx)
	default:
	}
	if len(data) > maxDatagramSize {
		return E.New("datagram of ", len(data), " bytes is larger than ", maxDatagramSize)
	}
	fragmentLen := a.datagramDataLen()
	fragmentCount := (len(data) + fragmentLen - 1) / fragmentLen
	if fragmentCount == 0 {
		fragmentCount = 1
	}
	if fragmentCount > maxDatagramFragments {
		return E.New("datagram of ", len(data), " bytes does not fit in ", maxDatagramFragments, " fragments")
	}
	a.datagramMu.Lock()
	message := a.datagramMessage
	a.datagramMessage++
	a.datagramMu.Unlock()
	for index := 0; index < fragmentCount; index++ {
		start := index * fragmentLen
		end := min(start+fragmentLen, len(data))
		a.queueFrame(appendDatagram(nil, datagramData{
			channel: channel,
			message: message,
			index:   uint8(index),
			total:   uint8(fragmentCount),
			data:    data[start:end],
		}))
	}
	a.wake()
	return nil
}

func (a *association) ReceiveDatagram(ctx context.Context) (Datagram, error) {
	select {
	case datagram := <-a.datagrams:
		return datagram, nil
	case <-ctx.Done():
		return Datagram{}, context.Cause(ctx)
	case <-a.ctx.Done():
		return Datagram{}, context.Cause(a.ctx)
	}
}

func (a *association) handleDatagram(data datagramData) error {
	a.datagramMu.Lock()
	defer a.datagramMu.Unlock()
	message, complete, err := a.defragger.feed(data, time.Now())
	if err != nil {
		return err
	}
	if !complete {
		return nil
	}
	select {
	case a.datagrams <- Datagram{Channel: data.channel, Data: message}:
	default:
		a.stats.droppedDatagrams.Add(1)
	}
	return nil
}
