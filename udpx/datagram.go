package udpx

import (
	"context"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// Datagrams
//
// A datagram is a message with no order and no delivery promise: what is lost is
// lost, and what arrives is handed over whole. That is what a forwarded UDP packet
// needs, and it is the reason the splitting lives here rather than above: a
// datagram larger than a packet is cut into fragments that are reassembled before
// anything is handed over, so a fragment that arrives first is a detail of the
// reassembly and not a message the layer above has to make sense of.
//
// A channel is a key the sender picks. One association carries as many channels as
// its owner needs, which is what keeps a forwarded UDP packet from costing an
// association: an association is a handshake, and a handshake is a password hash.
const (
	// maxDatagramFragments is how many fragments one datagram may be cut into.
	// The count is a single byte on the wire.
	maxDatagramFragments = 255

	// maxDatagramSize is the largest datagram this end sends or accepts. A UDP
	// payload cannot be larger, and a datagram nobody could forward is not worth
	// reassembling.
	maxDatagramSize = 0xffff

	// datagramBacklog is how many reassembled datagrams may wait for the
	// application. A full backlog drops what arrives instead of making the
	// receive loop wait: a datagram that has to be dropped is dropped, and the
	// streams of the same association keep moving while it happens.
	datagramBacklog = 64

	// maxDatagramReassemblyCount and maxDatagramReassemblyBytes bound the state
	// of the reassemblies in progress. Both are the sender's side of the deal
	// being kept: an association that fills them has stopped reading, and the
	// oldest reassembly is the one least likely to complete.
	maxDatagramReassemblyCount = 64
	maxDatagramReassemblyBytes = 256 * 1024

	// datagramReassemblyAge is how long a reassembly may stay incomplete. A
	// datagram whose fragments are that far apart in time is one a path lost a
	// fragment of, and waiting for the rest costs memory that a new message
	// would use better.
	datagramReassemblyAge = 4 * time.Second
)

// Datagram is one unreliable message from the peer, whole and in one piece.
type Datagram struct {
	// Channel is the key the sender chose for the message.
	Channel uint32
	// Data is the message. It belongs to whoever received it.
	Data []byte
}

// datagramKey identifies one datagram being reassembled: the message number is
// per channel, so two messages on one channel do not mix even when their
// fragments are interleaved.
type datagramKey struct {
	channel uint32
	message uint16
}

// datagramReassembly is the fragments of one datagram that arrived so far.
type datagramReassembly struct {
	parts  [][]byte
	added  time.Time
	size   int
	filled int
}

// datagramDefragger collects fragments until a datagram is complete.
//
// Every entry is bounded and every entry ages out, because both the number of
// datagrams in flight and their size come from the peer: an association that
// never completes one must not be able to hold memory for as long as it likes.
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

// feed adds one fragment and reports whether it completed a datagram, which it
// then returns. A fragment that is not part of any datagram, or one that arrived
// twice, is dropped: neither is worth an error, because a datagram carries no
// promise that would be broken by it.
func (d *datagramDefragger) feed(data datagramData, now time.Time) ([]byte, bool, error) {
	if data.total == 0 || data.index >= data.total {
		return nil, false, E.New("invalid datagram fragment ", int(data.index), " of ", int(data.total))
	}
	if data.total == 1 {
		// The packet the fragment came in is reused as soon as the frame was
		// read, so a message that is handed over without reassembly is copied
		// here as well.
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
		// The same message number was reused for a datagram of another shape,
		// which means the one before it will never complete: start over.
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

// expire drops the reassemblies that waited too long to complete.
func (d *datagramDefragger) expire(now time.Time) {
	for key, reassembly := range d.entries {
		if now.Sub(reassembly.added) >= datagramReassemblyAge {
			d.remove(key)
		}
	}
}

// evictOldest drops the reassembly that has been waiting longest and reports
// whether there was one.
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

// remove forgets one reassembly and the memory it held.
func (d *datagramDefragger) remove(key datagramKey) {
	reassembly, loaded := d.entries[key]
	if !loaded {
		return
	}
	d.bytes -= reassembly.size
	delete(d.entries, key)
}

// datagramDataLen is how much of a datagram one fragment carries, so that the
// frame it is packed into fits in a packet alone.
func (a *association) datagramDataLen() int {
	return a.maxPayload - datagramFixedLen
}

// SendDatagram sends one message to the peer. The message is split here, and a
// message that is lost is not sent again: a datagram is a datagram.
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
	return a.flush()
}

// ReceiveDatagram returns the next message the peer sent, whichever channel it
// belongs to.
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

// handleDatagram reassembles one fragment and hands the message over once it is
// whole. A datagram that cannot be reassembled is dropped, not an error: it is the
// peer's own message that is lost, and the streams beside it are not affected.
func (a *association) handleDatagram(data datagramData) error {
	// The reassemblies are one lock with the messages waiting for the
	// application: both are state the receive side owns and the caller of
	// ReceiveDatagram reads, and neither is worth two locks.
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
		// Nobody is keeping up. The message is dropped rather than the receive
		// loop waiting for room: an unreliable message that waited is still
		// unreliable, and the streams of this association are not.
	}
	return nil
}
