package udpx

import (
	"context"
	"sort"
	"time"

	"github.com/sagernet/sing-quic/congestion"
	"github.com/sagernet/sing-quic/udpio"

	E "github.com/sagernet/sing/common/exceptions"
)

// Sending
//
// The send path has two queues: frames waiting to be sent, and packets waiting
// to be acknowledged. Keeping them apart is what turns a lost packet into work:
// its frames go back to the head of the first queue and the packet leaves the
// second.
//
// A frame is encoded when it is queued and never again, with one exception: a
// stream frame carries a piece of what the application wrote, and encoding it
// when it is queued would copy every byte of the transfer once, only for the
// packet to copy it again. A stream frame therefore holds what it is made of and
// is encoded into the packet that carries it. A frame that is sent again is
// still the same bytes in a new packet — for a stream frame, the same piece of
// the stream's send buffer, which is why that buffer is released only once the
// frame leaves the flight table — and nothing about the packet it travels in is
// remembered by the frame beyond its number.
//
// A packet is assembled in one place: the batch buffer. The clear header and the
// payload are written where the packet belongs as it is planned, sealing encrypts
// the payload where it is, and the region the packet fills is what the socket is
// handed, so no byte of a packet is ever moved from where it was written.
//
// A batch is handed to a write loop of its own, which is what lets the two halves
// of sending happen at once: while the socket is taking one batch, the send path
// is framing, sealing and encoding the next one. Two batches exist at a time, one
// being filled and one being written, and only one of them is ever on its way into
// the socket, so packet numbers still leave in the order they were assigned.
type outFrame struct {
	// payload is the encoded frame, for every frame that is not a stream frame.
	payload []byte

	// streamFrame is what a stream frame is made of, and is the zero value for an
	// encoded one.
	streamFrame streamFrame

	// lastSent is the packet number the frame was last sent in.
	lastSent uint32

	// ackEliciting says whether the frame asks the peer for an acknowledgement.
	// A packet of nothing but acknowledgements is never acknowledged in turn,
	// which is what keeps two ends from acknowledging each other forever.
	ackEliciting bool
}

// streamFrame is a stream frame that has not been encoded yet: the bytes are the
// ones the application wrote, held by the send buffer of the stream.
type streamFrame struct {
	// carried marks the frame as a stream frame, which is what tells the two
	// shapes of an outFrame apart: a stream frame has no payload of its own
	// until it is in a packet.
	carried bool

	// stream is the stream the frame belongs to, which is what counts the frames
	// the peer has not acknowledged yet: a stream that closes tells the peer it is
	// done only once none of them is left.
	stream *Stream

	// chunk is the send buffer chunk data is a piece of, and the zero value for
	// a frame that carries no data. The frame is one of the holders of it, and it
	// gives that up when the peer acknowledged the frame: that is what makes the
	// memory of a write reusable, rather than garbage that waits for the next
	// collection.
	chunk *sendChunk

	data   []byte
	offset uint64
	fin    bool
}

// size is how many bytes the frame takes in a packet.
func (f outFrame) size() int {
	if f.streamFrame.carried {
		return streamFixedLen + len(f.streamFrame.data)
	}
	return len(f.payload)
}

// appendTo appends the frame to dst, encoding a stream frame now.
func (f outFrame) appendTo(dst []byte) []byte {
	if f.streamFrame.carried {
		return appendStream(dst, f.streamFrame.stream.id, f.streamFrame.offset, f.streamFrame.fin, f.streamFrame.data)
	}
	return append(dst, f.payload...)
}

// releaseFrames gives up what the frames of an acknowledged packet hold: the send
// buffer chunk each stream frame was cut from. A frame is in one packet at a time —
// a lost one goes back to the queue and is planned into the next packet instead of
// staying in the one it was lost in — so this is where its hold on the chunk ends,
// and the last holder of a chunk is what puts it back in the pool.
//
// What it does not do is count the frame as acknowledged for its stream: that is what
// a reset waits for, and it is done outside the flight lock (ackStreamFrames), so that
// the count and the release of the chunk stay in one critical section.
func releaseFrames(frames []outFrame) {
	for index := range frames {
		chunk := frames[index].streamFrame.chunk
		if chunk == nil {
			continue
		}
		// The frame is not going to be sent again, so the reference goes with the
		// hold: a second pass over the same frames releases nothing.
		frames[index].streamFrame.chunk = nil
		chunk.release()
	}
}

// frameQueue is the frames waiting to be sent, in the order they were produced.
// Whoever queues a frame hands its bytes over: the queue is what keeps them
// alive until they are in a packet.
type frameQueue struct {
	frames []outFrame
}

func (q *frameQueue) push(frame outFrame) {
	q.frames = append(q.frames, frame)
}

// pushFront puts frames back at the head of the queue, keeping their order: the
// frame that was sent longest ago is the one that has been waited for longest.
func (q *frameQueue) pushFront(frames []outFrame) {
	if len(frames) == 0 {
		return
	}
	q.frames = append(frames, q.frames...)
}

func (q *frameQueue) len() int {
	return len(q.frames)
}

// headAckEliciting reports whether the frame at the head asks the peer for an
// acknowledgement. A queue whose head does not is one the pacer is worth waiting
// out for: an acknowledgement is what opens the peer's window and is not worth
// spreading over time.
func (q *frameQueue) headAckEliciting() bool {
	return len(q.frames) > 0 && q.frames[0].ackEliciting
}

// takeAckOnly removes the acknowledgements at the head of the queue, up to what
// fits in one packet. They are the one kind of frame that is not congestion
// controlled: everything the other end sends waits for them, so a closed window
// that holds them back is a window that never opens again.
func (q *frameQueue) takeAckOnly(budget int) []outFrame {
	count := 0
	size := 0
	for count < len(q.frames) && !q.frames[count].ackEliciting {
		length := q.frames[count].size()
		if size+length > budget {
			break
		}
		size += length
		count++
	}
	if count == 0 {
		return nil
	}
	return q.takePrefix(count)
}

// take removes and returns the frames that fit in budget bytes. A frame that
// does not fit waits for the next packet rather than being split: a frame is the
// unit that is retransmitted, so a frame that changed shape between attempts
// would need its own bookkeeping.
func (q *frameQueue) take(budget int) []outFrame {
	count := 0
	size := 0
	for count < len(q.frames) {
		length := q.frames[count].size()
		if size+length > budget {
			break
		}
		size += length
		count++
	}
	if count == 0 {
		return nil
	}
	return q.takePrefix(count)
}

// takePrefix removes the first count frames and returns them.
//
// The array they live in is not written to again where they were: a frame that
// left the queue is what a packet in flight carries and what a retransmission
// sends, so it has to stay readable for as long as that packet is out. An empty
// queue therefore drops its array instead of starting over at its front, which is
// also what keeps the array from growing for the length of a whole transfer: it is
// written from its front once and only the frames of one flush are ever in it.
func (q *frameQueue) takePrefix(count int) []outFrame {
	taken := q.frames[:count:count]
	q.frames = q.frames[count:]
	if len(q.frames) == 0 {
		q.frames = nil
	}
	return taken
}

// frameType returns the type of the frame the entry carries.
func (f outFrame) frameType() frameType {
	if f.streamFrame.carried {
		return frameTypeStream
	}
	return frameType(f.payload[0] & frameTypeBits)
}

// sentPacket is one packet in flight.
type sentPacket struct {
	sentAt       time.Time
	frames       []outFrame
	size         int
	packetNumber uint32
	ackEliciting bool
	// sendState is what the congestion controller remembers about the packet,
	// which it hands out when the packet leaves and is done with when the answer
	// for the packet arrives. It lives here rather than in the controller for that
	// reason: this is the table whose entries leave, and a table of every packet
	// ever sent is a table that grows for the length of the association.
	sendState congestion.SendState
	// parity says the packet is a redundancy shard of a group. It counts into the
	// window like any other packet and is acknowledged like any other, and the only
	// thing it does not carry is a frame to send again: a parity shard that is lost
	// cost a shard, not a promise.
	parity bool
	// mtuProbe says the packet is a path MTU probe. It asks a question, so it is
	// never retransmitted and never counts against the window: a question that
	// costs a window is a question the window can refuse to ask.
	mtuProbe bool
	// removed says the packet left the flight table. The entry stays in the
	// ordered slice until the next compaction, because an acknowledgement covers
	// a range of packet numbers and rewriting the whole table once per range is
	// what turns a transfer into a quadratic amount of work.
	removed bool
}

// sentPackets is the set of packets in flight, ordered by packet number.
//
// An acknowledgement names ranges of packet numbers, so the packets it covers are
// found by searching the ordered slice instead of by a scan over everything in
// flight, and the ones that left are compacted out of it once a quarter of the
// table is gone. A loss is handled the same way, and both are reported as a
// prefix: a packet far behind what was acknowledged, or one that has been in
// flight long enough, is lost before anything that came after it.
type sentPackets struct {
	packets []*sentPacket
	bytes   int
	// parityBytes is how much of bytes is redundancy, which the send path needs to
	// charge the redundancy of the group being assembled without charging the one
	// already in flight twice.
	parityBytes int
	removed     int
}

func (s *sentPackets) append(packet *sentPacket) {
	s.packets = append(s.packets, packet)
	s.bytes += packet.size
	if packet.parity {
		s.parityBytes += packet.size
	}
}

// len is how many packets are in flight, not how many entries the table holds.
func (s *sentPackets) len() int {
	return len(s.packets) - s.removed
}

// acked marks the packets an acknowledgement covers and returns them.
func (s *sentPackets) acked(ranges []pnRange) []*sentPacket {
	if len(s.packets) == 0 || len(ranges) == 0 {
		return nil
	}
	var acked []*sentPacket
	for _, current := range ranges {
		index := sort.Search(len(s.packets), func(index int) bool {
			return s.packets[index].packetNumber >= current.start
		})
		for ; index < len(s.packets) && s.packets[index].packetNumber <= current.end; index++ {
			packet := s.packets[index]
			if packet.removed {
				continue
			}
			if s.markRemoved(packet) {
				acked = append(acked, packet)
			}
		}
	}
	s.compact()
	return acked
}

// lost marks the packets that are lost by now and returns them, oldest first.
func (s *sentPackets) lost(now time.Time, largestAcked uint32, lossDelay time.Duration) []*sentPacket {
	var lost []*sentPacket
	for _, packet := range s.packets {
		if packet.removed {
			continue
		}
		if !isLost(packet, now, largestAcked, lossDelay) {
			// The table is ordered by packet number and, with it, by send time, so
			// nothing behind a packet that is not lost is lost either.
			break
		}
		if s.markRemoved(packet) {
			lost = append(lost, packet)
		}
	}
	s.compact()
	return lost
}

// remove drops one packet from flight, which is what a failed write leaves
// behind: the packet never left, so nothing will acknowledge it.
func (s *sentPackets) remove(packet *sentPacket) {
	s.markRemoved(packet)
	s.compact()
}

// oldest returns the packet that has been in flight longest.
func (s *sentPackets) oldest() *sentPacket {
	var oldest *sentPacket
	for _, packet := range s.packets {
		if packet.removed {
			continue
		}
		if oldest == nil || packet.sentAt.Before(oldest.sentAt) {
			oldest = packet
		}
	}
	return oldest
}

func (s *sentPackets) markRemoved(packet *sentPacket) bool {
	if packet.removed {
		return false
	}
	packet.removed = true
	s.removed++
	s.bytes -= packet.size
	if packet.parity {
		s.parityBytes -= packet.size
	}
	return true
}

// compact drops the entries that left the flight table once enough of them are
// gone for the pass to be worth it.
func (s *sentPackets) compact() {
	if s.removed == 0 {
		return
	}
	if s.removed < len(s.packets)/4 && s.removed < 32 && len(s.packets) > 0 {
		return
	}
	kept := s.packets[:0]
	for _, packet := range s.packets {
		if packet.removed {
			continue
		}
		kept = append(kept, packet)
	}
	for index := len(kept); index < len(s.packets); index++ {
		s.packets[index] = nil
	}
	s.packets = kept
	s.removed = 0
}

// isLost reports whether a packet is lost. A packet is lost when it is far enough
// behind what the peer acknowledged that a reordering cannot explain it, or when it
// has been in flight for longer than a round trip and something behind it was
// acknowledged, so its acknowledgement is therefore not on the way.
//
// A packet the peer has acknowledged nothing behind is not lost by the second rule
// however long it has been in flight: its answer may be exactly what is on the way,
// and a retransmission of it would be a duplicate. A packet like that is what the
// probe asks about instead, which is the one place where being late is the signal.
func isLost(packet *sentPacket, now time.Time, largestAcked uint32, lossDelay time.Duration) bool {
	if largestAcked < packet.packetNumber {
		return false
	}
	if largestAcked-packet.packetNumber >= packetThreshold {
		return true
	}
	return now.Sub(packet.sentAt) >= lossDelay
}

// Sending control
//
// The send path has one owner: the send loop. Everything that produces frames —
// the application writing a stream, an acknowledgement, a retransmission, the
// probe timer — puts them in the queue and wakes the loop. The loop is the only
// goroutine that plans packets, seals them and writes the socket.
//
// The reason is the shape of the alternative. When every producer flushed for
// itself, the send lock was held across a write to a socket whose buffer can be
// full, and the receive path took that lock to answer an acknowledgement. A path
// that stopped draining, which is exactly what a full buffer means, then blocked
// the goroutine that reads the socket, and the association went silent in both
// directions with no way back. A send lock that is never held across a write is
// the whole fix, and one owner is what makes it possible.
//
// Pacing is the loop's own clock. A wait is slept in the loop rather than handed
// to a timer, because a timer serves anything under a millisecond as 1.07 of them
// and the batch would then be one packet per millisecond whatever the rate says.

// maxSendBatch is how many packets one pass over the queue may plan. What pacing
// allows bounds it in practice; this is the ceiling for when pacing does not: a
// run of acknowledgements, or the parity shards of a group closed at once.
const maxSendBatch = 16

// batchRoom is the room one batch has. A batch holds at most maxSendBatch data
// packets and the parity shards of the group that the last of them closed, so the
// room is those two numbers together: a batch that starts empty never has to grow
// in the middle of being filled, which is what lets the packets already planned
// keep pointing into it.
const batchRoom = (maxSendBatch + fecMaxParityShards) * maxPacketSize

// writeDrainTimeout bounds how long closing waits for the send loop to write what
// it was handed. A socket that stopped accepting writes is unblocked by closing
// it, which is what the caller does next: a close that waited for a stuck socket
// would hang the association instead of ending it.
const writeDrainTimeout = 100 * time.Millisecond

// batch is one buffer packets are assembled in and the list handed to the socket.
//
// It is a field of the association rather than a thing passed around because there
// is one sender: the loop fills a batch, writes it and resets it. Two of them
// existed when writing was another goroutine, and the overlap they bought is what
// the single owner pays for in clarity.
type batch struct {
	// buffer is where the packets are assembled: the room a packet needs is taken
	// before its payload is known byte for byte, and what the socket is handed is
	// the region the packet was written into.
	buffer []byte
	// pending is the packets of the batch in the order they were numbered, and
	// sealed counts the ones of them that are sealed.
	pending []pendingPacket
	sealed  int
	// packets is the list handed to the socket.
	packets []udpio.Packet
}

func newBatch() *batch {
	return &batch{buffer: make([]byte, 0, batchRoom)}
}

// reset empties the batch for the next fill, keeping the room the packets are
// written in. The pending entries are cleared because they hold the regions of the
// buffer and the packets in flight, neither of which outlives the write.
func (b *batch) reset() {
	for index := range b.pending {
		b.pending[index] = pendingPacket{}
	}
	b.pending = b.pending[:0]
	b.packets = b.packets[:0]
	b.sealed = 0
	b.buffer = b.buffer[:0]
}

// pendingPacket is one packet of the batch, from the moment it has a number and a
// place in the batch buffer to the moment the batch leaves the host.
type pendingPacket struct {
	sent *sentPacket
	// packet is the region of the batch buffer the packet fills, from its clear
	// header to the last byte of its tag.
	packet []byte
	// payloadStart is where the payload begins in packet: what is in front of it is
	// the clear header, which sealing authenticates rather than encrypts.
	payloadStart int
	// priorInFlight is what was in flight when the packet was recorded, which the
	// congestion controller needs per packet and which therefore cannot be read
	// after the whole batch has been added.
	priorInFlight int
}

// flush sends what can be sent now, in the caller's goroutine. The send loop is
// the path data takes; this is for a test that drives the send path directly and
// for a close that has one packet to get out before the socket goes away.
func (a *association) flush() error {
	a.pumpMu.Lock()
	defer a.pumpMu.Unlock()
	return a.pump()
}

// pump plans and writes packets until the window, the pacer or the queue says
// there is nothing more to send. It runs in one goroutine at a time: the send loop
// owns it, and flush borrows it.
func (a *association) pump() error {
	for {
		select {
		case <-a.ctx.Done():
			return context.Cause(a.ctx)
		default:
		}
		a.sendMu.Lock()
		if len(a.batch.pending) >= maxSendBatch {
			a.sendMu.Unlock()
			if err := a.writeBatch(); err != nil {
				return err
			}
			continue
		}
		// The pacer is asked once per batch, and only for data: an acknowledgement
		// is what opens the peer's window and is not worth waiting out a rate for.
		// A probe is a question about a path that has gone quiet, so it goes now.
		if len(a.batch.pending) == 0 && a.queue.len() > 0 && a.queue.headAckEliciting() &&
			a.probeCredits == 0 && !a.closing.Load() && a.windowAllows() {
			wait := a.pacingWait()
			if wait > 0 {
				a.sendMu.Unlock()
				sleepAtLeast(wait)
				continue
			}
		}
		frames := a.nextFramesLocked()
		if frames == nil {
			pending := len(a.batch.pending) > 0
			a.sendMu.Unlock()
			if pending {
				if err := a.writeBatch(); err != nil {
					return err
				}
			}
			return nil
		}
		err := a.planLocked(frames)
		a.sendMu.Unlock()
		if err != nil {
			return err
		}
	}
}

// nextFramesLocked takes the frames of the next packet, or nil when the window and
// the queue leave nothing to send. The caller holds sendMu.
func (a *association) nextFramesLocked() []outFrame {
	if a.queue.len() == 0 {
		return nil
	}
	if a.closing.Load() || a.probeCredits > 0 {
		if !a.closing.Load() {
			a.probeCredits--
		}
		return a.queue.take(a.maxPayload)
	}
	if a.windowAllows() {
		return a.queue.take(a.maxPayload)
	}
	// A closed window still passes acknowledgements: the peer waits for them
	// before it can send anything, and two ends that each held one back would wait
	// for a window neither of them can open.
	return a.queue.takeAckOnly(a.maxPayload)
}

// sendLoop is the send path: it wakes when something was queued or when the window
// may have opened, and sends until nothing more can go.
func (a *association) sendLoop() {
	defer close(a.sendDone)
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-a.sendWake:
		}
		a.pumpMu.Lock()
		err := a.pump()
		a.pumpMu.Unlock()
		if err != nil {
			return
		}
	}
}

// wake asks the send loop to look at the queue again. Whoever asks while the loop
// is already awake has nothing to add, so the request is a token rather than a
// queue.
func (a *association) wake() {
	select {
	case a.sendWake <- struct{}{}:
	default:
	}
}

// sleepCoarse is how much of a wait is left to nanosleep. A timer serves a whole
// number of milliseconds, so what it is asked for has to be at least a millisecond
// short of the wait and rounded up from there; two is that plus the rounding.
const sleepCoarse = 2 * time.Millisecond

// sleepAtLeast waits at least d, precisely enough that the bucket does not have to
// make up more than the sixty microseconds nanosleep is late by. The coarse part is
// a timer so that a slow path does not sit on an operating system thread for the
// whole of a wait it could have slept through.
func sleepAtLeast(d time.Duration) {
	if d > sleepCoarse {
		time.Sleep(d - sleepCoarse)
		d = sleepCoarse
	}
	nanosleep(d)
}

// planLocked puts the frames into the batch as one packet and, when this packet is
// the one that fills a FEC group, closes the group.
//
// What a packet is gets decided here: its number, its clear header, its payload and
// its place in the batch buffer. Sealing is what waits, for one of two reasons: the
// members of a group have to be sealed before the parity shards that cover them can
// be computed, and the packets of a batch are sealed together when the batch leaves.
// The caller holds sendMu, which is what keeps packet numbers leaving in the order
// they were assigned.
func (a *association) planLocked(frames []outFrame) error {
	payloadLen := 0
	for _, frame := range frames {
		payloadLen += frame.size()
	}
	h := header{
		ConnectionID: a.peerConnID,
		Type:         packetTypeData,
		Epoch:        a.sendRing.epoch(),
		PacketNumber: a.sendPacket,
	}
	packet, payloadStart, err := a.reserveLocked(h, nil, payloadLen)
	if err != nil {
		return err
	}
	payload := packet[payloadStart:payloadStart]
	for _, frame := range frames {
		payload = frame.appendTo(payload)
	}
	// The time the packet is sent is stamped by the batch, when it leaves the send
	// path: what a round trip is measured from is the write, not the framing.
	sent := &sentPacket{
		packetNumber: h.PacketNumber,
		frames:       frames,
		size:         len(packet),
	}
	for index := range frames {
		frames[index].lastSent = h.PacketNumber
		sent.ackEliciting = sent.ackEliciting || frames[index].ackEliciting
	}
	a.batch.pending = append(a.batch.pending, pendingPacket{sent: sent, packet: packet, payloadStart: payloadStart})
	a.sendPacket++
	if a.fecSender != nil {
		// A group is a run of consecutive packet numbers, so it fills as they are
		// numbered rather than as they are sealed, and the parity shards are numbered
		// right behind the member that filled it.
		a.fecSender.planned++
		if a.fecSender.planned == a.fecSender.dataShards {
			return a.closeGroupLocked()
		}
	}
	return nil
}

// reserveLocked makes room for one packet of the batch and writes the part of it
// that is in the clear: the common header and, for a parity shard, the description
// of its group. It returns the region the packet fills and where the payload starts
// in it.
//
// The room is exactly what the packet takes — as long as the description makes the
// header, the payload, and a tag behind it — because the region is what the socket
// is going to be handed.
func (a *association) reserveLocked(h header, description *fecHeader, payloadLen int) (packet []byte, payloadStart int, err error) {
	length := headerLen + payloadLen + tagLen
	if description != nil {
		length += fecFixedLen + fecLengthLen*int(description.MemberCount)
	}
	start := len(a.batch.buffer)
	if start+length > batchRoom {
		// A batch that asked for more than one batch holds is a batch that should
		// have left before this packet was planned.
		return nil, 0, E.New("packet of ", length, " bytes in a batch of ", start, " bytes")
	}
	written := h.appendTo(a.batch.buffer[start:start])
	if description != nil {
		written = description.appendTo(written)
	}
	a.batch.buffer = a.batch.buffer[:start+length]
	return a.batch.buffer[start : start+length], len(written), nil
}

// sealPendingLocked seals the packets of the batch that are not sealed yet, and
// hands the ones that carry frames to the FEC group being assembled.
//
// Sealing happens where the payload is, which is what keeps a packet from being
// assembled twice: the region of the batch buffer the socket is going to be handed
// is the region the payload was written into and the region the tag is written
// behind. The caller holds sendMu.
func (a *association) sealPendingLocked() {
	if a.batch.sealed == len(a.batch.pending) {
		return
	}
	unsealed := a.batch.pending[a.batch.sealed:]
	for index := range unsealed {
		a.sendRing.sealInPlace(a.sealNonce[:], unsealed[index].packet, unsealed[index].payloadStart, unsealed[index].sent.packetNumber)
	}
	a.batch.sealed = len(a.batch.pending)
	if a.fecSender == nil {
		return
	}
	for index := range unsealed {
		if unsealed[index].sent.parity {
			// A parity shard covers the group that is already closed rather than
			// being a member of the one being assembled.
			continue
		}
		a.fecSender.add(unsealed[index].packet, unsealed[index].sent.packetNumber)
	}
}

// writeBatch seals the batch, records what its packets mean for the window, for
// the congestion controller and for the probe timer, and hands it to the socket.
//
// What the packets mean is recorded before the write rather than after it: a packet
// that leaves is in flight whether or not the write returns, and the answer for it
// may arrive before the send path gets back to this point.
func (a *association) writeBatch() error {
	a.sendMu.Lock()
	current := a.batch
	if len(current.pending) == 0 {
		a.sendMu.Unlock()
		return nil
	}
	a.sealPendingLocked()
	// The batch leaves the send path now, so this is when its packets are sent: a
	// packet planned at the start of the batch and one planned at its end wait for
	// the same write, and a round trip is measured from the write rather than from
	// the framing in front of it.
	now := time.Now()
	remote := a.RemoteAddr()
	current.packets = current.packets[:0]
	bytes := 0
	for index := range current.pending {
		current.pending[index].sent.sentAt = now
		bytes += current.pending[index].sent.size
		current.packets = append(current.packets, udpio.Packet{Data: current.pending[index].packet, Addr: remote})
	}
	a.stats.sentPackets.Add(int64(len(current.packets)))
	a.stats.sentBytes.Add(int64(bytes))
	// The packets are recorded as in flight while the send lock is still held, so
	// that a frame is reachable from exactly one place at any moment: the queue, the
	// batch, or the flight table. A reader that took the send lock and then the
	// flight lock — which is the order both paths take — never sees a frame in none
	// of them.
	a.flightMu.Lock()
	wasEmpty := a.inFlight.len() == 0
	for index := range current.pending {
		packet := &current.pending[index]
		if !packet.sent.ackEliciting {
			// Nothing in this packet asks for an acknowledgement, so nothing will
			// ever acknowledge it: putting it in flight would leave an entry that
			// can only be given up on, and would keep the probe timer aimed at a
			// packet nobody is waiting for.
			continue
		}
		packet.priorInFlight = a.inFlight.bytes
		a.inFlight.append(packet.sent)
	}
	a.flightMu.Unlock()
	for index := range current.pending {
		packet := &current.pending[index]
		if packet.sent.ackEliciting {
			packet.sent.sendState = a.congestionSent(packet.sent.packetNumber, packet.sent.size, packet.priorInFlight)
		}
	}
	a.resetIdle()
	// The probe timer belongs to the oldest packet in flight, so it is armed when
	// there was nothing in flight before this batch. A packet that follows a
	// pending one is already covered by the wait that packet armed.
	if wasEmpty {
		a.armPTO()
	}
	// The packets leave the batch before the write, not after it: what is in
	// flight is what the socket was handed, and a frame must be reachable from one
	// place only. The regions of the buffer the packets point into stay as they
	// are until the write returns, because nothing plans into the batch while this
	// goroutine is in the write.
	written := current.pending
	current.pending = current.pending[:0]
	current.sealed = 0
	a.sendMu.Unlock()
	err := a.batchIO.WritePackets(current.packets)
	if err != nil {
		if a.writingProbe.Load() && isMessageTooLong(err) {
			// The probe was the one packet larger than the path: the socket said so
			// before anything else had to be written, and the size it refused is
			// the size that is not available.
			a.mtuProbeFailed()
			return nil
		}
		a.writeFailed(written, err)
		return err
	}
	current.reset()
	return nil
}

// writeFailed takes the packets of a batch the socket refused out of flight and
// ends the association: a socket that cannot take a batch is a socket that nothing
// else on this association is going to work on. The close is announced to nobody,
// because what would carry the announcement is the same socket.
func (a *association) writeFailed(failed []pendingPacket, err error) {
	a.flightMu.Lock()
	for index := range failed {
		if failed[index].sent.ackEliciting {
			a.inFlight.remove(failed[index].sent)
		}
	}
	a.flightMu.Unlock()
	// The shutdown waits for the send loop, which is this goroutine, so it runs
	// where it can: the loop is what makes the wait finish.
	go a.shutdown(E.Cause(err, "write packets"), false)
}
