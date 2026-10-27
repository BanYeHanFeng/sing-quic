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

	// stream is what a stream frame is made of, and is the zero value for an
	// encoded one.
	stream streamFrame

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

	// chunk is the send buffer chunk data is a piece of, and the zero value for
	// a frame that carries no data. The frame is one of the holders of it, and it
	// gives that up when the peer acknowledged the frame: that is what makes the
	// memory of a write reusable, rather than garbage that waits for the next
	// collection.
	chunk *sendChunk

	data     []byte
	offset   uint64
	streamID uint32
	fin      bool
}

// size is how many bytes the frame takes in a packet.
func (f outFrame) size() int {
	if f.stream.carried {
		return streamFixedLen + len(f.stream.data)
	}
	return len(f.payload)
}

// appendTo appends the frame to dst, encoding a stream frame now.
func (f outFrame) appendTo(dst []byte) []byte {
	if f.stream.carried {
		return appendStream(dst, f.stream.streamID, f.stream.offset, f.stream.fin, f.stream.data)
	}
	return append(dst, f.payload...)
}

// releaseFrames gives up what the frames of an acknowledged packet hold: the send
// buffer chunk each stream frame was cut from. A frame is in one packet at a time —
// a lost one goes back to the queue and is planned into the next packet instead of
// staying in the one it was lost in — so this is where its hold on the chunk ends,
// and the last holder of a chunk is what puts it back in the pool.
func releaseFrames(frames []outFrame) {
	for index := range frames {
		chunk := frames[index].stream.chunk
		if chunk == nil {
			continue
		}
		// The frame is not going to be sent again, so the reference goes with the
		// hold: a second pass over the same frames releases nothing.
		frames[index].stream.chunk = nil
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
	if f.stream.carried {
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
	// removed says the packet left the flight table. The entry stays in the
	// ordered slice until the next compaction, because an acknowledgement covers
	// a range of packet numbers and rewriting the whole table once per range is
	// what turns a transfer into a quadratic amount of work.
	removed bool
}

// maxSendBatch is how many packets one flush may hand to the socket at once. What
// pacing allows bounds it in practice; this is the ceiling for when pacing does
// not: a run of acknowledgements, or the parity shards of a group encoded at once.
const maxSendBatch = 16

// batchRoom is the room one batch has: a batch holds at most maxSendBatch packets
// and no packet is longer than maxPacketSize, so a batch that starts empty never
// has to grow in the middle of being filled — which is what lets the packets
// already planned keep pointing into it.
const batchRoom = maxSendBatch * maxPacketSize

// writeBatchSlots is how many batches the send path holds at once: the one it is
// filling and the one the write loop is handing to the socket. Two is what the
// overlap needs, and more would only make a batch that is already complete wait
// behind another one, because a packet number leaves in the order it was assigned.
const writeBatchSlots = 2

// writeDrainTimeout bounds how long closing waits for the socket to take the batch
// it was handed. A socket that stopped accepting writes is unblocked by closing it,
// which is what the caller does next: a close that waited for a stuck socket would
// hang the association instead of ending it.
const writeDrainTimeout = 100 * time.Millisecond

// writeDrainPoll is how often closing looks while it waits.
const writeDrainPoll = 20 * time.Microsecond

// batch is one buffer a batch of packets is assembled in and handed to the socket
// in.
//
// It is a thing of its own rather than a field of the association because two of
// them exist at the same time: the one being filled and the one being written. A
// batch belongs to the send path from the moment it is taken until it is handed
// over, and to the write loop from then until it comes back, so nothing in it is
// touched by both at once.
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

// reset empties the batch for the next fill, keeping what the next batch needs:
// the room the packets are written in and the array of packets themselves. The
// pending entries are cleared because they hold the regions of the buffer and the
// packets in flight, neither of which outlives the write.
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

// flush packs the frames waiting to be sent into packets and sends them, as far
// as the congestion window and the pacing rate allow. What does not fit stays
// queued: an acknowledgement opens the window again and calls this.
//
// A flush is a batch: packets are assembled into one buffer and leave in as few
// calls as the socket allows. Whether that is one call or twenty is the socket's
// business, and a socket that can segment sends a run of equal packets with a
// single one.
func (a *association) flush() error {
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	for {
		if a.queue.len() == 0 {
			return a.writePendingLocked()
		}
		if len(a.batch.pending) >= maxSendBatch {
			if err := a.writePendingLocked(); err != nil {
				return err
			}
			continue
		}
		if !a.windowAllows() {
			if len(a.batch.pending) > 0 {
				// What is planned leaves before the window is asked again: it was
				// taken while the window was open, and the acknowledgement that
				// opens the window further is an answer to it.
				if err := a.writePendingLocked(); err != nil {
					return err
				}
				continue
			}
			acknowledgement := a.queue.takeAckOnly(a.maxPayload)
			if len(acknowledgement) > 0 {
				// The window is closed, but this packet is what the peer needs
				// before it can send anything, and an acknowledgement is not
				// congestion controlled. Two ends that each held one back would
				// wait for the other to open a window neither of them can open.
				err := a.planLocked(acknowledgement)
				if err != nil {
					return err
				}
				continue
			}
			// The window is full: it opens when an acknowledgement arrives, and
			// nothing before that can change it.
			return nil
		}
		if len(a.batch.pending) == 0 {
			// The pacing rate is what spreads the batches over time, so it is
			// asked once per batch: a batch that waited for its own last packet
			// would hold one packet, and one packet per call is the thing the
			// socket was asked to avoid. What a batch spends beyond the tokens it
			// found is what the next one waits for.
			if wait := a.pacingWait(); wait > 0 {
				a.wakePacer()
				return nil
			}
		}
		frames := a.queue.take(a.maxPayload)
		if len(frames) == 0 {
			return E.New("frame of ", a.queue.frames[0].size(), " bytes does not fit in a packet")
		}
		err := a.planLocked(frames)
		if err != nil {
			return err
		}
	}
}

// wakePacer asks the pacing goroutine to look at the clock again. Whoever asks
// while it is already awake has nothing to add, so the request is a token rather
// than a queue.
func (a *association) wakePacer() {
	select {
	case a.paceWake <- struct{}{}:
	default:
	}
}

// paceLoop is the clock the send path follows: it waits out what the pacer says the
// last batch still owes, and then asks for the next one.
//
// It used to be a timer, and a timer cannot be the clock of a send path: a wait under
// a millisecond is served as 1.07 of them whatever it was asked for, so a batch of
// sixteen packets could not leave more often than once per 1.07 ms — 21 MiB/s however
// fast the path was. The bucket that made up the difference is a burst of rate times
// the wait, and on a path whose queue is 25 KB a burst is the loss. Sleeping here
// instead is late by about sixty microseconds, which the bucket covers and a path
// does not notice.
//
// It is a goroutine rather than a wait inside flush because flush is called from the
// receive path: an acknowledgement has to be able to open the window without first
// waiting out a rate, and waiting under the send lock is the same wait under the lock
// that acknowledgement needs.
func (a *association) paceLoop() {
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-a.paceWake:
		}
		for {
			wait := a.pacingWait()
			if wait <= 0 {
				break
			}
			sleepAtLeast(wait)
			select {
			case <-a.ctx.Done():
				return
			default:
			}
		}
		if err := a.flush(); err != nil {
			return
		}
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
	select {
	case <-a.ctx.Done():
		return context.Cause(a.ctx)
	default:
	}
	if len(a.batch.pending) >= maxSendBatch {
		if err := a.writePendingLocked(); err != nil {
			return err
		}
	}
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

// writePendingLocked hands the batch that is full to the write loop and takes the
// next one to fill. What the packets mean for the window, for the congestion
// controller and for the probe timer is recorded here rather than with the write,
// so that the whole send path is one goroutine: what leaves the association is
// what was decided here, and the write loop only moves bytes. The caller holds
// sendMu.
func (a *association) writePendingLocked() error {
	current := a.batch
	if len(current.pending) == 0 {
		return nil
	}
	select {
	case <-a.ctx.Done():
		current.reset()
		return context.Cause(a.ctx)
	default:
	}
	a.sealPendingLocked()
	// The batch leaves the send path now, so this is when its packets are sent: a
	// packet planned at the start of the batch and one planned at its end wait for
	// the same write, and a round trip is measured from the write rather than from
	// the framing in front of it.
	now := time.Now()
	remote := a.RemoteAddr()
	current.packets = current.packets[:0]
	for index := range current.pending {
		current.pending[index].sent.sentAt = now
		current.packets = append(current.packets, udpio.Packet{Data: current.pending[index].packet, Addr: remote})
	}
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
	// The next batch is taken before this one is handed over, which is what keeps
	// the send path holding a batch at all times: what it waits for is the write of
	// the batch in front of the one it just finished, and that wait is where the
	// two halves of sending meet.
	next, err := a.nextBatchLocked()
	if err != nil {
		current.reset()
		return err
	}
	a.writingMu.Lock()
	a.writing++
	a.writingMu.Unlock()
	// The hand over never waits: at most one batch is being written and at most one
	// waits for its turn, because there are only two batches to pass around.
	a.written <- current
	a.batch = next
	return nil
}

// nextBatchLocked returns the batch to fill next: one the socket has finished
// with. When the socket has finished with neither of them, the send path waits
// here, which is the whole of the back pressure: one batch being written and one
// being filled is what the pipeline holds, and a third would only queue behind the
// write that a batch of 16 packets has to wait for anyway. The caller holds sendMu.
func (a *association) nextBatchLocked() (*batch, error) {
	select {
	case next := <-a.freeBatches:
		next.reset()
		return next, nil
	default:
	}
	select {
	case next := <-a.freeBatches:
		next.reset()
		return next, nil
	case <-a.ctx.Done():
		return nil, context.Cause(a.ctx)
	}
}

// writeLoop is the other half of sending: it hands the batches the send path
// filled to the socket, one at a time, in the order they were numbered.
//
// Writing a batch is a system call into a socket that may have to wait for room,
// and it is the largest single item of the send path. Preparing a batch is framing,
// sealing and, with FEC, the arithmetic of the parity shards over it. Both used to
// be the same goroutine one after the other; here one happens while the other does,
// and what makes that safe is that only one batch is ever on its way into the
// socket, so what the peer sees is still one order of packet numbers.
func (a *association) writeLoop() {
	defer close(a.writeDone)
	for {
		select {
		case <-a.writeStop:
			return
		default:
		}
		select {
		case <-a.writeStop:
			return
		case current := <-a.written:
			err := a.batchIO.WritePackets(current.packets)
			if err != nil {
				a.writeFailed(current, err)
			}
			a.writingMu.Lock()
			a.writing--
			a.writingMu.Unlock()
			// The slot comes back whether the write worked or not: what is in it is
			// not going to be sent again from here, and a batch that cannot be
			// written is a batch whose bytes are already recorded as lost.
			a.freeBatches <- current
		}
	}
}

// writeFailed takes the packets of a batch the socket refused out of flight and
// ends the association: a socket that cannot take a batch is a socket that nothing
// else on this association is going to work on. The close is announced to nobody,
// because what would carry the announcement is the same socket.
func (a *association) writeFailed(failed *batch, err error) {
	a.flightMu.Lock()
	for index := range failed.pending {
		if failed.pending[index].sent.ackEliciting {
			a.inFlight.remove(failed.pending[index].sent)
		}
	}
	a.flightMu.Unlock()
	// The shutdown waits for the write loop, which is this goroutine, so it runs
	// where it can: the loop is what makes the wait finish.
	go a.shutdown(E.Cause(err, "write packets"), false)
}

// drainWrites waits for the socket to have taken the batches it was handed, and
// gives up after writeDrainTimeout: a socket that stopped accepting writes is
// unblocked by closing it, which is what the caller does next.
func (a *association) drainWrites() {
	deadline := time.Now().Add(writeDrainTimeout)
	for {
		a.writingMu.Lock()
		writing := a.writing
		a.writingMu.Unlock()
		if writing == 0 || time.Now().After(deadline) {
			return
		}
		time.Sleep(writeDrainPoll)
	}
}
