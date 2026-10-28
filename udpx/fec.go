package udpx

import (
	"errors"
	"sync/atomic"
	"time"

	"github.com/klauspost/reedsolomon"
	E "github.com/sagernet/sing/common/exceptions"
)

// Forward error correction
//
// A FEC group is k member packets and m parity shards of a systematic
// Reed-Solomon code over GF(2^8). Any k of the k+m shards reconstruct the group,
// so a group that loses m members comes back wherever they fell — that is the
// whole contract, and it is why the code is not written here. What a codec of
// this size spends is one multiply-accumulate per member per parity shard, and
// the SIMD kernels in klauspost/reedsolomon do that faster than a hand-written
// loop does a xor: 2.7 us against 5.2 us for 32 members and 2 parity shards of
// 1400 bytes. Above about four parity shards the ordering flips — k*m
// multiplications outgrow k xors — and no shape this transport offers goes there.
//
// At one parity shard the two codes are the same code, since the first row of a
// Vandermonde matrix is all ones: what a single parity shard can repair does not
// depend on the code at all, only on how many of them there are.
//
// The code is systematic in the sense that matters here: the members travel as
// themselves, and the parity is only ever used by a receiver that is missing
// something. A member that arrives is never reconstructed, and a group whose
// members all arrive costs its parity and nothing else.

const (
	// fecMaxShards is the most shards a group can have. Every count on the wire
	// is a byte, and a group is described by one byte of members and one of
	// parity.
	fecMaxShards = 256
)

// fecCodec is the code of one end. The shape of a group is chosen by the wire — a
// group that closed before it filled has fewer members — so the codec keeps one
// encoder per shape and builds the matrix for a new shape once. It belongs to one
// end of one association and is driven by that end's goroutine, which is why it
// has no lock: a Reed-Solomon encoder keeps a cache of inverted matrices while it
// reconstructs, so two ends must not share one.
type fecCodec struct {
	encoders map[[2]uint8]reedsolomon.Encoder
}

// encoder returns the code for a group of members members and parity parity
// shards, building it the first time that shape is seen.
func (c *fecCodec) encoder(members, parity int) (reedsolomon.Encoder, error) {
	shape := [2]uint8{uint8(members), uint8(parity)}
	if encoder, found := c.encoders[shape]; found {
		return encoder, nil
	}
	// A shard is never longer than a packet, which is below the size that a
	// second goroutine would pay for itself.
	encoder, err := reedsolomon.New(members, parity, reedsolomon.WithAutoGoroutines(maxPacketSize))
	if err != nil {
		return nil, err
	}
	if c.encoders == nil {
		c.encoders = make(map[[2]uint8]reedsolomon.Encoder, 4)
	}
	c.encoders[shape] = encoder
	return encoder, nil
}

// fecShardSize checks the shape of a group and returns the length of a shard.
// Every shard of a group has the same length — the length of the longest member,
// which is what keeps a group of small packets from being padded to the MTU —
// and the members count and parity count are what the wire can carry.
func fecShardSize(members, parity int, shards [][]byte) (int, error) {
	if members < 1 {
		return 0, E.New("FEC group of ", members, " members")
	}
	if parity < 1 {
		return 0, E.New("FEC group with ", parity, " parity shards")
	}
	if members+parity > fecMaxShards {
		return 0, E.New("FEC group of ", members, " members and ", parity, " parity shards")
	}
	size := 0
	for index, shard := range shards {
		if shard == nil {
			continue
		}
		if size == 0 {
			size = len(shard)
			continue
		}
		if len(shard) != size {
			return 0, E.New("FEC shard ", index, " of ", len(shard), " bytes in a group of ", size)
		}
	}
	if size == 0 {
		return 0, E.New("FEC group of empty shards")
	}
	return size, nil
}

// encode computes the parity shards of a group. members holds the member shards
// in the order the group describes them and parity the shards to compute, all of
// the same length; only parity is written.
func (c *fecCodec) encode(members, parity [][]byte) error {
	shards := make([][]byte, 0, len(members)+len(parity))
	shards = append(shards, members...)
	shards = append(shards, parity...)
	if _, err := fecShardSize(len(members), len(parity), shards); err != nil {
		return err
	}
	encoder, err := c.encoder(len(members), len(parity))
	if err != nil {
		return err
	}
	return encoder.Encode(shards)
}

// recover reconstructs the member shards of a group that did not arrive. shards
// holds members+parity entries, the members first and then the parity shards, a
// nil entry being a shard nobody has. It returns how many members it filled in:
// the code reconstructs from any k shards, so the answer is every missing member
// or none, and none means the group is waiting for a shard still on the path.
func (c *fecCodec) recover(members, parity int, shards [][]byte) (int, error) {
	if len(shards) != members+parity {
		return 0, E.New("FEC group of ", len(shards), " shards for ", members, " members and ", parity, " parity shards")
	}
	if _, err := fecShardSize(members, parity, shards); err != nil {
		return 0, err
	}
	missing := 0
	for _, shard := range shards[:members] {
		if shard == nil {
			missing++
		}
	}
	if missing == 0 {
		return 0, nil
	}
	encoder, err := c.encoder(members, parity)
	if err != nil {
		return 0, err
	}
	if err = encoder.ReconstructData(shards); err != nil {
		if errors.Is(err, reedsolomon.ErrTooFewShards) {
			return 0, nil
		}
		return 0, err
	}
	return missing, nil
}

// Groups
//
// A group is k consecutive packet numbers and the parity shards that follow them.
// Members are not enumerated on the wire because they do not have to be: the
// group is named by its first packet number and the codec knows that the next k-1
// are its members, which is also what lets a receiver know a member is missing
// before any parity arrived.
//
// A group whose members are all acknowledged is still a group: parity is encoded
// when the sender stops sending members, and there is no way to know in advance
// which of them the path will drop. What a group costs is its parity, which is
// only ever sent once every member has left.

const (
	// fecMaxDataShards is the most members a group may hold. It bounds what a
	// parity packet has to describe: two bytes of member length each, in the clear
	// header of every parity shard.
	fecMaxDataShards = 32

	// defaultParityShards is the redundancy a group gets when the caller asks for
	// data shards without saying how much redundancy to pay for them.
	defaultParityShards = 2

	// fecMaxParityShards is the most redundancy a group may carry. A path that
	// loses a quarter of what crosses it is not one a redundancy of half would
	// help, and the extra bytes are charged to the window like everything else.
	fecMaxParityShards = 8

	// fecBufferLimit is how many packet-sized buffers one end keeps between groups.
	// A sender holds k members and m parity shards at once and a receiver the shards
	// of fecReceiveGroups groups, so the largest group this end may build is what
	// bounds it: a hundred kilobytes held for the life of an association, against an
	// allocation of that size for every group ever encoded.
	fecBufferLimit = 2*fecMaxDataShards + fecMaxParityShards

	// fecMinGroupMembers is the smallest group the timer may close. A group of one
	// packet with one parity shard is everything sent twice, which is a fine trade
	// for a path that loses half of it and a poor one for a request whose answer
	// is one packet long.
	fecMinGroupMembers = 2

	// fecGroupTimeout is how long an open group waits for more members before it is
	// closed as it is. Parity is not something the peer waits for, so this is the
	// cost of protecting a group the sender was too idle to fill: a member that is
	// lost is recovered one timeout later instead of one round trip later.
	fecGroupTimeout = 10 * time.Millisecond

	// fecReceiveGroups is how many groups a receiver assembles at once. A group is
	// only worth keeping until its parity arrives, which is one round trip at most,
	// so a handful covers everything a sender can have in flight.
	fecReceiveGroups = 8

	// fecReceiveCache is how many packets a receiver keeps for the group whose
	// parity has not arrived yet. A group is described by a parity packet that
	// comes after its members, so the members have to be remembered to be
	// recoverable, and a group whose members were dropped from here is not
	// recoverable at all: what was forgotten is delivered twice at worst, and the
	// frame that carries it is the same frame.
	fecReceiveCache = 64
)

// fecSender assembles the groups this end sends. It is driven by the goroutine
// that sends, under the send lock, which is also what keeps packet numbers in the
// order the groups describe.
type fecSender struct {
	dataShards int
	// parityShards is how many redundant packets each group gets. It is what the
	// caller asked for: redundancy is a cost paid on every group, so how much of it
	// is worth paying is the caller's answer, not something this end measures.
	parityShards int

	codec fecCodec

	// group holds the packets of the open group in the order they were sent, and
	// shardLen the length of the longest of them: parity shards are padded to it
	// rather than to the MTU, so a group of small packets stays small.
	group    [][]byte
	groupID  uint32
	shardLen int

	// planned is how many members the open group has been promised. It is what
	// closes the group, and it counts packets as they are numbered rather than as
	// they are sealed: a group is a run of consecutive packet numbers, so the one
	// that fills it is known before the batch is sealed.
	planned int

	// free is the buffers of the groups already encoded, lengths the room to
	// describe the group being encoded and shards the list of shards it was
	// encoded into. A group is 2k+m packet-sized buffers, and asking the allocator
	// for them once per k packets is what a sender with redundancy would otherwise
	// spend on the collector: everything here belongs to sendMu, so it needs no
	// lock of its own.
	free    [][]byte
	lengths []byte
	shards  [][]byte

	// timer closes the open group when nothing followed it for a while.
	timer *time.Timer
}

func newFECSender(options FECOptions) *fecSender {
	if options.DataShards <= 0 {
		return nil
	}
	dataShards := options.DataShards
	if dataShards > fecMaxDataShards {
		dataShards = fecMaxDataShards
	}
	parityShards := options.ParityShards
	if parityShards <= 0 {
		parityShards = defaultParityShards
	}
	if parityShards > fecMaxParityShards {
		parityShards = fecMaxParityShards
	}
	return &fecSender{
		dataShards:   dataShards,
		parityShards: parityShards,
	}
}

// buffer returns an empty buffer of one packet's size, kept from a group that was
// already encoded when there is one. Every buffer a group holds comes from here,
// which is what lets a member grow to the length of the group's shards in place.
func (s *fecSender) buffer() []byte {
	if len(s.free) == 0 {
		return make([]byte, 0, maxPacketSize)
	}
	buffer := s.free[len(s.free)-1]
	s.free = s.free[:len(s.free)-1]
	return buffer[:0]
}

// release hands a buffer back for the next group. A buffer that is not one of
// these is left to the collector.
func (s *fecSender) release(buffer []byte) {
	if cap(buffer) < maxPacketSize || len(s.free) >= fecBufferLimit {
		return
	}
	s.free = append(s.free, buffer[:0])
}

// lengthsFor returns the room to describe count members, kept from the group
// before: the description is copied into every parity packet as it is sealed, so
// it only has to live as long as the group does.
func (s *fecSender) lengthsFor(count int) []byte {
	size := fecLengthLen * count
	if cap(s.lengths) < size {
		s.lengths = make([]byte, size)
	}
	return s.lengths[:size]
}

// shardsFor returns count parity shards of shardLen bytes each. The code writes
// every one of them from the first byte, so what they held before does not matter.
func (s *fecSender) shardsFor(count, shardLen int) [][]byte {
	if cap(s.shards) < count {
		s.shards = make([][]byte, count)
	}
	shards := s.shards[:count]
	for index := range shards {
		shards[index] = s.buffer()[:shardLen]
	}
	return shards
}

// pad extends a member to the shard length of its group, which is what makes the
// members the shards the code expects. The padding is zeroed here rather than when
// the buffer was allocated, because the buffer behind it held another packet then.
func (s *fecSender) pad(member []byte) []byte {
	if cap(member) < s.shardLen {
		padded := make([]byte, s.shardLen)
		copy(padded, member)
		return padded
	}
	shard := member[:s.shardLen]
	clear(shard[len(member):])
	return shard
}

// payloadBudget is how many payload bytes a packet may carry once this end
// protects its packets: a parity shard is as long as the longest member and it
// describes the group in its clear header, so members give up the room that
// description needs, and the parity packet is never larger than a member.
func (s *fecSender) payloadBudget(mtu int) int {
	return mtu - 2*(headerLen+tagLen) - fecFixedLen - fecLengthLen*s.dataShards
}

// open reports whether a group is waiting for more members.
func (s *fecSender) open() bool {
	return len(s.group) > 0
}

// close forgets the open group, handing its buffers back. It is called before the
// parity is sent, so that a failed write cannot leave the same group to be
// encoded twice.
func (s *fecSender) close() {
	for _, member := range s.group {
		s.release(member)
	}
	s.group = s.group[:0]
	s.shardLen = 0
	s.planned = 0
	if s.timer != nil {
		s.timer.Stop()
	}
}

// add hands one sealed packet to the open group. The caller holds sendMu.
//
// The packet bytes are kept rather than a description of them: a member is
// recovered as the packet the sender wrote, which is what makes it authenticable
// and what keeps recovery from being a second kind of receive.
func (s *fecSender) add(packet []byte, packetNumber uint32) {
	if len(s.group) == 0 {
		// A group is named after its first member, which is what a receiver counts
		// from: members are not enumerated, they are the packet numbers that follow.
		s.groupID = packetNumber
		s.timer.Reset(fecGroupTimeout)
	}
	member := append(s.buffer(), packet...)
	s.group = append(s.group, member)
	if len(member) > s.shardLen {
		s.shardLen = len(member)
	}
}

// flushFECGroup closes the group that nothing followed, so that a group which will
// never be filled is still protected. It runs on the group timer.
func (a *association) flushFECGroup() {
	sender := a.fecSender
	if sender == nil {
		return
	}
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	select {
	case <-a.ctx.Done():
		return
	default:
	}
	if sender.planned < fecMinGroupMembers {
		// Two packets are not worth as many parity shards: what a group this small
		// buys is one timeout of latency on a loss, and the sender is idle enough
		// that what it protects is not what the peer is waiting for.
		sender.close()
		return
	}
	if err := a.closeGroupLocked(); err != nil {
		return
	}
	// Nothing else is going to fill a batch on a timer: the group closed on its
	// own, so the parity it produced is handed to the send loop now.
	a.wake()
}

// closeGroupLocked ends the open group: it seals the members the group was
// promised, computes the parity shards over them and plans the packets that carry
// them. The caller holds sendMu.
//
// The members have to be sealed here rather than with the rest of the batch: a
// parity shard is a function of the packets the sender wrote, so the encoder reads
// what the socket is going to send.
func (a *association) closeGroupLocked() error {
	sender := a.fecSender
	a.sealPendingLocked()
	members := sender.group
	if len(members) == 0 {
		return nil
	}
	parityCount := sender.parityShards
	description := fecHeader{
		GroupID:     sender.groupID,
		MemberCount: uint8(len(members)),
		ParityCount: uint8(parityCount),
		lengths:     sender.lengthsFor(len(members)),
	}
	shardLen := sender.shardLen
	for index, member := range members {
		// Every shard is as long as the longest member, not as long as the MTU: a
		// group of small packets must not be inflated to full size just to be
		// recoverable, and the original length is what the description carries.
		description.setMemberLength(index, len(member))
		members[index] = sender.pad(member)
	}
	parity := sender.shardsFor(parityCount, shardLen)
	err := sender.codec.encode(members, parity)
	sender.close()
	if err == nil {
		for index, shard := range parity {
			description.Index = uint8(index)
			err = a.planParityLocked(description, shard)
			if err != nil {
				break
			}
		}
	}
	for _, shard := range parity {
		sender.release(shard)
	}
	return err
}

// planParityLocked puts one parity shard into the batch. The caller holds sendMu,
// so the packet number is the next one in the sequence: parity packets are numbered
// like everything else, which is what keeps the members of a group in the one order
// the description assumes.
func (a *association) planParityLocked(description fecHeader, shard []byte) error {
	h := header{
		ConnectionID: a.peerConnID,
		Type:         packetTypeFEC,
		Epoch:        a.sendRing.epoch(),
		PacketNumber: a.sendPacket,
	}
	// A group closes on the packet that fills it, so the parity shards of a batch
	// may be one more than the data packets it holds: batchRoom is what bounds
	// them, not maxSendBatch.
	packet, payloadStart, err := a.reserveLocked(h, &description, len(shard))
	if err != nil {
		return err
	}
	copy(packet[payloadStart:], shard)
	a.sendPacket++
	a.batch.pending = append(a.batch.pending, pendingPacket{
		sent: &sentPacket{
			packetNumber: h.PacketNumber,
			size:         len(packet),
			ackEliciting: true,
			parity:       true,
		},
		packet:       packet,
		payloadStart: payloadStart,
	})
	return nil
}

// fecCachedPacket is one packet kept for the group it belongs to.
type fecCachedPacket struct {
	packetNumber uint32
	bytes        []byte
}

// fecReceiveGroup is a group a receiver is assembling.
type fecReceiveGroup struct {
	groupID uint32
	// lengths holds the length of every member, which is the length a recovered
	// member is cut back to: the shard carries the padding, the packet does not.
	lengths []int
	// members and parity are the shards that arrived, indexed from the first
	// packet number of the group and from the first parity shard. A member that is
	// nil has not been seen and is what recovery fills in.
	members [][]byte
	parity  [][]byte
}

// member returns the index of a packet number in the group, or -1 when the packet
// is not one of its members.
func (g *fecReceiveGroup) member(packetNumber uint32) int {
	if packetNumber < g.groupID || packetNumber-g.groupID >= uint32(len(g.members)) {
		return -1
	}
	return int(packetNumber - g.groupID)
}

// fecReceiver assembles the groups the peer sends. It belongs to the goroutine
// that reads the socket: a recovered packet takes the same path as one that
// arrived, which is the point of recovering the packet bytes rather than the
// frames they carry.
type fecReceiver struct {
	// active says the peer protects what it sends. Until it does, packets are not
	// worth copying: there is no parity that could recover them.
	active bool

	// recent is a ring of the packets that arrived, newest over oldest, so a group
	// can be assembled from the members that came before its description.
	recent []fecCachedPacket
	next   int

	groups map[uint32]*fecReceiveGroup

	codec fecCodec

	// free is the parity shards of the groups already assembled: unlike a member,
	// which belongs to the ring, a parity shard belongs to its group alone, so it
	// is handed back when the group is dropped. It is driven by the goroutine that
	// reads the socket, which is why it needs no lock.
	free [][]byte

	// recovered counts the members that only arrived because their parity did,
	// which is the one number that says whether the redundancy was spent on
	// anything.
	recovered atomic.Int64
}

func newFECReceiver() fecReceiver {
	return fecReceiver{groups: make(map[uint32]*fecReceiveGroup)}
}

// buffer returns an empty buffer of one packet's size, kept from a group that was
// already assembled when there is one.
func (r *fecReceiver) buffer() []byte {
	if len(r.free) == 0 {
		return make([]byte, 0, maxPacketSize)
	}
	buffer := r.free[len(r.free)-1]
	r.free = r.free[:len(r.free)-1]
	return buffer[:0]
}

// release hands a parity shard back for the next group.
func (r *fecReceiver) release(buffer []byte) {
	if cap(buffer) < maxPacketSize || len(r.free) >= fecBufferLimit {
		return
	}
	r.free = append(r.free, buffer[:0])
}

// shard returns a copy of a parity shard that the group can keep: the shard is a
// view of the buffer the next packet is read into, and a group waits for the
// shards that follow it.
func (r *fecReceiver) shard(shard []byte) []byte {
	cached := r.buffer()
	if cap(cached) < len(shard) {
		cached = make([]byte, 0, len(shard))
	}
	cached = cached[:len(shard)]
	copy(cached, shard)
	return cached
}

// drop forgets a group, handing the parity shards it holds back. Its members are
// not its to hand back: they are slots of the ring.
func (r *fecReceiver) drop(groupID uint32) {
	group, found := r.groups[groupID]
	if !found {
		return
	}
	for _, shard := range group.parity {
		r.release(shard)
	}
	delete(r.groups, groupID)
}

// remember keeps a member packet for the group that may describe it later.
func (r *fecReceiver) remember(packetNumber uint32, packet []byte) {
	if r.recent == nil {
		r.recent = make([]fecCachedPacket, fecReceiveCache)
	}
	slot := &r.recent[r.next]
	// The slot is taken back from the packet it held before, so the ring allocates
	// once per slot rather than once per packet. What that costs is a group the
	// ring has started overwriting: its members are other packets now, so it cannot
	// be assembled any more and is dropped rather than recovered from bytes that
	// are no longer its own.
	for groupID, group := range r.groups {
		if group.member(slot.packetNumber) >= 0 {
			r.drop(groupID)
		}
	}
	if cap(slot.bytes) < len(packet) {
		slot.bytes = make([]byte, len(packet))
	}
	cached := slot.bytes[:len(packet)]
	copy(cached, packet)
	*slot = fecCachedPacket{packetNumber: packetNumber, bytes: cached}
	r.next = (r.next + 1) % len(r.recent)
	// A group that is already assembling takes it as the shard it is: a member that
	// arrives after the first parity packet is as good as one that arrived before.
	for _, group := range r.groups {
		if index := group.member(packetNumber); index >= 0 {
			group.members[index] = cached
		}
	}
}

// group returns the group a parity packet describes, building it from what already
// arrived the first time one is seen.
func (r *fecReceiver) group(description *fecHeader) *fecReceiveGroup {
	members := int(description.MemberCount)
	parity := int(description.ParityCount)
	if members+parity > fecMaxShards {
		return nil
	}
	lengths := make([]int, members)
	shardLen := 0
	for index := range lengths {
		lengths[index] = description.memberLength(index)
		// A member is a whole packet: its clear header and its tag are at least
		// what it can be, and a description that says otherwise describes
		// something no sender wrote.
		if lengths[index] < headerLen+tagLen || lengths[index] > maxPacketSize {
			return nil
		}
		if lengths[index] > shardLen {
			shardLen = lengths[index]
		}
	}
	if shardLen == 0 || shardLen > maxPacketSize {
		return nil
	}
	existing, found := r.groups[description.GroupID]
	if found {
		// The description is the same for every shard of a group, and a group that
		// is already assembling has the lengths the members were sent with.
		return existing
	}
	if len(r.groups) >= fecReceiveGroups {
		r.evict()
	}
	group := &fecReceiveGroup{
		groupID: description.GroupID,
		lengths: lengths,
		members: make([][]byte, members),
		parity:  make([][]byte, parity),
	}
	for _, cached := range r.recent {
		if index := group.member(cached.packetNumber); index >= 0 {
			group.members[index] = cached.bytes
		}
	}
	r.groups[group.groupID] = group
	return group
}

// evict forgets the oldest group being assembled, which is the one least likely to
// be recovered: its parity is late enough that the sender has moved on.
func (r *fecReceiver) evict() {
	var oldest uint32
	found := false
	for groupID := range r.groups {
		if !found || groupID < oldest {
			oldest = groupID
			found = true
		}
	}
	if found {
		r.drop(oldest)
	}
}

// parity takes one parity shard and returns the member packets that can be
// recovered with it. The returned packets are the bytes the sender wrote,
// including the padding the shard carries, cut back to the length each member was
// described with. The shard itself is a view of the buffer the next packet is read
// into, so a group keeps a copy of it rather than the view.
func (r *fecReceiver) parity(description *fecHeader, shard []byte) [][]byte {
	r.active = true
	group := r.group(description)
	if group == nil {
		return nil
	}
	if int(description.Index) >= len(group.parity) {
		return nil
	}
	// Every shard of a group is as long as the longest member, so a parity shard of
	// another length describes a group that was not encoded this way.
	longest := 0
	for _, length := range group.lengths {
		if length > longest {
			longest = length
		}
	}
	if len(shard) != longest {
		return nil
	}
	// A parity packet can arrive twice — a shard that was retransmitted arrives
	// beside the one it replaced — and the shard it displaces goes back to the pool
	// it came from rather than to the collector.
	if previous := group.parity[description.Index]; previous != nil {
		r.release(previous)
	}
	group.parity[description.Index] = r.shard(shard)
	missing := 0
	for _, member := range group.members {
		if member == nil {
			missing++
		}
	}
	if missing == 0 {
		// Everything arrived on its own, which is the ordinary case: the parity was
		// insurance nobody had to claim.
		r.drop(group.groupID)
		return nil
	}
	shards := make([][]byte, 0, len(group.members)+len(group.parity))
	shards = append(shards, group.members...)
	shards = append(shards, group.parity...)
	filled, err := r.codec.recover(len(group.members), len(group.parity), shards)
	if err != nil {
		r.drop(group.groupID)
		return nil
	}
	if filled != missing {
		// More members are missing than the parity that arrived can replace: wait
		// for the shards that follow rather than giving up on the group.
		return nil
	}
	// The group leaves the table before anything is delivered: a recovered packet
	// takes the normal receive path, which may reach this receiver again.
	r.drop(group.groupID)
	recovered := make([][]byte, 0, missing)
	for index, member := range group.members {
		if member != nil {
			continue
		}
		recovered = append(recovered, shards[index][:group.lengths[index]])
	}
	r.recovered.Add(int64(len(recovered)))
	return recovered
}
