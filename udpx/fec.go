package udpx

import (
	"math"
	"sync/atomic"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// Forward error correction
//
// A FEC group is k member packets and m parity shards: every member is a
// polynomial's worth of data, every parity shard is one evaluation of those
// polynomials, and any k of the k+m shards are enough to get the members back.
// That is a Reed-Solomon code over GF(256), which is what this file computes and
// nothing else: what a group is, how it is described on the wire and when to
// encode one belong to the packet and to the association.
//
// The code is systematic in the sense that matters here: the members travel as
// themselves, and the parity is only ever used by a receiver that is missing
// something. A member that arrives is never reconstructed, and a group whose
// members all arrive costs its parity and nothing else.
//
// The generator matrix is the identity for the members and a Cauchy matrix for
// the parity. Any square submatrix of a Cauchy matrix is invertible, so the
// combined matrix is as well whatever k of its rows a receiver is left with —
// which is the property the whole scheme rests on: a group is recoverable from
// any k shards, not from a lucky subset of them.

const (
	// gfPrimitive is the primitive polynomial of the field: x^8 + x^4 + x^3 +
	// x^2 + 1. It is one of the choices that make multiplication by 2 generate
	// every non-zero element, which is what the tables below assume.
	gfPrimitive = 0x11d

	// fecMaxShards is the most shards a group can have. Every count on the wire
	// is a byte, and a group is described by one byte of members and one of
	// parity.
	fecMaxShards = 256
)

// The field is small enough to multiply and divide by table: a product is a sum
// of two logarithms, and an inverse is a subtraction.
var (
	gfExp [512]byte
	gfLog [256]byte
	// gfProducts is the product of every coefficient with every byte. Encoding a
	// shard multiplies a whole shard by one coefficient, and a table turns that
	// from two lookups and an addition per byte into one lookup per byte: at 8+2
	// over a gigabyte of bulk data that is two gigabytes of multiplications, which
	// is the single largest cost a sender with redundancy switched on pays.
	gfProducts [256][256]byte
)

func init() {
	value := 1
	for index := 0; index < 255; index++ {
		gfExp[index] = byte(value)
		gfLog[value] = byte(index)
		value <<= 1
		if value&0x100 != 0 {
			value ^= gfPrimitive
		}
	}
	// The upper half of the exponent table is the lower half again, so a sum of
	// two logarithms never needs a modulo.
	for index := 255; index < len(gfExp); index++ {
		gfExp[index] = gfExp[index-255]
	}
	for coefficient := 0; coefficient < 256; coefficient++ {
		for value := 0; value < 256; value++ {
			gfProducts[coefficient][value] = gfMul(byte(coefficient), byte(value))
		}
	}
}

// gfMul multiplies in the field.
func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// gfInverse returns the multiplicative inverse of a, which must not be zero.
func gfInverse(a byte) byte {
	return gfExp[255-int(gfLog[a])]
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

// fecCoefficients writes the coefficients of shard index of a group of members
// members into row: a member shard is the unit vector of its own index, a parity
// shard is one row of the Cauchy matrix.
func fecCoefficients(members, index int, row []byte) {
	for position := range row {
		row[position] = 0
	}
	if index < members {
		row[index] = 1
		return
	}
	// The Cauchy matrix is 1/(x_i + y_j) with x_i the row and y_j the column, and
	// addition in this field is exclusive or. The two sets are apart by
	// construction, so no entry is a division by zero and no two of them are
	// equal (which is what makes every square submatrix invertible).
	parity := index - members
	for column := 0; column < members; column++ {
		row[column] = gfInverse(byte(parity) ^ byte(members+column))
	}
}

// fecEncode computes the parity shards of a group. members holds the member
// shards in the order the group describes them and parity the shards to compute,
// all of the same length; only parity is written.
func fecEncode(members [][]byte, parity [][]byte) error {
	shards := make([][]byte, 0, len(members)+len(parity))
	shards = append(shards, members...)
	shards = append(shards, parity...)
	_, err := fecShardSize(len(members), len(parity), shards)
	if err != nil {
		return err
	}
	row := make([]byte, len(members))
	for index := range parity {
		shard := parity[index]
		for position := range shard {
			shard[position] = 0
		}
		fecCoefficients(len(members), len(members)+index, row)
		for column, coefficient := range row {
			if coefficient == 0 {
				continue
			}
			// The member is cut to the shard's length once — they are equal by the
			// shape check above, and saying so is what takes the bounds check out of
			// the loop below, where it would be paid per byte.
			member := members[column][:len(shard)]
			if coefficient == 1 {
				for offset, value := range member {
					shard[offset] ^= value
				}
				continue
			}
			products := &gfProducts[coefficient]
			for offset, value := range member {
				shard[offset] ^= products[value]
			}
		}
	}
	return nil
}

// fecInvert inverts a square matrix of coefficients over the field, or reports
// that it has no inverse.
func fecInvert(matrix [][]byte) ([][]byte, error) {
	size := len(matrix)
	work := make([][]byte, size)
	for index, row := range matrix {
		if len(row) != size {
			return nil, E.New("FEC matrix row of ", len(row), " coefficients")
		}
		work[index] = make([]byte, 2*size)
		copy(work[index], row)
		work[index][size+index] = 1
	}
	for column := 0; column < size; column++ {
		pivot := -1
		for row := column; row < size; row++ {
			if work[row][column] != 0 {
				pivot = row
				break
			}
		}
		if pivot < 0 {
			return nil, E.New("FEC shards are not independent")
		}
		work[column], work[pivot] = work[pivot], work[column]
		normalize := gfInverse(work[column][column])
		for offset := column; offset < 2*size; offset++ {
			work[column][offset] = gfMul(work[column][offset], normalize)
		}
		for row := 0; row < size; row++ {
			if row == column {
				continue
			}
			factor := work[row][column]
			if factor == 0 {
				continue
			}
			for offset := column; offset < 2*size; offset++ {
				work[row][offset] ^= gfMul(factor, work[column][offset])
			}
		}
	}
	inverse := make([][]byte, size)
	for index := range inverse {
		inverse[index] = work[index][size:]
	}
	return inverse, nil
}

// fecRecover reconstructs the member shards of a group that did not arrive.
// shards holds members+parity entries, the members first and then the parity
// shards, a nil entry being a shard nobody has. The members that are missing are
// filled in when there were enough shards to recover from; nothing is written
// when there were not.
func fecRecover(members, parity int, shards [][]byte) error {
	if len(shards) != members+parity {
		return E.New("FEC group of ", len(shards), " shards for ", members, " members and ", parity, " parity shards")
	}
	shardLen, err := fecShardSize(members, parity, shards)
	if err != nil {
		return err
	}
	available := make([]int, 0, members+parity)
	for index, shard := range shards {
		if shard != nil {
			available = append(available, index)
		}
	}
	if len(available) < members {
		return E.New("FEC group of ", len(available), " shards for ", members, " members")
	}
	// Any k of the shards are enough: the matrix they form is invertible because
	// the parity rows of the generator come from a Cauchy matrix.
	known := available[:members]
	matrix := make([][]byte, members)
	for index, shardIndex := range known {
		matrix[index] = make([]byte, members)
		fecCoefficients(members, shardIndex, matrix[index])
	}
	inverse, err := fecInvert(matrix)
	if err != nil {
		return err
	}
	recovered := make([][]byte, members)
	for member := 0; member < members; member++ {
		if shards[member] != nil {
			continue
		}
		shard := make([]byte, shardLen)
		for row := 0; row < members; row++ {
			coefficient := inverse[member][row]
			if coefficient == 0 {
				continue
			}
			products := &gfProducts[coefficient]
			for offset, value := range shards[known[row]] {
				shard[offset] ^= products[value]
			}
		}
		recovered[member] = shard
	}
	for member, shard := range recovered {
		if shard != nil {
			shards[member] = shard
		}
	}
	return nil
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

	// fecLossSamples is how many packets have to be settled before the losses the
	// path is showing are worth acting on. Below it, the fraction is a fraction of
	// three packets and says nothing.
	fecLossSamples = 32

	// fecLossWindow is how many settled packets the loss estimate covers before it
	// is halved. It is the memory of the estimate: long enough not to react to a
	// burst, short enough to follow a path that changed.
	fecLossWindow = 128

	// fecRedundancyGain is how much redundancy a group gets for the losses it is
	// expected to see. Above one, because the point of the redundancy is the groups
	// that lose more than their share: a group that loses exactly what it expected
	// would be recovered by covering the average alone, and the ones that do not are
	// the ones whose members wait a round trip.
	fecRedundancyGain = 1.5
)

// fecSender assembles the groups this end sends. It is driven by the goroutine
// that sends, under the send lock, which is also what keeps packet numbers in the
// order the groups describe.
type fecSender struct {
	dataShards int
	// fixedParity is the redundancy that was asked for, or zero when the path
	// decides it.
	fixedParity int

	// lost and settled are what the path is doing: how many of the packets that
	// were settled since the estimate was last halved the path dropped, and how
	// many were settled. Redundancy is only worth as much as the losses it
	// replaces, so this is what decides how much to send.
	lost    int
	settled int

	// group holds the packets of the open group in the order they were sent, and
	// shardLen the length of the longest of them: parity shards are padded to it
	// rather than to the MTU, so a group of small packets stays small.
	group    [][]byte
	groupID  uint32
	shardLen int

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
	if parityShards > fecMaxParityShards {
		parityShards = fecMaxParityShards
	}
	if parityShards > dataShards {
		parityShards = dataShards
	}
	if parityShards < 0 {
		parityShards = 0
	}
	return &fecSender{
		dataShards:  dataShards,
		fixedParity: parityShards,
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

// observe records how many of the packets that one acknowledgement settled were
// lost. Only what carried frames is counted: redundancy that is lost is not a
// reason to send more redundancy, or a path that drops a fraction of everything
// would be answered with a fraction of everything, for as long as it lasts.
func (s *fecSender) observe(acked, lost int) {
	s.settled += acked + lost
	s.lost += lost
	if s.settled >= 2*fecLossWindow {
		// The estimate follows the path rather than its whole history: a path that
		// recovered is not a path that is still losing.
		s.settled /= 2
		s.lost /= 2
	}
}

// parity is how many redundant packets the next group gets.
//
// It is one and a half times the losses a group is expected to see: enough to
// cover the average and some of the spread, and not so much that a group pays for
// the tail of it that a retransmission would have covered anyway. A path that has
// shown no loss gets none, which is what makes this free where there is nothing to
// repair.
func (s *fecSender) parity() int {
	if s.fixedParity > 0 {
		return s.fixedParity
	}
	if s.settled < fecLossSamples {
		return 0
	}
	expected := fecRedundancyGain * float64(s.dataShards) * float64(s.lost) / float64(s.settled)
	count := int(math.Ceil(expected))
	if count < 0 {
		count = 0
	}
	if count > s.dataShards {
		count = s.dataShards
	}
	if count > fecMaxParityShards {
		count = fecMaxParityShards
	}
	return count
}

// payloadBudget is how many payload bytes a packet may carry once this end
// protects its packets: a parity shard is as long as the longest member and it
// describes the group in its clear header, so members give up the room that
// description needs, and the parity packet is never larger than a member.
func (s *fecSender) payloadBudget() int {
	return maxPacketSize - 2*(headerLen+tagLen) - fecFixedLen - fecLengthLen*s.dataShards
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
	if s.timer != nil {
		s.timer.Stop()
	}
}

// fecMemberLocked adds a packet that just left to the open group, and encodes the
// group once it holds a full one. The caller holds sendMu.
func (a *association) fecMemberLocked(packet []byte, packetNumber uint32) error {
	sender := a.fecSender
	if sender == nil {
		return nil
	}
	if len(sender.group) == 0 {
		// A group is named after its first member, which is what a receiver counts
		// from: members are not enumerated, they are the packet numbers that follow.
		sender.groupID = packetNumber
		sender.timer.Reset(fecGroupTimeout)
	}
	// The packet bytes are kept rather than a description of them: a member is
	// recovered as the packet the sender wrote, which is what makes it
	// authenticable and what keeps recovery from being a second kind of receive.
	member := append(sender.buffer(), packet...)
	sender.group = append(sender.group, member)
	if len(member) > sender.shardLen {
		sender.shardLen = len(member)
	}
	if len(sender.group) < sender.dataShards {
		return nil
	}
	return a.sendParityLocked()
}

// fecObserve tells the sender what one acknowledgement settled, so that the
// redundancy of the next group follows what the path is losing.
func (a *association) fecObserve(acked, lost []*sentPacket) {
	if a.fecSender == nil {
		return
	}
	settled := 0
	dropped := 0
	for _, packet := range acked {
		if !packet.parity {
			settled++
		}
	}
	for _, packet := range lost {
		if !packet.parity {
			dropped++
		}
	}
	if settled == 0 && dropped == 0 {
		return
	}
	a.sendMu.Lock()
	a.fecSender.observe(settled, dropped)
	a.sendMu.Unlock()
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
	if len(sender.group) < fecMinGroupMembers {
		// Two packets are not worth as many parity shards: what a group this small
		// buys is one timeout of latency on a loss, and the sender is idle enough
		// that what it protects is not what the peer is waiting for.
		sender.close()
		return
	}
	if err := a.sendParityLocked(); err != nil {
		return
	}
	// Nothing else is going to fill a batch on a timer: the group closed on its
	// own, so the parity it produced leaves now.
	_ = a.writePendingLocked()
}

// sendParityLocked encodes the open group and sends its parity shards, one packet
// each. The caller holds sendMu.
func (a *association) sendParityLocked() error {
	sender := a.fecSender
	members := sender.group
	if len(members) == 0 {
		return nil
	}
	parityCount := sender.parity()
	if parityCount == 0 {
		// The path is not losing anything worth covering, so the group is closed
		// without redundancy: what it would cost is the parity of every group
		// forever, and what it would save is nothing.
		sender.close()
		return nil
	}
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
	err := fecEncode(members, parity)
	sender.close()
	if err == nil {
		for index, shard := range parity {
			description.Index = uint8(index)
			err = a.sendParityPacketLocked(description, shard)
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

// sendParityPacketLocked writes one parity shard. The caller holds sendMu, so the
// packet number is the next one in the sequence: parity packets are numbered like
// everything else, which is what keeps the members of a group in the one order the
// description assumes.
func (a *association) sendParityPacketLocked(description fecHeader, shard []byte) error {
	h := header{
		ConnectionID: a.peerConnID,
		Type:         packetTypeFEC,
		Epoch:        a.sendRing.epoch(),
		PacketNumber: a.sendPacket,
	}
	packet, err := a.sealLocked(h, &description, shard)
	if err != nil {
		return err
	}
	a.sendPacket++
	return a.appendPacketLocked(&sentPacket{
		packetNumber: h.PacketNumber,
		sentAt:       time.Now(),
		size:         len(packet),
		ackEliciting: true,
		parity:       true,
	}, packet)
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
	available := 0
	for _, member := range group.members {
		if member != nil {
			available++
		}
	}
	for _, parityShard := range group.parity {
		if parityShard != nil {
			available++
		}
	}
	if available < len(group.members) {
		return nil
	}
	missing := false
	for _, member := range group.members {
		if member == nil {
			missing = true
			break
		}
	}
	if !missing {
		// Everything arrived on its own, which is the ordinary case: the parity was
		// insurance nobody had to claim.
		r.drop(group.groupID)
		return nil
	}
	shards := make([][]byte, 0, len(group.members)+len(group.parity))
	shards = append(shards, group.members...)
	shards = append(shards, group.parity...)
	err := fecRecover(len(group.members), len(group.parity), shards)
	if err != nil {
		r.drop(group.groupID)
		return nil
	}
	// The group leaves the table before anything is delivered: a recovered packet
	// takes the normal receive path, which may reach this receiver again.
	r.drop(group.groupID)
	recovered := make([][]byte, 0, len(group.members))
	for index, member := range group.members {
		if member != nil {
			continue
		}
		recovered = append(recovered, shards[index][:group.lengths[index]])
	}
	r.recovered.Add(int64(len(recovered)))
	return recovered
}
