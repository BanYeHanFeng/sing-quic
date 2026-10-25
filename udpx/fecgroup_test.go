package udpx

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// fecTestStreamID is a stream a client opens: the low bit of a stream id belongs
// to the end that did not dial.
const fecTestStreamID = 2

// fecTestPacket is one packet a fake socket kept, parsed with the key ring of the
// direction it was written in.
type fecTestPacket struct {
	raw         []byte
	header      header
	description *fecHeader
	payload     []byte
}

// fecTestPackets returns what the socket wrote, parsed.
func fecTestPackets(t *testing.T, conn *fakeConn, ring *keyRing) []fecTestPacket {
	t.Helper()
	conn.mu.Lock()
	written := make([][]byte, len(conn.packets))
	for index, packet := range conn.packets {
		written[index] = bytes.Clone(packet)
	}
	conn.mu.Unlock()
	packets := make([]fecTestPacket, len(written))
	for index, packet := range written {
		packetHeader, description, payload, err := ring.open(bytes.Clone(packet))
		if err != nil {
			t.Fatalf("open packet %d: %v", index, err)
		}
		packets[index] = fecTestPacket{
			raw:         packet,
			header:      packetHeader,
			description: description,
			payload:     bytes.Clone(payload),
		}
	}
	return packets
}

// newTestFECPair builds two ends that share one key direction: the first protects
// what it sends, the second takes it.
func newTestFECPair(t *testing.T, options Options) (*association, *association, *fakeConn) {
	t.Helper()
	sendAEAD, err := newAEAD(testKey(0x11))
	if err != nil {
		t.Fatal(err)
	}
	conn := newFakeConn()
	sender := newAssociation(conn, handshakeResult{
		send: newKeyRing(0, sendAEAD),
		recv: newKeyRing(0, mustAEAD(t, testKey(0x22))),
	}, conn.LocalAddr(), options, true, false)
	t.Cleanup(func() {
		sender.shutdown(net.ErrClosed, false)
	})
	receiver := newAssociation(newFakeConn(), handshakeResult{
		send: newKeyRing(0, mustAEAD(t, testKey(0x33))),
		recv: newKeyRing(0, mustAEAD(t, testKey(0x11))),
	}, conn.LocalAddr(), Options{IdleTimeout: time.Minute}, false, false)
	t.Cleanup(func() {
		receiver.shutdown(net.ErrClosed, false)
	})
	return sender, receiver, conn
}

// fecQueueFrame queues one stream frame of the given size and sends it, and returns
// the data it carries.
func fecQueueFrame(t *testing.T, a *association, offset uint64, size int, fill byte) []byte {
	t.Helper()
	data := bytes.Repeat([]byte{fill}, size)
	a.queueFrame(appendStream(nil, fecTestStreamID, offset, false, data))
	err := a.flush()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// fecFeed hands the packets to the receiver, leaving out the packet numbers in
// dropped: what arrives is what a path chose to deliver.
func fecFeed(t *testing.T, receiver *association, packets []fecTestPacket, dropped ...uint32) {
	t.Helper()
	for _, packet := range packets {
		skip := false
		for _, droppedNumber := range dropped {
			if packet.header.PacketNumber == droppedNumber {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		err := receiver.handlePacket(bytes.Clone(packet.raw), receiver.RemoteAddr())
		if err != nil {
			t.Fatalf("packet %d: %v", packet.header.PacketNumber, err)
		}
	}
}

// TestFECGroupSending requires a group of k packets to be followed by m parity
// packets that describe it: the members are named by the packet number of the
// first of them, the lengths are the lengths they were sent with, and the shard is
// as long as the longest member rather than as long as the MTU.
func TestFECGroupSending(t *testing.T) {
	sender, _, conn := newTestFECPair(t, Options{IdleTimeout: time.Minute, FEC: FECOptions{DataShards: 4, ParityShards: 2}})
	sizes := []int{1000, 900, 800, 700}
	offset := uint64(0)
	for index, size := range sizes {
		fecQueueFrame(t, sender, offset, size, byte(index))
		offset += uint64(size)
	}
	packets := fecTestPackets(t, conn, &sender.sendRing)
	if len(packets) != len(sizes)+2 {
		t.Fatalf("%d packets written for four members and two parity shards", len(packets))
	}
	longest := len(packets[0].raw)
	for index := range sizes {
		if packets[index].header.Type != packetTypeData {
			t.Fatalf("packet %d is of type %d", index, packets[index].header.Type)
		}
		if packets[index].header.PacketNumber != uint32(index) {
			t.Fatalf("member %d is packet %d", index, packets[index].header.PacketNumber)
		}
	}
	for index := len(sizes); index < len(packets); index++ {
		parity := packets[index]
		if parity.header.Type != packetTypeFEC {
			t.Fatalf("packet %d is of type %d", index, parity.header.Type)
		}
		if parity.header.PacketNumber != uint32(index) {
			t.Fatalf("parity shard %d is packet %d", index, parity.header.PacketNumber)
		}
		if parity.description == nil {
			t.Fatalf("packet %d has no group description", index)
		}
		if parity.description.GroupID != 0 {
			t.Fatalf("group starts at %d", parity.description.GroupID)
		}
		if parity.description.MemberCount != uint8(len(sizes)) || parity.description.ParityCount != 2 {
			t.Fatalf("group of %d members and %d parity shards", parity.description.MemberCount, parity.description.ParityCount)
		}
		if parity.description.Index != uint8(index-len(sizes)) {
			t.Fatalf("parity shard %d is index %d", index, parity.description.Index)
		}
		for member := range sizes {
			if length := parity.description.memberLength(member); length != len(packets[member].raw) {
				t.Fatalf("member %d is described as %d bytes but is %d", member, length, len(packets[member].raw))
			}
		}
		if len(parity.payload) != longest {
			t.Fatalf("parity shard is %d bytes for a longest member of %d", len(parity.payload), longest)
		}
	}
	// Redundancy takes room in the window like everything else, which is what keeps
	// a protected stream from filling every buffer between the two ends.
	sender.flightMu.Lock()
	inFlight := sender.inFlight.len()
	parityBytes := sender.inFlight.parityBytes
	totalBytes := sender.inFlight.bytes
	sender.flightMu.Unlock()
	if inFlight != len(packets) {
		t.Fatalf("%d packets in flight for %d written", inFlight, len(packets))
	}
	if parityBytes == 0 || parityBytes >= totalBytes {
		t.Fatalf("%d of %d bytes in flight are redundancy", parityBytes, totalBytes)
	}
}

// TestFECGroupRecovery requires a group with a missing member to be recovered from
// its parity, and the recovered member to take the normal receive path: its frames
// are delivered, and the packet is acknowledged, which is what tells the sender it
// does not have to send it again.
func TestFECGroupRecovery(t *testing.T) {
	sender, receiver, conn := newTestFECPair(t, Options{IdleTimeout: time.Minute, FEC: FECOptions{DataShards: 4, ParityShards: 2}})
	sizes := []int{1000, 1000, 1000, 1000, 500, 500, 500, 500}
	offset := uint64(0)
	expected := make([]byte, 0, 6000)
	for index, size := range sizes {
		expected = append(expected, fecQueueFrame(t, sender, offset, size, byte(index))...)
		offset += uint64(size)
	}
	packets := fecTestPackets(t, conn, &sender.sendRing)
	// Two groups of four members and two parity shards each.
	if len(packets) != 12 {
		t.Fatalf("%d packets written for two groups", len(packets))
	}
	// The first group is the one that pays for the receiver not knowing yet that the
	// peer protects what it sends: nothing that arrived before the first parity
	// packet was kept, so its members are only delivered by arriving themselves.
	fecFeed(t, receiver, packets[0:1])
	fecFeed(t, receiver, packets[2:4])
	fecFeed(t, receiver, packets[4:5])
	fecFeed(t, receiver, packets[1:2])
	// The second group loses a member, and its parity is enough to get it back.
	fecFeed(t, receiver, packets[6:8])
	fecFeed(t, receiver, packets[9:10])
	fecFeed(t, receiver, packets[10:11])
	receiver.streamsMu.Lock()
	stream := receiver.streams[fecTestStreamID]
	receiver.streamsMu.Unlock()
	if stream == nil {
		t.Fatal("no stream was opened by the frames")
	}
	received := make([]byte, len(expected))
	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	read := 0
	for read < len(received) {
		n, err := stream.Read(received[read:])
		if err != nil {
			t.Fatalf("read %d of %d bytes: %v", read, len(received), err)
		}
		read += n
	}
	if !bytes.Equal(received, expected) {
		t.Fatal("what the stream delivered is not what was written")
	}
	// The recovered packet is acknowledged like one that arrived: the sender has to
	// stop waiting for it, or the recovery saved nothing.
	receiver.ackMu.Lock()
	recovered := receiver.ack.ranges.contains(8)
	receiver.ackMu.Unlock()
	if !recovered {
		t.Fatal("the recovered packet was not acknowledged")
	}
}

// TestFECGroupNotEnoughShards requires a group that is short of shards to be left
// alone: recovering from fewer than k is not possible, and a receiver that guessed
// would deliver bytes the sender never wrote.
func TestFECGroupNotEnoughShards(t *testing.T) {
	sender, receiver, conn := newTestFECPair(t, Options{IdleTimeout: time.Minute, FEC: FECOptions{DataShards: 4, ParityShards: 2}})
	offset := uint64(0)
	for index := 0; index < 8; index++ {
		offset += uint64(len(fecQueueFrame(t, sender, offset, 1000, byte(index))))
	}
	packets := fecTestPackets(t, conn, &sender.sendRing)
	if len(packets) != 12 {
		t.Fatalf("%d packets written for two groups", len(packets))
	}
	// The first group arrives whole, which is also what tells the receiver that its
	// peer protects what it sends.
	fecFeed(t, receiver, packets[0:5])
	// The second group is short of one shard of four: two members and one parity
	// packet arrived, and that is not enough to say anything about the member that
	// did not.
	fecFeed(t, receiver, packets[6:8], 7)
	fecFeed(t, receiver, packets[10:11])
	receiver.ackMu.Lock()
	delivered := receiver.ack.ranges.contains(8)
	receiver.ackMu.Unlock()
	if delivered {
		t.Fatal("a packet was acknowledged that never arrived")
	}
}

// TestFECGroupTimer requires a group that the sender is too idle to fill to be
// closed anyway, and a group of one packet to be closed without redundancy.
func TestFECGroupTimer(t *testing.T) {
	sender, _, conn := newTestFECPair(t, Options{IdleTimeout: time.Minute, FEC: FECOptions{DataShards: 8, ParityShards: 2}})
	// One member on its own is not worth protecting, and the timer is what says
	// that nothing more is coming.
	fecQueueFrame(t, sender, 0, 1000, 0)
	time.Sleep(4 * fecGroupTimeout)
	if written := conn.len(); written != 1 {
		t.Fatalf("%d packets written for a group of one member", written)
	}
	// Two members are, and the group that the timer closes describes the two it has
	// rather than the eight it was waiting for.
	fecQueueFrame(t, sender, 1000, 1000, 1)
	fecQueueFrame(t, sender, 2000, 1000, 2)
	time.Sleep(4 * fecGroupTimeout)
	packets := fecTestPackets(t, conn, &sender.sendRing)
	if len(packets) != 5 {
		t.Fatalf("%d packets written for a group of two members", len(packets))
	}
	for index := 3; index < len(packets); index++ {
		parity := packets[index]
		if parity.header.Type != packetTypeFEC {
			t.Fatalf("packet %d is of type %d", index, parity.header.Type)
		}
		if parity.description.MemberCount != 2 {
			t.Fatalf("a group closed by the timer describes %d members", parity.description.MemberCount)
		}
		if parity.description.GroupID != 1 {
			t.Fatalf("group starts at %d", parity.description.GroupID)
		}
	}
}

// TestFECOverLossyLink requires a transfer over a path that loses packets to arrive
// whole, with parity that recovered what the path dropped: recovering a member is
// cheaper than waiting a round trip for it, which is the whole reason the packet
// number is in the clear.
func TestFECOverLossyLink(t *testing.T) {
	for _, config := range []struct {
		name    string
		options FECOptions
	}{
		{"fixed parity", FECOptions{DataShards: 8, ParityShards: 2}},
		{"parity from loss", FECOptions{DataShards: 8}},
	} {
		t.Run(config.name, func(t *testing.T) {
			testFECOverLossyLink(t, config.options)
		})
	}
}

func testFECOverLossyLink(t *testing.T, fecOptions FECOptions) {
	password := NewPassword("password")
	listenerConn := udpConn(t)
	listener := ListenPacket(listenerConn, testVerifier{password}, Options{})
	defer listener.Close()
	link := newSimulatedLink(t, listenerConn.LocalAddr(), linkOptions{loss: 0.05, delay: 20 * time.Millisecond})
	ctx := testContext(t, 120*time.Second)
	client, err := Dial(ctx, udpConn(t), link.clientAddr(), password, Options{FEC: fecOptions})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseWithError(nil)
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload(256 << 10)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		if _, writeErr := stream.Write(payload); writeErr != nil {
			t.Errorf("write: %v", writeErr)
			return
		}
		if closeErr := stream.CloseWrite(); closeErr != nil {
			t.Errorf("close write: %v", closeErr)
		}
	}()
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	read := make([]byte, 0, len(payload))
	buffer := make([]byte, 32*1024)
	for len(read) < len(payload) {
		n, readErr := accepted.Read(buffer)
		if readErr != nil {
			t.Fatalf("read %d of %d bytes: %v", len(read), len(payload), readErr)
		}
		read = append(read, buffer[:n]...)
	}
	if !bytes.Equal(read, payload) {
		t.Fatal("the payload changed on the way")
	}
	recovered := server.(*association).fec.recovered.Load()
	if recovered == 0 {
		t.Fatal("no packet was recovered from parity")
	}
}

// TestFECParityFollowsLoss requires the redundancy of a group to follow what the
// path is losing: nothing where nothing is lost, and more where more is, with what
// was asked for taking precedence over both.
func TestFECParityFollowsLoss(t *testing.T) {
	sender := newFECSender(FECOptions{DataShards: 8})
	if sender == nil {
		t.Fatal("data shards of eight did not turn forward error correction on")
	}
	// Nothing has been settled, so nothing is known about the path.
	if parity := sender.parity(); parity != 0 {
		t.Fatalf("%d parity shards before anything was acknowledged", parity)
	}
	sender.observe(32, 0)
	if parity := sender.parity(); parity != 0 {
		t.Fatalf("%d parity shards on a path that lost nothing", parity)
	}
	// Five per cent of what is settled: a group of eight expects half a packet lost.
	sender.observe(28, 4)
	if parity := sender.parity(); parity < 1 {
		t.Fatalf("%d parity shards for a path losing five per cent", parity)
	}
	// A path that loses half of everything gets redundancy in proportion, up to the
	// members it covers.
	sender.observe(0, 64)
	if parity := sender.parity(); parity < 2 || parity > 8 {
		t.Fatalf("%d parity shards for a path losing half of it", parity)
	}
	// What the caller asked for is what is sent, whatever the path does.
	fixed := newFECSender(FECOptions{DataShards: 8, ParityShards: 3})
	if parity := fixed.parity(); parity != 3 {
		t.Fatalf("%d parity shards for a group that asked for three", parity)
	}
	if sender := newFECSender(FECOptions{DataShards: 0}); sender != nil {
		t.Fatal("zero data shards did not turn forward error correction off")
	}
}

// TestFECRecoveredOnce requires a packet that already arrived to be left alone when
// the group around it is recovered. The first parity shard can arrive before the
// members do, so a group is assembled from a cache the earliest members never
// entered; recovering it then has to notice that they arrived rather than hand the
// same frames up a second time.
func TestFECRecoveredOnce(t *testing.T) {
	sender, receiver, conn := newTestFECPair(t, Options{IdleTimeout: time.Minute, FEC: FECOptions{DataShards: 4, ParityShards: 2}})
	for channel := range 4 {
		if err := sender.SendDatagram(uint32(channel), []byte{byte(channel)}); err != nil {
			t.Fatal(err)
		}
	}
	packets := fecTestPackets(t, conn, &sender.sendRing)
	if len(packets) != 6 {
		t.Fatalf("%d packets written for one group", len(packets))
	}
	// The first member arrives before this end knows the peer protects what it
	// sends, so it is delivered and not kept. Parity follows, then the rest of the
	// members, and the second shard is what completes the group.
	fecFeed(t, receiver, []fecTestPacket{packets[0], packets[4], packets[1], packets[2], packets[3], packets[5]})
	seen := make(map[uint32]int)
	for range 4 {
		datagram, err := receiver.ReceiveDatagram(testContext(t, 5*time.Second))
		if err != nil {
			t.Fatalf("%d datagrams arrived: %v", len(seen), err)
		}
		seen[datagram.Channel]++
	}
	for channel := range uint32(4) {
		if seen[channel] != 1 {
			t.Fatalf("channel %d arrived %d times", channel, seen[channel])
		}
	}
	// Nothing else is waiting: a recovered copy of a member that arrived would be
	// one more message, not a correction.
	extra := testContext(t, 500*time.Millisecond)
	datagram, err := receiver.ReceiveDatagram(extra)
	if err == nil {
		t.Fatalf("channel %d arrived twice", datagram.Channel)
	}
}
