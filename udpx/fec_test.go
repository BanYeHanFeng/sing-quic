package udpx

import (
	"bytes"
	"math/rand"
	"testing"
)

// fecTestShards builds a group of members members and parity parity shards, all
// of shardLen bytes, with the given seed so a failure is a failure that happens
// again.
func fecTestShards(members, parity, shardLen int, seed int64) ([][]byte, [][]byte) {
	random := rand.New(rand.NewSource(seed))
	shards := make([][]byte, members)
	for index := range shards {
		shards[index] = make([]byte, shardLen)
		random.Read(shards[index])
	}
	parityShards := make([][]byte, parity)
	for index := range parityShards {
		parityShards[index] = make([]byte, shardLen)
	}
	return shards, parityShards
}

// TestFECEncodeRecover requires a group to come back from as many missing members
// as it has parity shards, wherever they fell: the code reconstructs from any k of
// the k+m shards, so the position of a loss is not part of the question.
func TestFECEncodeRecover(t *testing.T) {
	for _, members := range []int{1, 2, 3, 4, 5, 6, 8, 32} {
		for _, parity := range []int{1, 2, 3} {
			if members+parity > 40 {
				continue
			}
			for shardLen := 1; shardLen <= 9; shardLen += 4 {
				original, parityShards := fecTestShards(members, parity, shardLen, int64(members*100+parity*10+shardLen))
				var codec fecCodec
				if err := codec.encode(original, parityShards); err != nil {
					t.Fatalf("%d/%d: encode: %v", members, parity, err)
				}
				for lost := 0; lost < members; lost++ {
					shards := fecGroup(original, parityShards)
					shards[lost] = nil
					filled, err := codec.recover(members, parity, shards)
					if err != nil {
						t.Fatalf("%d/%d: recover %d: %v", members, parity, lost, err)
					}
					if filled != 1 {
						t.Fatalf("%d/%d: %d members filled in for the one at %d", members, parity, filled, lost)
					}
					fecRequireRecovered(t, members, original, shards)
				}
				for first := 0; first < members; first++ {
					for second := first + 1; second < members; second++ {
						shards := fecGroup(original, parityShards)
						shards[first] = nil
						shards[second] = nil
						filled, err := codec.recover(members, parity, shards)
						if err != nil {
							t.Fatalf("%d/%d: recover %d and %d: %v", members, parity, first, second, err)
						}
						want := 0
						if parity >= 2 {
							want = 2
						}
						if filled != want {
							t.Fatalf("%d/%d: %d members filled in for %d and %d", members, parity, filled, first, second)
						}
						if want == 2 {
							fecRequireRecovered(t, members, original, shards)
						}
					}
				}
			}
		}
	}
}

// fecGroup is the shard slice a receiver works on: the members first and then the
// parity, as a group describes them.
func fecGroup(members, parity [][]byte) [][]byte {
	shards := make([][]byte, 0, len(members)+len(parity))
	shards = append(shards, members...)
	shards = append(shards, parity...)
	return shards
}

// fecRequireRecovered requires every member of the slice to be the shard that was
// encoded, including the ones that never left.
func fecRequireRecovered(t *testing.T, members int, original, shards [][]byte) {
	t.Helper()
	for index := 0; index < members; index++ {
		if !bytes.Equal(shards[index], original[index]) {
			t.Fatalf("member %d came back changed", index)
		}
	}
}

// TestFECRecoverByPacketBytes requires a recovered member to be the packet that
// was sent, byte for byte, so that it goes through authentication like any other
// packet: recovering a payload would leave the header to be invented, and a
// packet whose header was invented is not the packet the sender wrote.
func TestFECRecoverByPacketBytes(t *testing.T) {
	ring := newKeyRing(0, mustAEAD(t, testKey(0x11)))
	members := make([][]byte, 4)
	payloads := make([][]byte, 4)
	shardLen := 0
	for index := range members {
		payload := bytes.Repeat([]byte{byte(index), 0xaa, 0x55}, 40+index)
		payloads[index] = payload
		packet, err := ring.seal(nil, header{
			ConnectionID: connectionID{0x01, 0x02},
			Type:         packetTypeData,
			PacketNumber: uint32(index),
		}, nil, payload)
		if err != nil {
			t.Fatal(err)
		}
		members[index] = packet
		if len(packet) > shardLen {
			shardLen = len(packet)
		}
	}
	// Members are padded to the longest one, which is what a group of small
	// packets costs instead of the MTU.
	shards := make([][]byte, len(members))
	for index, member := range members {
		shards[index] = make([]byte, shardLen)
		copy(shards[index], member)
	}
	parityShards := [][]byte{make([]byte, shardLen), make([]byte, shardLen)}
	var codec fecCodec
	err := codec.encode(shards, parityShards)
	if err != nil {
		t.Fatal(err)
	}
	// Lose two members anywhere: two parity shards replace two members.
	recovered := [][]byte{shards[0], nil, nil, shards[3], parityShards[0], parityShards[1]}
	filled, err := codec.recover(len(members), 2, recovered)
	if err != nil {
		t.Fatal(err)
	}
	if filled != 2 {
		t.Fatalf("%d members filled in for two missing", filled)
	}
	for index, packet := range recovered[:len(members)] {
		recoveredHeader, _, payload, openErr := ring.open(packet[:len(members[index])])
		if openErr != nil {
			t.Fatalf("member %d did not authenticate after recovery: %v", index, openErr)
		}
		if recoveredHeader.PacketNumber != uint32(index) {
			t.Fatalf("member %d came back as packet %d", index, recoveredHeader.PacketNumber)
		}
		if !bytes.Equal(payload, payloads[index]) {
			t.Fatalf("member %d came back with other content", index)
		}
	}
}

// TestFECRejects requires the codec to refuse shapes it cannot encode or recover,
// so a group description the wire allows but the code cannot serve is dropped
// instead of producing garbage that then fails authentication.
func TestFECRejects(t *testing.T) {
	var codec fecCodec
	shards := [][]byte{make([]byte, 4), make([]byte, 4), make([]byte, 4)}
	if err := codec.encode(nil, shards[:1]); err == nil {
		t.Fatal("a group of no members was encoded")
	}
	if err := codec.encode(shards, nil); err == nil {
		t.Fatal("a group of no parity shards was encoded")
	}
	uneven := [][]byte{make([]byte, 4), make([]byte, 5)}
	if err := codec.encode(uneven, shards[:1]); err == nil {
		t.Fatal("shards of different lengths were encoded")
	}
	// 300 shards do not fit in the two bytes that describe a group.
	tooMany := make([][]byte, 300)
	for index := range tooMany {
		tooMany[index] = make([]byte, 1)
	}
	if err := codec.encode(tooMany[:200], tooMany[200:]); err == nil {
		t.Fatal("a group of 300 shards was encoded")
	}
	// k of k+m is the minimum: one short and nothing is promised.
	full := [][]byte{make([]byte, 4), make([]byte, 4), make([]byte, 4)}
	if _, err := codec.recover(3, 1, full[:2]); err == nil {
		t.Fatal("a group without enough shards was recovered")
	}
	// Two members missing and one parity shard to replace them: nothing is filled
	// in, but the group is not an error — a shard still on the path may arrive.
	short := [][]byte{make([]byte, 4), nil, nil, nil}
	if filled, err := codec.recover(3, 1, short); err != nil || filled != 0 {
		t.Fatalf("%d members filled in from a group that is two shards short", filled)
	}
	if _, err := codec.recover(2, 1, [][]byte{make([]byte, 4), make([]byte, 4)}); err == nil {
		t.Fatal("a group of the wrong number of shards was recovered")
	}
	// Two members missing and two parity shards: the code is MDS, so which two
	// went missing is not part of the question.
	together := [][]byte{nil, make([]byte, 4), nil, make([]byte, 4), make([]byte, 4), make([]byte, 4)}
	if filled, err := codec.recover(4, 2, together); err != nil || filled != 2 {
		t.Fatalf("%d members filled in for two missing", filled)
	}
}
