package udpx

import (
	"bytes"
	"math/rand"
	"slices"
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

// TestGaloisField requires the field arithmetic to be arithmetic: every element
// has an inverse, and multiplying by it gives one.
func TestGaloisField(t *testing.T) {
	for value := 1; value < 256; value++ {
		inverse := gfInverse(byte(value))
		if inverse == 0 {
			t.Fatalf("%d has an inverse of zero", value)
		}
		if product := gfMul(byte(value), inverse); product != 1 {
			t.Fatalf("%d times its inverse is %d", value, product)
		}
	}
	// Multiplication commutes and distributes, which is the part a wrong table
	// breaks without failing the check above.
	for first := 0; first < 256; first += 7 {
		for second := 0; second < 256; second += 11 {
			if gfMul(byte(first), byte(second)) != gfMul(byte(second), byte(first)) {
				t.Fatalf("%d times %d does not commute", first, second)
			}
			third := byte(second + 1)
			distributed := gfMul(byte(first), byte(second)) ^ gfMul(byte(first), third)
			if gfMul(byte(first), byte(second)^third) != distributed {
				t.Fatalf("%d does not distribute over %d and %d", first, second, third)
			}
		}
	}
}

// TestFECEncodeRecover requires a group to be recoverable from any k of its k+m
// shards, which is the one property the receiver relies on: it never chooses
// which shards it is left with.
func TestFECEncodeRecover(t *testing.T) {
	for _, members := range []int{1, 2, 3, 4, 5, 6, 8} {
		for _, parity := range []int{1, 2, 3} {
			if members+parity > 10 {
				continue
			}
			for shardLen := 1; shardLen <= 9; shardLen += 4 {
				original, parityShards := fecTestShards(members, parity, shardLen, int64(members*100+parity*10+shardLen))
				err := fecEncode(original, parityShards)
				if err != nil {
					t.Fatalf("%d/%d: encode: %v", members, parity, err)
				}
				// Every subset of shards that loses at most parity shards has to
				// come back whole: losing one more is beyond what the code
				// promises, and losing none is the case that has to be free.
				for missing := 0; missing <= parity; missing++ {
					indexes := fecCombinations(members+parity, missing)
					for _, dropped := range indexes {
						shards := make([][]byte, 0, members+parity)
						shards = append(shards, original...)
						shards = append(shards, parityShards...)
						shards = slices.Clone(shards)
						for _, index := range dropped {
							shards[index] = nil
						}
						recoverErr := fecRecover(members, parity, shards)
						if recoverErr != nil {
							t.Fatalf("%d/%d/%d: recover after losing %v: %v", members, parity, shardLen, dropped, recoverErr)
						}
						for index, shard := range original {
							if !bytes.Equal(shards[index], shard) {
								t.Fatalf("%d/%d/%d: member %d came back changed after losing %v", members, parity, shardLen, index, dropped)
							}
						}
					}
				}
			}
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
	err := fecEncode(shards, parityShards)
	if err != nil {
		t.Fatal(err)
	}
	// Lose two members, which the two parity shards have to replace: four of the
	// six shards are left, which is exactly k.
	recovered := [][]byte{shards[0], nil, nil, shards[3], parityShards[0], parityShards[1]}
	err = fecRecover(len(members), 2, recovered)
	if err != nil {
		t.Fatal(err)
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
	shards := [][]byte{make([]byte, 4), make([]byte, 4), make([]byte, 4)}
	if err := fecEncode(nil, shards[:1]); err == nil {
		t.Fatal("a group of no members was encoded")
	}
	if err := fecEncode(shards, nil); err == nil {
		t.Fatal("a group of no parity shards was encoded")
	}
	uneven := [][]byte{make([]byte, 4), make([]byte, 5)}
	if err := fecEncode(uneven, shards[:1]); err == nil {
		t.Fatal("shards of different lengths were encoded")
	}
	// 300 shards do not fit in the two bytes that describe a group.
	tooMany := make([][]byte, 300)
	for index := range tooMany {
		tooMany[index] = make([]byte, 1)
	}
	if err := fecEncode(tooMany[:200], tooMany[200:]); err == nil {
		t.Fatal("a group of 300 shards was encoded")
	}
	// k of k+m is the minimum: one short and nothing is promised.
	full := [][]byte{make([]byte, 4), make([]byte, 4), make([]byte, 4)}
	if err := fecRecover(3, 1, full[:2]); err == nil {
		t.Fatal("a group without enough shards was recovered")
	}
	missing := [][]byte{make([]byte, 4), nil, nil}
	if err := fecRecover(3, 1, missing); err == nil {
		t.Fatal("a group without enough shards was recovered")
	}
	if err := fecRecover(2, 1, [][]byte{make([]byte, 4), make([]byte, 4)}); err == nil {
		t.Fatal("a group of the wrong number of shards was recovered")
	}
}

// fecCombinations returns every way of choosing size of count indexes, which is
// what lets a recovery test cover all the erasure patterns of a shape instead of
// a few that were thought of.
func fecCombinations(count, size int) [][]int {
	if size == 0 {
		return [][]int{nil}
	}
	if size > count {
		return nil
	}
	var combinations [][]int
	current := make([]int, size)
	for index := range current {
		current[index] = index
	}
	for {
		combination := make([]int, size)
		copy(combination, current)
		combinations = append(combinations, combination)
		position := size - 1
		for position >= 0 && current[position] == count-size+position {
			position--
		}
		if position < 0 {
			return combinations
		}
		current[position]++
		for index := position + 1; index < size; index++ {
			current[index] = current[index-1] + 1
		}
	}
}
