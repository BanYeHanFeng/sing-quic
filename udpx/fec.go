package udpx

import (
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
			if coefficient == 1 {
				for offset, value := range members[column] {
					shard[offset] ^= value
				}
				continue
			}
			for offset, value := range members[column] {
				shard[offset] ^= gfMul(coefficient, value)
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
			for offset, value := range shards[known[row]] {
				shard[offset] ^= gfMul(coefficient, value)
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
