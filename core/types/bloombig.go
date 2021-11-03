// Copyright 2021 Zergity (zergity@gmail.com)

package types

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"math/bits"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	// BloomBigByteLength represents the number of bytes used in a header log bloom.
	BloomBigByteLength = 256 * 4096 * 4

	// BloomBigBitLength represents the number of bits used in a header log bloom.
	BloomBigBitLength = 8 * BloomBigByteLength
)

var EmptyBloomBig = BloomBig{}

// BloomBig represents a 2048 bit bloom filter.
type BloomBig [BloomBigByteLength]byte

// BytesToBloomBig converts a byte slice to a bloom filter.
// It panics if b is not of suitable size.
func BytesToBloomBig(b []byte) BloomBig {
	var bloom BloomBig
	bloom.SetBytes(b)
	return bloom
}

// SetBytes sets the content of b to the given bytes.
// It panics if d is not of suitable size.
func (b *BloomBig) SetBytes(d []byte) {
	if len(b) < len(d) {
		panic(fmt.Sprintf("bloom bytes too big %d %d", len(b), len(d)))
	}
	copy(b[BloomBigByteLength-len(d):], d)
}

// Add adds d to the filter. Future calls of Test(d) will return true.
func (b *BloomBig) Add(d []byte) {
	b.add(d, make([]byte, 12))
}

// require len(item) >= 2+32+32
// require len(buf) >= 12
func (b *BloomBig) AddLog(log *Log, item []byte, buf []byte) error {
	if log.Removed {
		return nil // ignore removed log
	}
	n := byte(len(log.Topics))
	if n == 0 {
		return nil // ignore log with no topic
	}

	item[0] = n
	copy(item[1:], log.Topics[0].Bytes())

	for i := byte(1); i < n; i++ {
		// n + topic[0] + i + topic[i]
		item[32] = i
		copy(item[33:], log.Topics[i].Bytes())
		b.Add(item)
	}
	// n + topic[0] + address
	copy(item[32:], log.Address.Bytes())
	b.add(item[:1+32+20], buf)
	return nil
}

// add is internal version of Add, which takes a scratch buffer for reuse (needs to be at least 12 bytes)
func (b *BloomBig) add(d []byte, buf []byte) {
	i1, v1, i2, v2, i3, v3 := bloomBigValues(d, buf)
	b[i1] |= v1
	b[i2] |= v2
	b[i3] |= v3
}

// Big converts b to a big integer.
// Note: Converting a bloom filter to a big.Int and then calling GetBytes
// does not return the same bytes, since big.Int will trim leading zeroes
func (b BloomBig) Big() *big.Int {
	return new(big.Int).SetBytes(b[:])
}

// Bytes returns the backing byte slice of the bloom
func (b BloomBig) Bytes() []byte {
	return b[:]
}

// Test checks if the given topic is present in the bloom filter
func (b BloomBig) Test(topic []byte) bool {
	i1, v1, i2, v2, i3, v3 := bloomBigValues(topic, make([]byte, 12))
	return v1 == v1&b[i1] &&
		v2 == v2&b[i2] &&
		v3 == v3&b[i3]
}

// MarshalText encodes b as a hex string with 0x prefix.
func (b BloomBig) MarshalText() ([]byte, error) {
	return hexutil.Bytes(b[:]).MarshalText()
}

// UnmarshalText b as a hex string with 0x prefix.
func (b *BloomBig) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedText("BloomBig", input, b[:])
}

// BloomBigBytes returns the bloom filter for the given data
func BloomBigBytes(data []byte) []byte {
	var b BloomBig
	b.SetBytes(data)
	return b.Bytes()
}

func bloomBigPositions(data []byte, hashbuf []byte) (uint, uint, uint) {
	sha := hasherPool.Get().(crypto.KeccakState)
	sha.Reset()
	sha.Write(data)
	sha.Read(hashbuf)
	hasherPool.Put(sha)
	p1 := uint(binary.BigEndian.Uint32(hashbuf) % BloomBigBitLength)
	p2 := uint(binary.BigEndian.Uint32(hashbuf[4:]) % BloomBigBitLength)
	p3 := uint(binary.BigEndian.Uint32(hashbuf[8:]) % BloomBigBitLength)
	return p1, p2, p3
}

// bloomBigValues returns the bytes (index-value pairs) to set for the given data
func bloomBigValues(data []byte, hashbuf []byte) (uint, byte, uint, byte, uint, byte) {
	p1, p2, p3 := bloomBigPositions(data, hashbuf)

	v1 := byte(1 << (p1 & 0x7))
	v2 := byte(1 << (p2 & 0x7))
	v3 := byte(1 << (p3 & 0x7))

	i1 := p1 >> 3
	i2 := p2 >> 3
	i3 := p3 >> 3

	return i1, v1, i2, v2, i3, v3
}

// BloomBigLookup is a convenience-method to check presence int he bloom filter
func BloomBigLookup(bin BloomBig, topic bytesBacked) bool {
	return bin.Test(topic.Bytes())
}

func (b *BloomBig) OnesCount() (count int) {
	for _, v := range b {
		count += bits.OnesCount8(v)
	}
	return count
}

func (b *BloomBig) Rate() float64 {
	bits := b.OnesCount()
	return math.Pow(float64(bits)/BloomBigBitLength, 3)
}
