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
	BloomBigK = 8

	// BloomBigByteLength represents the number of bytes used in a header log bloom.
	BloomBigByteLength = 256 * 4096 * 6

	// BloomBigBitLength represents the number of bits used in a header log bloom.
	BloomBigBitLength = BloomBigByteLength << 3
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
	var buf [4 * BloomBigK]byte
	b.add(d, buf[:])
}

// require len(item) >= 2+32+32
// require len(buf) >= 4*k
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
		b.add(item[:], buf)
	}
	// n + topic[0] + address
	copy(item[32:], log.Address.Bytes())
	b.add(item[:1+32+20], buf)
	return nil
}

// add is internal version of Add, which takes a scratch buffer for reuse (needs to be at least 4*k bytes)
func (b *BloomBig) add(d []byte, buf []byte) {
	ii, vv := bloomBigValues(d, buf)
	for i := 0; i < len(ii); i++ {
		b[ii[i]] |= vv[i]
	}
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
	var buf [4 * BloomBigK]byte
	ii, vv := bloomBigValues(topic, buf[:])
	for i := 0; i < len(ii); i++ {
		if vv[i] != vv[i]&b[ii[i]] {
			return false
		}
	}
	return true
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

func bloomBigPositions(data []byte, hashbuf []byte) (p [BloomBigK]uint) {
	sha := hasherPool.Get().(crypto.KeccakState)
	sha.Reset()
	sha.Write(data)
	sha.Read(hashbuf)
	hasherPool.Put(sha)
	for i := 0; i < BloomBigK; i++ {
		p[i] = uint(binary.BigEndian.Uint32(hashbuf[4*i:]) % BloomBigBitLength)
	}
	return p
}

// bloomBigValues returns the bytes (index-value pairs) to set for the given data
func bloomBigValues(data []byte, buf []byte) (ii [BloomBigK]uint, vv [BloomBigK]byte) {
	p := bloomBigPositions(data, buf)
	for i := 0; i < len(p); i++ {
		vv[i] = byte(1 << (p[i] & 0x7))
		ii[i] = p[i] >> 3
	}
	return ii, vv
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
	return math.Pow(float64(bits)/BloomBigBitLength, BloomBigK)
}
