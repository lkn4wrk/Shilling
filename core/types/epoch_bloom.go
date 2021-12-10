// Copyright 2021 Zergity (zergity@gmail.com)

package types

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"math/bits"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	// EpochBloomM represents the number of hashes used in a epoch bloom.
	EpochBloomK = 8
)

var CollidedTopics = map[common.Hash]byte{
	common.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"): 3, // ERC20 Transfer
}

// EpochBloom represents a epoch bit bloom filter.
type EpochBloom []byte

type BloomDocument struct {
	First uint64 `bson:"_id"`
	Range int    `bson:"range"`
	Bits  []byte `bson:"bits"`
}

func NewBloom(blocks int, ratio int) EpochBloom {
	m := blocks * ratio * 2048
	return NewBloomWithM(m)
}

func NewBloomWithM(m int) EpochBloom {
	if m%8 != 0 {
		panic("invalid bloom m")
	}
	return make(EpochBloom, m/8)
}

// BytesToEpochBloom converts a byte slice to a bloom filter.
// It panics if b is not of suitable size.
func BytesToEpochBloom(b []byte) EpochBloom {
	bloom := make(EpochBloom, len(b))
	bloom.SetBytes(b)
	return bloom
}

// SetBytes sets the content of b to the given bytes.
// It panics if d is not of suitable size.
func (b EpochBloom) SetBytes(d []byte) {
	if len(b) != len(d) {
		panic(fmt.Sprintf("bloom bytes mismatches %d != %d", len(b), len(d)))
	}
	copy(b, d)
}

// Add adds d to the filter. Future calls of Test(d) will return true.
func (b EpochBloom) Add(d []byte) {
	var buf [4 * EpochBloomK]byte
	b.add(d, buf[:])
}

// require len(item) >= 1+32+1+32
// require len(buf) >= 4*k
func (log *Log) AddToBlooms(bs []EpochBloom, item []byte, buf []byte) error {
	if log.Removed {
		return nil // ignore removed log
	}
	n := byte(len(log.Topics))
	if n == 0 {
		return nil // ignore log with no topic
	}

	if mostPopular, collided := CollidedTopics[log.Topics[0]]; collided && n != mostPopular {
		item[0] = n
	} else {
		item[0] = 0
	}
	copy(item[1:], log.Topics[0].Bytes())

	for i := byte(1); i < n; i++ {
		// n + topic[0] + i + topic[i]
		item[33] = i
		copy(item[34:], log.Topics[i].Bytes())
		// TODO: optimize this to hash only once
		for _, b := range bs {
			b.add(item[:1+32+1+32], buf)
		}
	}
	// n + topic[0] + address
	copy(item[33:], log.Address.Bytes())
	// TODO: optimize this to hash only once
	for _, b := range bs {
		b.add(item[:1+32+20], buf)
	}
	return nil
}

// add is internal version of Add, which takes a scratch buffer for reuse (needs to be at least 4*k bytes)
func (b EpochBloom) add(d []byte, buf []byte) {
	m := uint32(len(b)) * 8
	ii, vv := bloomBigValues(m, d, buf)
	for i := 0; i < len(ii); i++ {
		b[ii[i]] |= vv[i]
	}
}

// Big converts b to a big integer.
// Note: Converting a bloom filter to a big.Int and then calling GetBytes
// does not return the same bytes, since big.Int will trim leading zeroes
func (b EpochBloom) Big() *big.Int {
	return new(big.Int).SetBytes(b[:])
}

// Bytes returns the backing byte slice of the bloom
func (b EpochBloom) Bytes() []byte {
	return b[:]
}

// Test checks if the given topic is present in the bloom filter
func (b EpochBloom) Test(topic []byte) bool {
	m := uint32(len(b)) * 8
	var buf [4 * EpochBloomK]byte
	ii, vv := bloomBigValues(m, topic, buf[:])
	for i := 0; i < len(ii); i++ {
		if vv[i] != vv[i]&b[ii[i]] {
			return false
		}
	}
	return true
}

// MarshalText encodes b as a hex string with 0x prefix.
func (b EpochBloom) MarshalText() ([]byte, error) {
	return hexutil.Bytes(b[:]).MarshalText()
}

// UnmarshalText b as a hex string with 0x prefix.
func (b EpochBloom) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedText("EpochBloom", input, b[:])
}

// EpochBloomBytes returns the bloom filter for the given data
func EpochBloomBytes(data []byte) []byte {
	var b EpochBloom
	b.SetBytes(data)
	return b.Bytes()
}

func bloomBigPositions(m uint32, data []byte, hashbuf []byte) (p [EpochBloomK]uint) {
	sha := hasherPool.Get().(crypto.KeccakState)
	sha.Reset()
	sha.Write(data)
	sha.Read(hashbuf)
	hasherPool.Put(sha)
	for i := 0; i < EpochBloomK; i++ {
		p[i] = uint(binary.BigEndian.Uint32(hashbuf[4*i:]) % m)
	}
	return p
}

// bloomBigValues returns the bytes (index-value pairs) to set for the given data
func bloomBigValues(m uint32, data []byte, buf []byte) (ii [EpochBloomK]uint, vv [EpochBloomK]byte) {
	p := bloomBigPositions(m, data, buf)
	for i := 0; i < len(p); i++ {
		vv[i] = byte(1 << (p[i] & 0x7))
		ii[i] = p[i] >> 3
	}
	return ii, vv
}

// EpochBloomLookup is a convenience-method to check presence int he bloom filter
func EpochBloomLookup(bin EpochBloom, topic bytesBacked) bool {
	return bin.Test(topic.Bytes())
}

func (b EpochBloom) Bits() (count int) {
	for _, v := range b {
		count += bits.OnesCount8(v)
	}
	return count
}

func (b EpochBloom) Rate() float64 {
	m := float64(len(b)) * 8
	bits := b.Bits()
	return math.Pow(float64(bits)/m, EpochBloomK)
}

func (b EpochBloom) Size() uint {
	m := float64(len(b)) * 8
	return uint(-m * math.Log(1-float64(b.Bits())/m) / EpochBloomK)
}
