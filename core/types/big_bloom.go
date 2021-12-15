// Copyright 2021 Zergity (zergity@gmail.com)

package types

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	MaxK = 8
)

var CollidedTopics = map[common.Hash]byte{
	common.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"): 3, // ERC20 Transfer
}

// BigBloom represents a epoch bit bloom filter.
type BigBloom struct {
	k    int
	bits []byte

	pPos int // 32 bytes offset for partition selection
	kPos int // 32 bytes offset for the first hash
}

type BloomDocument struct {
	First uint64 `bson:"_id"`
	Range int    `bson:"range"`
	Bits  []byte `bson:"bits"`
}

func NewBloom(blocks int, ratio int) BigBloom {
	m := blocks * ratio * 2048
	return NewBloomWithM(m)
}

func NewBloomWithM(m int) BigBloom {
	if m%8 != 0 {
		panic("invalid bloom m")
	}
	return BigBloom{
		k:    8,
		bits: make([]byte, m/8),

		pPos: 0,
		kPos: 0,
	}
}

// BytesToEpochBloom converts a byte slice to a bloom filter.
// It panics if b is not of suitable size.
func BytesToEpochBloom(b []byte) BigBloom {
	m := len(b) * 8
	bloom := NewBloomWithM(m)
	bloom.SetBytes(b)
	return bloom
}

// SetBytes sets the content of b to the given bytes.
// It panics if d is not of suitable size.
func (b BigBloom) SetBytes(d []byte) {
	if len(b.bits) != len(d) {
		panic(fmt.Sprintf("bloom bytes mismatches %d != %d", len(b.bits), len(d)))
	}
	copy(b.bits, d)
}

// Add adds d to the filter. Future calls of Test(d) will return true.
func (b BigBloom) Add(d []byte) {
	var buf [4 * MaxK]byte
	b.add(d, buf[:])
}

// require len(item) >= 1+32+1+32
// require len(buf) >= 4*k
func (log *Log) AddToBlooms(bs []BigBloom, item []byte, buf []byte) error {
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

	// n + topic[0]
	copy(item[1:], log.Topics[0].Bytes())
	// TODO: optimize this to hash only once
	for _, b := range bs {
		b.add(item[:1+32], buf)
	}

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
func (b BigBloom) add(d []byte, buf []byte) {
	m := uint32(b.M())
	ii, vv := bloomBigValues(m, d, buf)
	for i := b.kPos; i < b.kPos+b.k; i++ {
		b.bits[ii[i]] |= vv[i]
	}
}

// Bytes returns the backing byte slice of the bloom
func (b BigBloom) Bytes() []byte {
	return b.bits[:]
}

// Test checks if the given topic is present in the bloom filter
func (b BigBloom) Test(topic []byte) bool {
	m := uint32(b.M())
	var buf [4 * MaxK]byte
	ii, vv := bloomBigValues(m, topic, buf[:])
	for i := b.kPos; i < b.kPos+b.k; i++ {
		if vv[i] != vv[i]&b.bits[ii[i]] {
			return false
		}
	}
	return true
}

// EpochBloomBytes returns the bloom filter for the given data
func EpochBloomBytes(data []byte) []byte {
	var b BigBloom
	b.SetBytes(data)
	return b.Bytes()
}

func bloomBigPositions(m uint32, data []byte, hashbuf []byte) (p [MaxK]uint) {
	sha := hasherPool.Get().(crypto.KeccakState)
	sha.Reset()
	sha.Write(data)
	sha.Read(hashbuf)
	hasherPool.Put(sha)
	for i := 0; i < MaxK; i++ {
		p[i] = uint(binary.BigEndian.Uint32(hashbuf[4*i:]) % m)
	}
	return p
}

// bloomBigValues returns the bytes (index-value pairs) to set for the given data
func bloomBigValues(m uint32, data []byte, buf []byte) (ii [MaxK]uint, vv [MaxK]byte) {
	p := bloomBigPositions(m, data, buf)
	for i := 0; i < len(p); i++ {
		vv[i] = byte(1 << (p[i] & 0x7))
		ii[i] = p[i] >> 3
	}
	return ii, vv
}

// EpochBloomLookup is a convenience-method to check presence int he bloom filter
func EpochBloomLookup(bin BigBloom, topic bytesBacked) bool {
	return bin.Test(topic.Bytes())
}

func (b BigBloom) Bits() (count int) {
	for _, v := range b.bits {
		count += bits.OnesCount8(v)
	}
	return count
}

func (b BigBloom) Rate() float64 {
	m := float64(b.M())
	bits := b.Bits()
	return math.Pow(float64(bits)/m, float64(b.k))
}

func (b BigBloom) Size() uint {
	m := float64(b.M())
	return uint(-m * math.Log(1-float64(b.Bits())/m) / float64(b.k))
}

func (b BigBloom) M() int {
	return len(b.bits) * 8
}
