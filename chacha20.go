/*
Package chacha20 provides a pure Go implementation of ChaCha20, a fast, secure
stream cipher.

From DJB's paper:

	ChaCha8 is a 256-bit stream cipher based on the 8-round cipher Salsa20/8.
	The changes from Salsa20/8 to ChaCha8 are designed to improve diffusion per
	round, conjecturally increasing resistance to cryptanalysis, while
	preserving—and often improving—time per round. ChaCha12 and ChaCha20 are
	analogous modiﬁcations of the 12-round and 20-round ciphers Salsa20/12 and
	Salsa20/20. This paper presents the ChaCha family and explains the
	differences between Salsa20 and ChaCha.

(from http://cr.yp.to/chacha/chacha-20080128.pdf)

For more information, see http://cr.yp.to/chacha.html
*/
package chacha20

import (
	"encoding/binary"
	"errors"
)

const (
	// KeySize is the length of ChaCha20 keys, in bytes.
	KeySize = 32

	// NonceSize is the length of ChaCha20 nonces, in bytes.
	NonceSize = 8

	size  = 16       // the size of the state, in words
	block = size * 4 // the size of the block, in bytes
)

var (
	// ErrInvalidKey is returned when the provided key is not 256 bits long.
	ErrInvalidKey = errors.New("chacha20: Invalid key length (must be 256 bits)")
	// ErrInvalidNonce is returned when the provided nonce is not 64 bits long.
	ErrInvalidNonce = errors.New("chacha20: Invalid nonce length (must be 64 bits)")
	// the magic constants for 256-bit keys
	constants = []uint32{1634760805, 857760878, 2036477234, 1797285236}
)

// A Cipher is an instance of ChaCha20 using a particular key and nonce.
type Cipher struct {
	input, output *[size]uint32
	count         int
}

// NewCipher creates and returns a new Cipher.  The key argument must be 256
// bits long, and the nonce argument must be 64 bits long. The nonce must be
// randomly generated or used only once. This Cipher instance must not be used
// to encrypt more than 2^70 bytes (~1 zettabyte).
func NewCipher(key []byte, nonce []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}

	if len(nonce) != NonceSize {
		return nil, ErrInvalidNonce
	}

	c := new(Cipher)
	c.input = new([size]uint32)
	c.output = new([size]uint32)

	c.input[0] = constants[0]
	c.input[1] = constants[1]
	c.input[2] = constants[2]
	c.input[3] = constants[3]

	c.input[4] = binary.LittleEndian.Uint32(key[0:])
	c.input[5] = binary.LittleEndian.Uint32(key[4:])
	c.input[6] = binary.LittleEndian.Uint32(key[8:])
	c.input[7] = binary.LittleEndian.Uint32(key[12:])
	c.input[8] = binary.LittleEndian.Uint32(key[16:])
	c.input[9] = binary.LittleEndian.Uint32(key[20:])
	c.input[10] = binary.LittleEndian.Uint32(key[24:])
	c.input[11] = binary.LittleEndian.Uint32(key[28:])

	c.input[12] = 0
	c.input[13] = 0
	c.input[14] = binary.LittleEndian.Uint32(nonce[0:])
	c.input[15] = binary.LittleEndian.Uint32(nonce[4:])

	c.advance()

	return c, nil
}

// XORKeyStream sets dst to the result of XORing src with the key stream.
// Dst and src may be the same slice but otherwise should not overlap. You
// should not encrypt more than 2^70 bytes (~1 zettabyte) without re-keying and
// using a new nonce.
func (c *Cipher) XORKeyStream(dst, src []byte) {
	i := 0
	for i < len(src) {
		if c.count == 0 {
			c.advance()
		}

		offset := block - c.count
		k := c.output[offset>>2] >> uint((offset&3)<<3)
		dst[i] = src[i] ^ byte(k)
		i++
		c.count--
	}
}

// Reset zeros the key data so that it will no longer appear in the process's
// memory.
func (c *Cipher) Reset() {
	for i := 0; i < size; i++ {
		c.input[i] = 0
		c.output[i] = 0
	}
	c.count = 0
}

// advances the keystream
func (c *Cipher) advance() {
	core(c.input, c.output)
	c.count = block
	c.input[12]++
	if c.input[12] == 0 {
		c.input[13]++
	}
}

// the core ChaCha20 transform
func core(input, output *[size]uint32) {
	var (
		x00 = input[0]
		x01 = input[1]
		x02 = input[2]
		x03 = input[3]
		x04 = input[4]
		x05 = input[5]
		x06 = input[6]
		x07 = input[7]
		x08 = input[8]
		x09 = input[9]
		x10 = input[10]
		x11 = input[11]
		x12 = input[12]
		x13 = input[13]
		x14 = input[14]
		x15 = input[15]
	)

	// unrolled and expanded for great fun
	var x uint32

	// Rounds 1 and 2
	x00 += x04
	x = x12 ^ x00
	x12 = (x << 16) | (x >> 16)
	x08 += x12
	x = x04 ^ x08
	x04 = (x << 12) | (x >> 20)
	x00 += x04
	x = x12 ^ x00
	x12 = (x << 8) | (x >> 24)
	x08 += x12
	x = x04 ^ x08
	x04 = (x << 7) | (x >> 25)
	x01 += x05
	x = x13 ^ x01
	x13 = (x << 16) | (x >> 16)
	x09 += x13
	x = x05 ^ x09
	x05 = (x << 12) | (x >> 20)
	x01 += x05
	x = x13 ^ x01
	x13 = (x << 8) | (x >> 24)
	x09 += x13
	x = x05 ^ x09
	x05 = (x << 7) | (x >> 25)
	x02 += x06
	x = x14 ^ x02
	x14 = (x << 16) | (x >> 16)
	x10 += x14
	x = x06 ^ x10
	x06 = (x << 12) | (x >> 20)
	x02 += x06
	x = x14 ^ x02
	x14 = (x << 8) | (x >> 24)
	x10 += x14
	x = x06 ^ x10
	x06 = (x << 7) | (x >> 25)
	x03 += x07
	x = x15 ^ x03
	x15 = (x << 16) | (x >> 16)
	x11 += x15
	x = x07 ^ x11
	x07 = (x << 12) | (x >> 20)
	x03 += x07
	x = x15 ^ x03
	x15 = (x << 8) | (x >> 24)
	x11 += x15
	x = x07 ^ x11
	x07 = (x << 7) | (x >> 25)
	x00 += x05
	x = x15 ^ x00
	x15 = (x << 16) | (x >> 16)
	x10 += x15
	x = x05 ^ x10
	x05 = (x << 12) | (x >> 20)
	x00 += x05
	x = x15 ^ x00
	x15 = (x << 8) | (x >> 24)
	x10 += x15
	x = x05 ^ x10
	x05 = (x << 7) | (x >> 25)
	x01 += x06
	x = x12 ^ x01
	x12 = (x << 16) | (x >> 16)
	x11 += x12
	x = x06 ^ x11
	x06 = (x << 12) | (x >> 20)
	x01 += x06
	x = x12 ^ x01
	x12 = (x << 8) | (x >> 24)
	x11 += x12
	x = x06 ^ x11
	x06 = (x << 7) | (x >> 25)
	x02 += x07
	x = x13 ^ x02
	x13 = (x << 16) | (x >> 16)
	x08 += x13
	x = x07 ^ x08
	x07 = (x << 12) | (x >> 20)
	x02 += x07
	x = x13 ^ x02
	x13 = (x << 8) | (x >> 24)
	x08 += x13
	x = x07 ^ x08
	x07 = (x << 7) | (x >> 25)
	x03 += x04
	x = x14 ^ x03
	x14 = (x << 16) | (x >> 16)
	x09 += x14
	x = x04 ^ x09
	x04 = (x << 12) | (x >> 20)
	x03 += x04
	x = x14 ^ x03
	x14 = (x << 8) | (x >> 24)
	x09 += x14
	x = x04 ^ x09
	x04 = (x << 7) | (x >> 25)

	// Rounds 3 and 4
	x00 += x04
	x = x12 ^ x00
	x12 = (x << 16) | (x >> 16)
	x08 += x12
	x = x04 ^ x08
	x04 = (x << 12) | (x >> 20)
	x00 += x04
	x = x12 ^ x00
	x12 = (x << 8) | (x >> 24)
	x08 += x12
	x = x04 ^ x08
	x04 = (x << 7) | (x >> 25)
	x01 += x05
	x = x13 ^ x01
	x13 = (x << 16) | (x >> 16)
	x09 += x13
	x = x05 ^ x09
	x05 = (x << 12) | (x >> 20)
	x01 += x05
	x = x13 ^ x01
	x13 = (x << 8) | (x >> 24)
	x09 += x13
	x = x05 ^ x09
	x05 = (x << 7) | (x >> 25)
	x02 += x06
	x = x14 ^ x02
	x14 = (x << 16) | (x >> 16)
	x10 += x14
	x = x06 ^ x10
	x06 = (x << 12) | (x >> 20)
	x02 += x06
	x = x14 ^ x02
	x14 = (x << 8) | (x >> 24)
	x10 += x14
	x = x06 ^ x10
	x06 = (x << 7) | (x >> 25)
	x03 += x07
	x = x15 ^ x03
	x15 = (x << 16) | (x >> 16)
	x11 += x15
	x = x07 ^ x11
	x07 = (x << 12) | (x >> 20)
	x03 += x07
	x = x15 ^ x03
	x15 = (x << 8) | (x >> 24)
	x11 += x15
	x = x07 ^ x11
	x07 = (x << 7) | (x >> 25)
	x00 += x05
	x = x15 ^ x00
	x15 = (x << 16) | (x >> 16)
	x10 += x15
	x = x05 ^ x10
	x05 = (x << 12) | (x >> 20)
	x00 += x05
	x = x15 ^ x00
	x15 = (x << 8) | (x >> 24)
	x10 += x15
	x = x05 ^ x10
	x05 = (x << 7) | (x >> 25)
	x01 += x06
	x = x12 ^ x01
	x12 = (x << 16) | (x >> 16)
	x11 += x12
	x = x06 ^ x11
	x06 = (x << 12) | (x >> 20)
	x01 += x06
	x = x12 ^ x01
	x12 = (x << 8) | (x >> 24)
	x11 += x12
	x = x06 ^ x11
	x06 = (x << 7) | (x >> 25)
	x02 += x07
	x = x13 ^ x02
	x13 = (x << 16) | (x >> 16)
	x08 += x13
	x = x07 ^ x08
	x07 = (x << 12) | (x >> 20)
	x02 += x07
	x = x13 ^ x02
	x13 = (x << 8) | (x >> 24)
	x08 += x13
	x = x07 ^ x08
	x07 = (x << 7) | (x >> 25)
	x03 += x04
	x = x14 ^ x03
	x14 = (x << 16) | (x >> 16)
	x09 += x14
	x = x04 ^ x09
	x04 = (x << 12) | (x >> 20)
	x03 += x04
	x = x14 ^ x03
	x14 = (x << 8) | (x >> 24)
	x09 += x14
	x = x04 ^ x09
	x04 = (x << 7) | (x >> 25)

	// Rounds 5 and 6
	x00 += x04
	x = x12 ^ x00
	x12 = (x << 16) | (x >> 16)
	x08 += x12
	x = x04 ^ x08
	x04 = (x << 12) | (x >> 20)
	x00 += x04
	x = x12 ^ x00
	x12 = (x << 8) | (x >> 24)
	x08 += x12
	x = x04 ^ x08
	x04 = (x << 7) | (x >> 25)
	x01 += x05
	x = x13 ^ x01
	x13 = (x << 16) | (x >> 16)
	x09 += x13
	x = x05 ^ x09
	x05 = (x << 12) | (x >> 20)
	x01 += x05
	x = x13 ^ x01
	x13 = (x << 8) | (x >> 24)
	x09 += x13
	x = x05 ^ x09
	x05 = (x << 7) | (x >> 25)
	x02 += x06
	x = x14 ^ x02
	x14 = (x << 16) | (x >> 16)
	x10 += x14
	x = x06 ^ x10
	x06 = (x << 12) | (x >> 20)
	x02 += x06
	x = x14 ^ x02
	x14 = (x << 8) | (x >> 24)
	x10 += x14
	x = x06 ^ x10
	x06 = (x << 7) | (x >> 25)
	x03 += x07
	x = x15 ^ x03
	x15 = (x << 16) | (x >> 16)
	x11 += x15
	x = x07 ^ x11
	x07 = (x << 12) | (x >> 20)
	x03 += x07
	x = x15 ^ x03
	x15 = (x << 8) | (x >> 24)
	x11 += x15
	x = x07 ^ x11
	x07 = (x << 7) | (x >> 25)
	x00 += x05
	x = x15 ^ x00
	x15 = (x << 16) | (x >> 16)
	x10 += x15
	x = x05 ^ x10
	x05 = (x << 12) | (x >> 20)
	x00 += x05
	x = x15 ^ x00
	x15 = (x << 8) | (x >> 24)
	x10 += x15
	x = x05 ^ x10
	x05 = (x << 7) | (x >> 25)
	x01 += x06
	x = x12 ^ x01
	x12 = (x << 16) | (x >> 16)
	x11 += x12
	x = x06 ^ x11
	x06 = (x << 12) | (x >> 20)
	x01 += x06
	x = x12 ^ x01
	x12 = (x << 8) | (x >> 24)
	x11 += x12
	x = x06 ^ x11
	x06 = (x << 7) | (x >> 25)
	x02 += x07
	x = x13 ^ x02
	x13 = (x << 16) | (x >> 16)
	x08 += x13
	x = x07 ^ x08
	x07 = (x << 12) | (x >> 20)
	x02 += x07
	x = x13 ^ x02
	x13 = (x << 8) | (x >> 24)
	x08 += x13
	x = x07 ^ x08
	x07 = (x << 7) | (x >> 25)
	x03 += x04
	x = x14 ^ x03
	x14 = (x << 16) | (x >> 16)
	x09 += x14
	x = x04 ^ x09
	x04 = (x << 12) | (x >> 20)
	x03 += x04
	x = x14 ^ x03
	x14 = (x << 8) | (x >> 24)
	x09 += x14
	x = x04 ^ x09
	x04 = (x << 7) | (x >> 25)

	// Rounds 7 and 8
	x00 += x04
	x = x12 ^ x00
	x12 = (x << 16) | (x >> 16)
	x08 += x12
	x = x04 ^ x08
	x04 = (x << 12) | (x >> 20)
	x00 += x04
	x = x12 ^ x00
	x12 = (x << 8) | (x >> 24)
	x08 += x12
	x = x04 ^ x08
	x04 = (x << 7) | (x >> 25)
	x01 += x05
	x = x13 ^ x01
	x13 = (x << 16) | (x >> 16)
	x09 += x13
	x = x05 ^ x09
	x05 = (x << 12) | (x >> 20)
	x01 += x05
	x = x13 ^ x01
	x13 = (x << 8) | (x >> 24)
	x09 += x13
	x = x05 ^ x09
	x05 = (x << 7) | (x >> 25)
	x02 += x06
	x = x14 ^ x02
	x14 = (x << 16) | (x >> 16)
	x10 += x14
	x = x06 ^ x10
	x06 = (x << 12) | (x >> 20)
	x02 += x06
	x = x14 ^ x02
	x14 = (x << 8) | (x >> 24)
	x10 += x14
	x = x06 ^ x10
	x06 = (x << 7) | (x >> 25)
	x03 += x07
	x = x15 ^ x03
	x15 = (x << 16) | (x >> 16)
	x11 += x15
	x = x07 ^ x11
	x07 = (x << 12) | (x >> 20)
	x03 += x07
	x = x15 ^ x03
	x15 = (x << 8) | (x >> 24)
	x11 += x15
	x = x07 ^ x11
	x07 = (x << 7) | (x >> 25)
	x00 += x05
	x = x15 ^ x00
	x15 = (x << 16) | (x >> 16)
	x10 += x15
	x = x05 ^ x10
	x05 = (x << 12) | (x >> 20)
	x00 += x05
	x = x15 ^ x00
	x15 = (x << 8) | (x >> 24)
	x10 += x15
	x = x05 ^ x10
	x05 = (x << 7) | (x >> 25)
	x01 += x06
	x = x12 ^ x01
	x12 = (x << 16) | (x >> 16)
	x11 += x12
	x = x06 ^ x11
	x06 = (x << 12) | (x >> 20)
	x01 += x06
	x = x12 ^ x01
	x12 = (x << 8) | (x >> 24)
	x11 += x12
	x = x06 ^ x11
	x06 = (x << 7) | (x >> 25)
	x02 += x07
	x = x13 ^ x02
	x13 = (x << 16) | (x >> 16)
	x08 += x13
	x = x07 ^ x08
	x07 = (x << 12) | (x >> 20)
	x02 += x07
	x = x13 ^ x02
	x13 = (x << 8) | (x >> 24)
	x08 += x13
	x = x07 ^ x08
	x07 = (x << 7) | (x >> 25)
	x03 += x04
	x = x14 ^ x03
	x14 = (x << 16) | (x >> 16)
	x09 += x14
	x = x04 ^ x09
	x04 = (x << 12) | (x >> 20)
	x03 += x04
	x = x14 ^ x03
	x14 = (x << 8) | (x >> 24)
	x09 += x14
	x = x04 ^ x09
	x04 = (x << 7) | (x >> 25)

	// Rounds 9 and 10
	x00 += x04
	x = x12 ^ x00
	x12 = (x << 16) | (x >> 16)
	x08 += x12
	x = x04 ^ x08
	x04 = (x << 12) | (x >> 20)
	x00 += x04
	x = x12 ^ x00
	x12 = (x << 8) | (x >> 24)
	x08 += x12
	x = x04 ^ x08
	x04 = (x << 7) | (x >> 25)
	x01 += x05
	x = x13 ^ x01
	x13 = (x << 16) | (x >> 16)
	x09 += x13
	x = x05 ^ x09
	x05 = (x << 12) | (x >> 20)
	x01 += x05
	x = x13 ^ x01
	x13 = (x << 8) | (x >> 24)
	x09 += x13
	x = x05 ^ x09
	x05 = (x << 7) | (x >> 25)
	x02 += x06
	x = x14 ^ x02
	x14 = (x << 16) | (x >> 16)
	x10 += x14
	x = x06 ^ x10
	x06 = (x << 12) | (x >> 20)
	x02 += x06
	x = x14 ^ x02
	x14 = (x << 8) | (x >> 24)
	x10 += x14
	x = x06 ^ x10
	x06 = (x << 7) | (x >> 25)
	x03 += x07
	x = x15 ^ x03
	x15 = (x << 16) | (x >> 16)
	x11 += x15
	x = x07 ^ x11
	x07 = (x << 12) | (x >> 20)
	x03 += x07
	x = x15 ^ x03
	x15 = (x << 8) | (x >> 24)
	x11 += x15
	x = x07 ^ x11
	x07 = (x << 7) | (x >> 25)
	x00 += x05
	x = x15 ^ x00
	x15 = (x << 16) | (x >> 16)
	x10 += x15
	x = x05 ^ x10
	x05 = (x << 12) | (x >> 20)
	x00 += x05
	x = x15 ^ x00
	x15 = (x << 8) | (x >> 24)
	x10 += x15
	x = x05 ^ x10
	x05 = (x << 7) | (x >> 25)
	x01 += x06
	x = x12 ^ x01
	x12 = (x << 16) | (x >> 16)
	x11 += x12
	x = x06 ^ x11
	x06 = (x << 12) | (x >> 20)
	x01 += x06
	x = x12 ^ x01
	x12 = (x << 8) | (x >> 24)
	x11 += x12
	x = x06 ^ x11
	x06 = (x << 7) | (x >> 25)
	x02 += x07
	x = x13 ^ x02
	x13 = (x << 16) | (x >> 16)
	x08 += x13
	x = x07 ^ x08
	x07 = (x << 12) | (x >> 20)
	x02 += x07
	x = x13 ^ x02
	x13 = (x << 8) | (x >> 24)
	x08 += x13
	x = x07 ^ x08
	x07 = (x << 7) | (x >> 25)
	x03 += x04
	x = x14 ^ x03
	x14 = (x << 16) | (x >> 16)
	x09 += x14
	x = x04 ^ x09
	x04 = (x << 12) | (x >> 20)
	x03 += x04
	x = x14 ^ x03
	x14 = (x << 8) | (x >> 24)
	x09 += x14
	x = x04 ^ x09
	x04 = (x << 7) | (x >> 25)

	// Rounds 11 and 12
	x00 += x04
	x = x12 ^ x00
	x12 = (x << 16) | (x >> 16)
	x08 += x12
	x = x04 ^ x08
	x04 = (x << 12) | (x >> 20)
	x00 += x04
	x = x12 ^ x00
	x12 = (x << 8) | (x >> 24)
	x08 += x12
	x = x04 ^ x08
	x04 = (x << 7) | (x >> 25)
	x01 += x05
	x = x13 ^ x01
	x13 = (x << 16) | (x >> 16)
	x09 += x13
	x = x05 ^ x09
	x05 = (x << 12) | (x >> 20)
	x01 += x05
	x = x13 ^ x01
	x13 = (x << 8) | (x >> 24)
	x09 += x13
	x = x05 ^ x09
	x05 = (x << 7) | (x >> 25)
	x02 += x06
	x = x14 ^ x02
	x14 = (x << 16) | (x >> 16)
	x10 += x14
	x = x06 ^ x10
	x06 = (x << 12) | (x >> 20)
	x02 += x06
	x = x14 ^ x02
	x14 = (x << 8) | (x >> 24)
	x10 += x14
	x = x06 ^ x10
	x06 = (x << 7) | (x >> 25)
	x03 += x07
	x = x15 ^ x03
	x15 = (x << 16) | (x >> 16)
	x11 += x15
	x = x07 ^ x11
	x07 = (x << 12) | (x >> 20)
	x03 += x07
	x = x15 ^ x03
	x15 = (x << 8) | (x >> 24)
	x11 += x15
	x = x07 ^ x11
	x07 = (x << 7) | (x >> 25)
	x00 += x05
	x = x15 ^ x00
	x15 = (x << 16) | (x >> 16)
	x10 += x15
	x = x05 ^ x10
	x05 = (x << 12) | (x >> 20)
	x00 += x05
	x = x15 ^ x00
	x15 = (x << 8) | (x >> 24)
	x10 += x15
	x = x05 ^ x10
	x05 = (x << 7) | (x >> 25)
	x01 += x06
	x = x12 ^ x01
	x12 = (x << 16) | (x >> 16)
	x11 += x12
	x = x06 ^ x11
	x06 = (x << 12) | (x >> 20)
	x01 += x06
	x = x12 ^ x01
	x12 = (x << 8) | (x >> 24)
	x11 += x12
	x = x06 ^ x11
	x06 = (x << 7) | (x >> 25)
	x02 += x07
	x = x13 ^ x02
	x13 = (x << 16) | (x >> 16)
	x08 += x13
	x = x07 ^ x08
	x07 = (x << 12) | (x >> 20)
	x02 += x07
	x = x13 ^ x02
	x13 = (x << 8) | (x >> 24)
	x08 += x13
	x = x07 ^ x08
	x07 = (x << 7) | (x >> 25)
	x03 += x04
	x = x14 ^ x03
	x14 = (x << 16) | (x >> 16)
	x09 += x14
	x = x04 ^ x09
	x04 = (x << 12) | (x >> 20)
	x03 += x04
	x = x14 ^ x03
	x14 = (x << 8) | (x >> 24)
	x09 += x14
	x = x04 ^ x09
	x04 = (x << 7) | (x >> 25)

	// Rounds 13 and 14
	x00 += x04
	x = x12 ^ x00
	x12 = (x << 16) | (x >> 16)
	x08 += x12
	x = x04 ^ x08
	x04 = (x << 12) | (x >> 20)
	x00 += x04
	x = x12 ^ x00
	x12 = (x << 8) | (x >> 24)
	x08 += x12
	x = x04 ^ x08
	x04 = (x << 7) | (x >> 25)
	x01 += x05
	x = x13 ^ x01
	x13 = (x << 16) | (x >> 16)
	x09 += x13
	x = x05 ^ x09
	x05 = (x << 12) | (x >> 20)
	x01 += x05
	x = x13 ^ x01
	x13 = (x << 8) | (x >> 24)
	x09 += x13
	x = x05 ^ x09
	x05 = (x << 7) | (x >> 25)
	x02 += x06
	x = x14 ^ x02
	x14 = (x << 16) | (x >> 16)
	x10 += x14
	x = x06 ^ x10
	x06 = (x << 12) | (x >> 20)
	x02 += x06
	x = x14 ^ x02
	x14 = (x << 8) | (x >> 24)
	x10 += x14
	x = x06 ^ x10
	x06 = (x << 7) | (x >> 25)
	x03 += x07
	x = x15 ^ x03
	x15 = (x << 16) | (x >> 16)
	x11 += x15
	x = x07 ^ x11
	x07 = (x << 12) | (x >> 20)
	x03 += x07
	x = x15 ^ x03
	x15 = (x << 8) | (x >> 24)
	x11 += x15
	x = x07 ^ x11
	x07 = (x << 7) | (x >> 25)
	x00 += x05
	x = x15 ^ x00
	x15 = (x << 16) | (x >> 16)
	x10 += x15
	x = x05 ^ x10
	x05 = (x << 12) | (x >> 20)
	x00 += x05
	x = x15 ^ x00
	x15 = (x << 8) | (x >> 24)
	x10 += x15
	x = x05 ^ x10
	x05 = (x << 7) | (x >> 25)
	x01 += x06
	x = x12 ^ x01
	x12 = (x << 16) | (x >> 16)
	x11 += x12
	x = x06 ^ x11
	x06 = (x << 12) | (x >> 20)
	x01 += x06
	x = x12 ^ x01
	x12 = (x << 8) | (x >> 24)
	x11 += x12
	x = x06 ^ x11
	x06 = (x << 7) | (x >> 25)
	x02 += x07
	x = x13 ^ x02
	x13 = (x << 16) | (x >> 16)
	x08 += x13
	x = x07 ^ x08
	x07 = (x << 12) | (x >> 20)
	x02 += x07
	x = x13 ^ x02
	x13 = (x << 8) | (x >> 24)
	x08 += x13
	x = x07 ^ x08
	x07 = (x << 7) | (x >> 25)
	x03 += x04
	x = x14 ^ x03
	x14 = (x << 16) | (x >> 16)
	x09 += x14
	x = x04 ^ x09
	x04 = (x << 12) | (x >> 20)
	x03 += x04
	x = x14 ^ x03
	x14 = (x << 8) | (x >> 24)
	x09 += x14
	x = x04 ^ x09
	x04 = (x << 7) | (x >> 25)

	// Rounds 15 and 16
	x00 += x04
	x = x12 ^ x00
	x12 = (x << 16) | (x >> 16)
	x08 += x12
	x = x04 ^ x08
	x04 = (x << 12) | (x >> 20)
	x00 += x04
	x = x12 ^ x00
	x12 = (x << 8) | (x >> 24)
	x08 += x12
	x = x04 ^ x08
	x04 = (x << 7) | (x >> 25)
	x01 += x05
	x = x13 ^ x01
	x13 = (x << 16) | (x >> 16)
	x09 += x13
	x = x05 ^ x09
	x05 = (x << 12) | (x >> 20)
	x01 += x05
	x = x13 ^ x01
	x13 = (x << 8) | (x >> 24)
	x09 += x13
	x = x05 ^ x09
	x05 = (x << 7) | (x >> 25)
	x02 += x06
	x = x14 ^ x02
	x14 = (x << 16) | (x >> 16)
	x10 += x14
	x = x06 ^ x10
	x06 = (x << 12) | (x >> 20)
	x02 += x06
	x = x14 ^ x02
	x14 = (x << 8) | (x >> 24)
	x10 += x14
	x = x06 ^ x10
	x06 = (x << 7) | (x >> 25)
	x03 += x07
	x = x15 ^ x03
	x15 = (x << 16) | (x >> 16)
	x11 += x15
	x = x07 ^ x11
	x07 = (x << 12) | (x >> 20)
	x03 += x07
	x = x15 ^ x03
	x15 = (x << 8) | (x >> 24)
	x11 += x15
	x = x07 ^ x11
	x07 = (x << 7) | (x >> 25)
	x00 += x05
	x = x15 ^ x00
	x15 = (x << 16) | (x >> 16)
	x10 += x15
	x = x05 ^ x10
	x05 = (x << 12) | (x >> 20)
	x00 += x05
	x = x15 ^ x00
	x15 = (x << 8) | (x >> 24)
	x10 += x15
	x = x05 ^ x10
	x05 = (x << 7) | (x >> 25)
	x01 += x06
	x = x12 ^ x01
	x12 = (x << 16) | (x >> 16)
	x11 += x12
	x = x06 ^ x11
	x06 = (x << 12) | (x >> 20)
	x01 += x06
	x = x12 ^ x01
	x12 = (x << 8) | (x >> 24)
	x11 += x12
	x = x06 ^ x11
	x06 = (x << 7) | (x >> 25)
	x02 += x07
	x = x13 ^ x02
	x13 = (x << 16) | (x >> 16)
	x08 += x13
	x = x07 ^ x08
	x07 = (x << 12) | (x >> 20)
	x02 += x07
	x = x13 ^ x02
	x13 = (x << 8) | (x >> 24)
	x08 += x13
	x = x07 ^ x08
	x07 = (x << 7) | (x >> 25)
	x03 += x04
	x = x14 ^ x03
	x14 = (x << 16) | (x >> 16)
	x09 += x14
	x = x04 ^ x09
	x04 = (x << 12) | (x >> 20)
	x03 += x04
	x = x14 ^ x03
	x14 = (x << 8) | (x >> 24)
	x09 += x14
	x = x04 ^ x09
	x04 = (x << 7) | (x >> 25)

	// Rounds 17 and 18
	x00 += x04
	x = x12 ^ x00
	x12 = (x << 16) | (x >> 16)
	x08 += x12
	x = x04 ^ x08
	x04 = (x << 12) | (x >> 20)
	x00 += x04
	x = x12 ^ x00
	x12 = (x << 8) | (x >> 24)
	x08 += x12
	x = x04 ^ x08
	x04 = (x << 7) | (x >> 25)
	x01 += x05
	x = x13 ^ x01
	x13 = (x << 16) | (x >> 16)
	x09 += x13
	x = x05 ^ x09
	x05 = (x << 12) | (x >> 20)
	x01 += x05
	x = x13 ^ x01
	x13 = (x << 8) | (x >> 24)
	x09 += x13
	x = x05 ^ x09
	x05 = (x << 7) | (x >> 25)
	x02 += x06
	x = x14 ^ x02
	x14 = (x << 16) | (x >> 16)
	x10 += x14
	x = x06 ^ x10
	x06 = (x << 12) | (x >> 20)
	x02 += x06
	x = x14 ^ x02
	x14 = (x << 8) | (x >> 24)
	x10 += x14
	x = x06 ^ x10
	x06 = (x << 7) | (x >> 25)
	x03 += x07
	x = x15 ^ x03
	x15 = (x << 16) | (x >> 16)
	x11 += x15
	x = x07 ^ x11
	x07 = (x << 12) | (x >> 20)
	x03 += x07
	x = x15 ^ x03
	x15 = (x << 8) | (x >> 24)
	x11 += x15
	x = x07 ^ x11
	x07 = (x << 7) | (x >> 25)
	x00 += x05
	x = x15 ^ x00
	x15 = (x << 16) | (x >> 16)
	x10 += x15
	x = x05 ^ x10
	x05 = (x << 12) | (x >> 20)
	x00 += x05
	x = x15 ^ x00
	x15 = (x << 8) | (x >> 24)
	x10 += x15
	x = x05 ^ x10
	x05 = (x << 7) | (x >> 25)
	x01 += x06
	x = x12 ^ x01
	x12 = (x << 16) | (x >> 16)
	x11 += x12
	x = x06 ^ x11
	x06 = (x << 12) | (x >> 20)
	x01 += x06
	x = x12 ^ x01
	x12 = (x << 8) | (x >> 24)
	x11 += x12
	x = x06 ^ x11
	x06 = (x << 7) | (x >> 25)
	x02 += x07
	x = x13 ^ x02
	x13 = (x << 16) | (x >> 16)
	x08 += x13
	x = x07 ^ x08
	x07 = (x << 12) | (x >> 20)
	x02 += x07
	x = x13 ^ x02
	x13 = (x << 8) | (x >> 24)
	x08 += x13
	x = x07 ^ x08
	x07 = (x << 7) | (x >> 25)
	x03 += x04
	x = x14 ^ x03
	x14 = (x << 16) | (x >> 16)
	x09 += x14
	x = x04 ^ x09
	x04 = (x << 12) | (x >> 20)
	x03 += x04
	x = x14 ^ x03
	x14 = (x << 8) | (x >> 24)
	x09 += x14
	x = x04 ^ x09
	x04 = (x << 7) | (x >> 25)

	// Rounds 19 and 20
	x00 += x04
	x = x12 ^ x00
	x12 = (x << 16) | (x >> 16)
	x08 += x12
	x = x04 ^ x08
	x04 = (x << 12) | (x >> 20)
	x00 += x04
	x = x12 ^ x00
	x12 = (x << 8) | (x >> 24)
	x08 += x12
	x = x04 ^ x08
	x04 = (x << 7) | (x >> 25)
	x01 += x05
	x = x13 ^ x01
	x13 = (x << 16) | (x >> 16)
	x09 += x13
	x = x05 ^ x09
	x05 = (x << 12) | (x >> 20)
	x01 += x05
	x = x13 ^ x01
	x13 = (x << 8) | (x >> 24)
	x09 += x13
	x = x05 ^ x09
	x05 = (x << 7) | (x >> 25)
	x02 += x06
	x = x14 ^ x02
	x14 = (x << 16) | (x >> 16)
	x10 += x14
	x = x06 ^ x10
	x06 = (x << 12) | (x >> 20)
	x02 += x06
	x = x14 ^ x02
	x14 = (x << 8) | (x >> 24)
	x10 += x14
	x = x06 ^ x10
	x06 = (x << 7) | (x >> 25)
	x03 += x07
	x = x15 ^ x03
	x15 = (x << 16) | (x >> 16)
	x11 += x15
	x = x07 ^ x11
	x07 = (x << 12) | (x >> 20)
	x03 += x07
	x = x15 ^ x03
	x15 = (x << 8) | (x >> 24)
	x11 += x15
	x = x07 ^ x11
	x07 = (x << 7) | (x >> 25)
	x00 += x05
	x = x15 ^ x00
	x15 = (x << 16) | (x >> 16)
	x10 += x15
	x = x05 ^ x10
	x05 = (x << 12) | (x >> 20)
	x00 += x05
	x = x15 ^ x00
	x15 = (x << 8) | (x >> 24)
	x10 += x15
	x = x05 ^ x10
	x05 = (x << 7) | (x >> 25)
	x01 += x06
	x = x12 ^ x01
	x12 = (x << 16) | (x >> 16)
	x11 += x12
	x = x06 ^ x11
	x06 = (x << 12) | (x >> 20)
	x01 += x06
	x = x12 ^ x01
	x12 = (x << 8) | (x >> 24)
	x11 += x12
	x = x06 ^ x11
	x06 = (x << 7) | (x >> 25)
	x02 += x07
	x = x13 ^ x02
	x13 = (x << 16) | (x >> 16)
	x08 += x13
	x = x07 ^ x08
	x07 = (x << 12) | (x >> 20)
	x02 += x07
	x = x13 ^ x02
	x13 = (x << 8) | (x >> 24)
	x08 += x13
	x = x07 ^ x08
	x07 = (x << 7) | (x >> 25)
	x03 += x04
	x = x14 ^ x03
	x14 = (x << 16) | (x >> 16)
	x09 += x14
	x = x04 ^ x09
	x04 = (x << 12) | (x >> 20)
	x03 += x04
	x = x14 ^ x03
	x14 = (x << 8) | (x >> 24)
	x09 += x14
	x = x04 ^ x09
	x04 = (x << 7) | (x >> 25)

	output[0] = x00 + input[0]
	output[1] = x01 + input[1]
	output[2] = x02 + input[2]
	output[3] = x03 + input[3]
	output[4] = x04 + input[4]
	output[5] = x05 + input[5]
	output[6] = x06 + input[6]
	output[7] = x07 + input[7]
	output[8] = x08 + input[8]
	output[9] = x09 + input[9]
	output[10] = x10 + input[10]
	output[11] = x11 + input[11]
	output[12] = x12 + input[12]
	output[13] = x13 + input[13]
	output[14] = x14 + input[14]
	output[15] = x15 + input[15]
}
