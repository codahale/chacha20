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
	"unsafe"
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
	input *[size]uint32 // the input block as words
	block *[block]byte  // the output block as bytes
	count int           // the number of unused bytes in the block
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
	c.block = new([block]byte)

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
		dst[i] = src[i] ^ c.block[block-c.count]
		c.count--
		i++
	}
}

// Reset zeros the key data so that it will no longer appear in the process's
// memory.
func (c *Cipher) Reset() {
	for i := 0; i < size; i++ {
		c.input[i] = 0
	}
	for i := 0; i < block; i++ {
		c.block[i] = 0
	}
	c.count = 0
}

// advances the keystream
func (c *Cipher) advance() {
	core(c.input, (*[size]uint32)(unsafe.Pointer(c.block)))
	c.count = block
	c.input[12]++
	if c.input[12] == 0 {
		c.input[13]++
	}
}
