package chacha20_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/codahale/chacha20"
)

// stolen from http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-00#section-7
var testVectors = [][]string{
	[]string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000",
		"76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669",
	},
	[]string{
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000",
		"4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275",
	},
	[]string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000001",
		"de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e3",
	},
	[]string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000",
		"ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb004",
	},
	[]string{
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"0001020304050607",
		"f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb",
	},
}

func TestChaCha20(t *testing.T) {
	for i, vector := range testVectors {
		t.Logf("Running test vector %d", i)

		key, err := hex.DecodeString(vector[0])
		if err != nil {
			t.Error(err)
		}

		nonce, err := hex.DecodeString(vector[1])
		if err != nil {
			t.Error(err)
		}

		c, err := chacha20.New(key, nonce)
		if err != nil {
			t.Error(err)
		}

		expected, err := hex.DecodeString(vector[2])
		if err != nil {
			t.Error(err)
		}

		src := make([]byte, len(expected))
		dst := make([]byte, len(expected))
		c.XORKeyStream(dst, src)

		if !bytes.Equal(expected, dst) {
			t.Errorf("Bad keystream: expected %x, was %x", expected, dst)

			for i, v := range expected {
				if dst[i] != v {
					t.Logf("Mismatch at offset %d: %x vs %x", i, v, dst[i])
					break
				}
			}
		}
	}
}

func TestBadKeySize(t *testing.T) {
	key := make([]byte, 3)
	nonce := make([]byte, chacha20.NonceSize)

	_, err := chacha20.New(key, nonce)

	if err != chacha20.ErrInvalidKey {
		t.Error("Should have rejected an invalid key")
	}
}

func TestBadNonceSize(t *testing.T) {
	key := make([]byte, chacha20.KeySize)
	nonce := make([]byte, 3)

	_, err := chacha20.New(key, nonce)

	if err != chacha20.ErrInvalidNonce {
		t.Error("Should have rejected an invalid nonce")
	}
}

func ExampleCipher() {
	key, err := hex.DecodeString("60143a3d7c7137c3622d490e7dbb85859138d198d9c648960e186412a6250722")
	if err != nil {
		panic(err)
	}

	// A nonce should only be used once. Generate it randomly.
	nonce, err := hex.DecodeString("308c92676fa95973")
	if err != nil {
		panic(err)
	}

	c, err := chacha20.New(key, nonce)
	if err != nil {
		panic(err)
	}

	src := []byte("hello I am a secret message")
	dst := make([]byte, len(src))

	c.XORKeyStream(dst, src)

	fmt.Printf("%x\n", dst)
	// Output:
	// a05452ebd981422dcdab2c9cde0d20a03f769e87d3e976ee6d6a11
}
