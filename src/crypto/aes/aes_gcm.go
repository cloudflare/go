// +build amd64

package aes

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

// Defined in gcm_amd64.s
func hasGCMAsm() bool
func aesEncBlock(dst, src []byte, ks []uint32)
func gcmAesInit(productTable []byte, ks []uint32)
func gcmAesData(productTable, data, T []byte)
func gcmAesEnc(productTable, dst, src, ctr, T []byte, ks []uint32)
func gcmAesDec(productTable, dst, src, ctr, T []byte, ks []uint32)
func gcmAesFinish(productTable, tagMask, T []byte, pLen, dLen uint64)

const (
	gcmBlockSize = 16
	gcmTagSize   = 16
	gcmNonceSize = 12
)

var errOpen = errors.New("cipher: message authentication failed")

type aesCipherGCM struct {
	aesCipher
}

// NewGCM implements cipher.gcmAble. It returns the AES cipher wrapped in Galois
// Counter Mode, using a assembly implementation where possible.
func (c *aesCipherGCM) NewGCM() (cipher.AEAD, error) {
	ks := make([]uint32, len(c.enc))
	copy(ks, c.enc)
	g := &gcmAsm{ks, make([]byte, 16*16)}
	gcmAesInit(g.productTable, g.ks)
	return g, nil
}

type gcmAsm struct {
	ks           []uint32
	productTable []byte
}

func (*gcmAsm) NonceSize() int {
	return gcmNonceSize
}

func (*gcmAsm) Overhead() int {
	return gcmTagSize
}

// form crypto/cipher:gcm.go
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

func (g *gcmAsm) Seal(dst, nonce, plaintext, data []byte) []byte {
	if len(nonce) != gcmNonceSize {
		panic("cipher: incorrect nonce length given to GCM")
	}

	ret, out := sliceForAppend(dst, len(plaintext)+gcmTagSize)

	var counter, tagMask [gcmBlockSize]byte
	// Init counter to nonce||1
	copy(counter[:], nonce)
	counter[gcmBlockSize-1] = 1

	aesEncBlock(tagMask[:], counter[:], g.ks)

	gcmAesData(g.productTable, data, out[len(plaintext):])
	if len(plaintext) > 0 {
		gcmAesEnc(g.productTable, out, plaintext, counter[:], out[len(plaintext):], g.ks)
	}
	gcmAesFinish(g.productTable, tagMask[:], out[len(plaintext):], uint64(len(plaintext)), uint64(len(data)))

	return ret
}

func (g *gcmAsm) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(nonce) != gcmNonceSize {
		panic("cipher: incorrect nonce length given to GCM")
	}
	if len(ciphertext) < gcmTagSize {
		return nil, errOpen
	}
	tag := ciphertext[len(ciphertext)-gcmTagSize:]
	ciphertext = ciphertext[:len(ciphertext)-gcmTagSize]
	ret, out := sliceForAppend(dst, len(ciphertext))

	// See GCM spec, section 7.1.
	var counter, tagMask [gcmBlockSize]byte
	copy(counter[:], nonce)
	counter[gcmBlockSize-1] = 1

	aesEncBlock(tagMask[:], counter[:], g.ks)

	var expectedTag [gcmTagSize]byte

	gcmAesData(g.productTable, data, expectedTag[:])
	if len(ciphertext) > 0 {
		gcmAesDec(g.productTable, out, ciphertext, counter[:], expectedTag[:], g.ks)
	}
	gcmAesFinish(g.productTable, tagMask[:], expectedTag[:], uint64(len(ciphertext)), uint64(len(data)))

	if subtle.ConstantTimeCompare(expectedTag[:], tag) != 1 {
		return nil, errOpen
	}

	return ret, nil
}
