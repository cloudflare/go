package chacha20poly1305

import (
	"crypto/cipher"
	"errors"
)

type chacha20poly1305 struct {
	*chacha20Cipher
}

//go:noescape
func chacha20Poly1305Open(dst []byte, key []uint32, src, ad []byte) bool

//go:noescape
func chacha20Poly1305Seal(dst []byte, key []uint32, src, ad []byte)

func NewChachaPoly(key []byte) (cipher.AEAD, error) {
	c, err := newChacha(key)
	if err != nil {
		return nil, err
	}

	ret := &chacha20poly1305{c}
	return ret, nil
}

func (cp *chacha20poly1305) NonceSize() int {
	return 12
}

func (cp *chacha20poly1305) Overhead() int {
	return 16
}

func (cp *chacha20poly1305) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	var err error

	if err = cp.setIV(nonce, 0); err != nil {
		panic("chacha20poly1305: incorrect nonce length given to ChaCha20-Poly1305")
	}

	ret, out := sliceForAppend(dst, len(plaintext)+16)
	chacha20Poly1305Seal(out[:], cp.state[:], plaintext, additionalData)
	return ret
}

var errOpen = errors.New("cipher: message authentication failed")

func (cp *chacha20poly1305) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	var err error

	if err = cp.setIV(nonce, 0); err != nil {
		panic("chacha20poly1305: incorrect nonce length given to ChaCha20-Poly1305")
	}

	if len(ciphertext) < 16 {
		return nil, errOpen
	}

	ciphertext = ciphertext[:len(ciphertext)-16]
	ret, out := sliceForAppend(dst, len(ciphertext))
	if chacha20Poly1305Open(out, cp.state[:], ciphertext, additionalData) != true {
		return nil, errOpen
	}

	return ret, nil
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
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
