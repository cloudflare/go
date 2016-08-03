package chacha20poly1305

import (
	"crypto/cipher"
	"errors"
)

var errOpen = errors.New("cipher: message authentication failed")

// An AEAD is an implementation of cipher.AEAD based on ChaCha20 and Poly1305,
// with a given key.
type AEAD struct {
	cp *Cipher
}

var _ cipher.AEAD = &AEAD{}

// NewAEAD returns a ChaCha20+Poly1305 AEAD with the given key, which must be 32 bytes.
func NewAEAD(key []byte) (*AEAD, error) {
	c, err := newChaCha(key)
	if err != nil {
		return nil, err
	}

	ret := &AEAD{c}
	return ret, nil
}

// NonceSize is 12 bytes.
func (a *AEAD) NonceSize() int {
	return 12
}

// Overhead is 16 bytes.
func (a *AEAD) Overhead() int {
	return 16
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
