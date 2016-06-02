// +build !amd64

package chacha20poly1305

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

type chacha20poly1305 struct {
	*chacha20Cipher
}

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
	var poly *poly1305MAC
	var err error

	if err = cp.setIV(nonce, 0); err != nil {
		panic("chacha20poly1305: incorrect nonce length given to ChaCha20-Poly1305")
	}

	ret, out := sliceForAppend(dst, len(plaintext)+16)

	var polyKey [64]byte
	var pad1, pad2 [16]byte

	cp.XORKeyStream(polyKey[:], polyKey[:])

	if poly, err = NewMac(polyKey[0:32]); err != nil {
		panic("chacha20poly1305: mac error")
	}
	a := len(additionalData)
	p := len(plaintext)

	if a&-15 > 0 {
		poly.Update(additionalData[:a&-16])
	}

	if a%16 > 0 {
		copy(pad1[:], additionalData[a&-16:])
		poly.Update(pad1[:])
	}

	cp.XORKeyStream(out, plaintext)

	if p&-16 > 0 {
		poly.Update(out[:p&-16])
	}

	if p%16 > 0 {
		copy(pad2[:], out[p&-16:len(plaintext)])
		poly.Update(pad2[:])
	}

	binary.LittleEndian.PutUint64(pad2[0:8], uint64(a))
	binary.LittleEndian.PutUint64(pad2[8:16], uint64(p))

	poly.Update(pad2[:])
	poly.Finish(out[len(plaintext):])
	return ret
}

var errOpen = errors.New("cipher: message authentication failed")

func (cp *chacha20poly1305) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	var poly *poly1305MAC
	var err error

	if err = cp.setIV(nonce, 0); err != nil {
		panic("chacha20poly1305: incorrect nonce length given to ChaCha20-Poly1305")
	}

	if len(ciphertext) < 16 {
		return nil, errOpen
	}

	tag := ciphertext[len(ciphertext)-16:]
	ciphertext = ciphertext[:len(ciphertext)-16]
	var polyKey [64]byte
	var pad1, pad2 [16]byte

	cp.XORKeyStream(polyKey[:], polyKey[:])

	if poly, err = NewMac(polyKey[0:32]); err != nil {
		panic("chacha20poly1305: mac error")
	}

	a := len(additionalData)
	c := len(ciphertext)

	if a&-15 > 0 {
		poly.Update(additionalData[:a&-16])
	}

	if a%16 > 0 {
		copy(pad1[:], additionalData[a&-16:])
		poly.Update(pad1[:])
	}

	if c&-15 > 0 {
		poly.Update(ciphertext[:c&-16])
	}

	if c%16 > 0 {
		copy(pad2[:], ciphertext[c&-16:len(ciphertext)])
		poly.Update(pad2[:])
	}

	binary.LittleEndian.PutUint64(pad2[0:8], uint64(a))
	binary.LittleEndian.PutUint64(pad2[8:16], uint64(c))

	poly.Update(pad2[:])
	poly.Finish(pad2[:])

	ret, out := sliceForAppend(dst, len(ciphertext))
	if subtle.ConstantTimeCompare(pad2[:], tag) != 1 {
		// Mimic AES-GCM
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}

	cp.XORKeyStream(out, ciphertext)
	cp.setIV(nonce, 0)
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
