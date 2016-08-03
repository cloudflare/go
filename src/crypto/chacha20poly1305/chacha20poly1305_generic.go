// +build !amd64

package chacha20poly1305

import (
	"crypto/internal/bytesop"
	"crypto/subtle"
	"encoding/binary"
)

// Seal encrypts and authenticates plaintext.
// See the cipher.AEAD interface for details.
func (x *AEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	var poly *MAC
	var err error

	if err = x.cp.setIV(nonce, 0); err != nil {
		panic("crypto/chacha20poly1305: incorrect nonce length")
	}

	ret, out := bytesop.SliceForAppend(dst, len(plaintext)+16)

	var polyKey [64]byte
	var pad1, pad2 [16]byte

	x.cp.XORKeyStream(polyKey[:], polyKey[:])

	if poly, err = NewMAC(polyKey[0:32]); err != nil {
		panic("crypto/chacha20poly1305: mac error")
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

	x.cp.XORKeyStream(out, plaintext)

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
	// Finish is guaranteed not to reallocate the slice as it has enough space.
	poly.Finish(out[:len(plaintext)])
	return ret
}

// Open authenticates and decrypts ciphertext.
// See the cipher.AEAD interface for details.
func (x *AEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	var poly *MAC
	var err error

	if err = x.cp.setIV(nonce, 0); err != nil {
		panic("crypto/chacha20poly1305: incorrect nonce length")
	}

	if len(ciphertext) < 16 {
		return nil, errOpen
	}

	tag := ciphertext[len(ciphertext)-16:]
	ciphertext = ciphertext[:len(ciphertext)-16]
	var polyKey [64]byte
	var pad1, pad2 [16]byte

	x.cp.XORKeyStream(polyKey[:], polyKey[:])

	if poly, err = NewMAC(polyKey[0:32]); err != nil {
		panic("crypto/chacha20poly1305: mac error")
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
	poly.Finish(pad2[:0])

	ret, out := bytesop.SliceForAppend(dst, len(ciphertext))
	if subtle.ConstantTimeCompare(pad2[:], tag) != 1 {
		// Mimic AES-GCM
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}

	x.cp.XORKeyStream(out, ciphertext)
	x.cp.setIV(nonce, 0)
	return ret, nil
}
