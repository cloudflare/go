package chacha20poly1305

import "crypto/internal/bytesop"

//go:noescape
func chacha20Poly1305Open(dst []byte, key []uint32, src, ad []byte) bool

//go:noescape
func chacha20Poly1305Seal(dst []byte, key []uint32, src, ad []byte)

// Seal implements cipher.AEAD.Seal.
func (a *AEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if err := a.cp.setIV(nonce, 0); err != nil {
		panic("crypto/chacha20poly1305: incorrect nonce length")
	}

	ret, out := bytesop.SliceForAppend(dst, len(plaintext)+16)
	chacha20Poly1305Seal(out[:], a.cp.state[:], plaintext, additionalData)
	return ret
}

// Open implements cipher.AEAD.Open.
func (a *AEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if err := a.cp.setIV(nonce, 0); err != nil {
		panic("crypto/chacha20poly1305: incorrect nonce length")
	}

	if len(ciphertext) < 16 {
		return nil, errOpen
	}

	ciphertext = ciphertext[:len(ciphertext)-16]
	ret, out := bytesop.SliceForAppend(dst, len(ciphertext))
	if chacha20Poly1305Open(out, a.cp.state[:], ciphertext, additionalData) != true {
		return nil, errOpen
	}

	return ret, nil
}
