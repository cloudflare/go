package chacha20poly1305

import (
	"bytes"
	cr "crypto/rand"
	"encoding/hex"
	mr "math/rand"
	"testing"
	"time"
)

func TestPoly1305(t *testing.T) {
	for i, test := range poly1305Tests {
		key, _ := hex.DecodeString(test.key)
		in, _ := hex.DecodeString(test.in)

		poly, _ := NewMAC(key[:])
		poly.Update(in)
		dst := poly.Finish(nil)

		if dstHex := hex.EncodeToString(dst); dstHex != test.out {
			t.Errorf("#%d: got %s, want %s", i, dstHex, test.out)
		}
	}
}

func TestChacha20(t *testing.T) {
	for i, test := range chacha20Tests {
		key, _ := hex.DecodeString(test.key)
		iv, _ := hex.DecodeString(test.iv)
		ref, _ := hex.DecodeString(test.out)
		ctr := test.ctr

		chacha, err := NewCipher(key, iv, ctr)
		if err != nil {
			t.Fatal(err)
		}

		ct := make([]byte, len(ref))
		chacha.XORKeyStream(ct, ct)

		if ctHex := hex.EncodeToString(ct); ctHex != test.out {
			t.Errorf("#%d: got %s, want %s", i, ctHex, test.out)
		}
	}
}

func TestChacha20Poly1305AEAD(t *testing.T) {

	mr.Seed(time.Now().UnixNano())

	for i, test := range chacha20Poly1305Tests {
		key, _ := hex.DecodeString(test.key)
		nonce, _ := hex.DecodeString(test.nonce)
		ad, _ := hex.DecodeString(test.aad)
		plaintext, _ := hex.DecodeString(test.plaintext)

		aead, err := NewAEAD(key)
		if err != nil {
			t.Fatal(err)
		}

		ct := aead.Seal(nil, nonce, plaintext, ad)
		if ctHex := hex.EncodeToString(ct); ctHex != test.out {
			t.Errorf("#%d: got %s, want %s", i, ctHex, test.out)
			continue
		}

		plaintext2, err := aead.Open(nil, nonce, ct, ad)
		if err != nil {
			t.Errorf("#%d: Open failed", i)
			continue
		}

		if !bytes.Equal(plaintext, plaintext2) {
			t.Errorf("#%d: plaintext's don't match: got %x vs %x", i, plaintext2, plaintext)
			continue
		}

		if len(ad) > 0 {
			alterAdIdx := mr.Intn(len(ad))
			ad[alterAdIdx] ^= 0x80
			if _, err := aead.Open(nil, nonce, ct, ad); err == nil {
				t.Errorf("#%d: Open was successful after altering additional data", i)
			}
			ad[alterAdIdx] ^= 0x80
		}

		alterNonceIdx := mr.Intn(aead.NonceSize())
		nonce[alterNonceIdx] ^= 0x80
		if _, err := aead.Open(nil, nonce, ct, ad); err == nil {
			t.Errorf("#%d: Open was successful after altering nonce", i)
		}
		nonce[alterNonceIdx] ^= 0x80

		alterCtIdx := mr.Intn(len(ct))
		ct[alterCtIdx] ^= 0x80
		if _, err := aead.Open(nil, nonce, ct, ad); err == nil {
			t.Errorf("#%d: Open was successful after altering ciphertext", i)
		}
		ct[alterCtIdx] ^= 0x80
	}

	// Some random tests to verify Open(Seal) == Plaintext
	for i := 0; i < 1000; i++ {
		var nonce [12]byte
		var key [32]byte

		al := mr.Intn(128)
		pl := mr.Intn(16384)
		ad := make([]byte, al)
		plaintext := make([]byte, pl)
		cr.Read(key[:])
		cr.Read(nonce[:])
		cr.Read(ad)
		cr.Read(plaintext)

		aead, err := NewAEAD(key[:])
		if err != nil {
			t.Fatal(err)
		}

		ct := aead.Seal(nil, nonce[:], plaintext, ad)

		plaintext2, err := aead.Open(nil, nonce[:], ct, ad)
		if err != nil {
			t.Errorf("Random #%d: Open failed", i)
			continue
		}

		if !bytes.Equal(plaintext, plaintext2) {
			t.Errorf("Random #%d: plaintext's don't match: got %x vs %x", i, plaintext2, plaintext)
			continue
		}

		if len(ad) > 0 {
			alterAdIdx := mr.Intn(len(ad))
			ad[alterAdIdx] ^= 0x80
			if _, err := aead.Open(nil, nonce[:], ct, ad); err == nil {
				t.Errorf("Random #%d: Open was successful after altering additional data", i)
			}
			ad[alterAdIdx] ^= 0x80
		}

		alterNonceIdx := mr.Intn(aead.NonceSize())
		nonce[alterNonceIdx] ^= 0x80
		if _, err := aead.Open(nil, nonce[:], ct, ad); err == nil {
			t.Errorf("Random #%d: Open was successful after altering nonce", i)
		}
		nonce[alterNonceIdx] ^= 0x80

		alterCtIdx := mr.Intn(len(ct))
		ct[alterCtIdx] ^= 0x80
		if _, err := aead.Open(nil, nonce[:], ct, ad); err == nil {
			t.Errorf("Random #%d: Open was successful after altering ciphertext", i)
		}
		ct[alterCtIdx] ^= 0x80
	}
}

func benchmarkPoly1305(b *testing.B, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var key [32]byte
	var dst [16]byte

	poly, _ := NewMAC(key[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		poly.Update(buf)
		poly.Finish(dst[:0])
	}
}

func benchmarkChacha20(b *testing.B, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var key [32]byte
	var iv [12]byte
	var ctr uint32

	chacha, _ := NewCipher(key[:], iv[:], ctr)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		chacha.XORKeyStream(buf, buf)
	}
}

func benchamarkChaCha20Poly1305Seal(b *testing.B, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var key [32]byte
	var nonce [12]byte
	var ad [13]byte
	var out []byte

	aead, _ := NewAEAD(key[:])
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out = aead.Seal(out[:0], nonce[:], buf[:], ad[:])
	}
}

func benchamarkChaCha20Poly1305Open(b *testing.B, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var key [32]byte
	var nonce [12]byte
	var ad [13]byte
	var ct []byte
	var out []byte

	aead, _ := NewAEAD(key[:])
	ct = aead.Seal(ct[:0], nonce[:], buf[:], ad[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, _ = aead.Open(out[:0], nonce[:], ct[:], ad[:])
	}
}

func BenchmarkPoly_64(b *testing.B) {
	benchmarkPoly1305(b, make([]byte, 64))
}

func BenchmarkPoly_1K(b *testing.B) {
	benchmarkPoly1305(b, make([]byte, 1024))
}

func BenchmarkChacha20_1K(b *testing.B) {
	benchmarkChacha20(b, make([]byte, 1024))
}

func BenchmarkChacha20_8K(b *testing.B) {
	benchmarkChacha20(b, make([]byte, 8*1024))
}

func BenchmarkChacha20Poly1305Open_16(b *testing.B) {
	benchamarkChaCha20Poly1305Open(b, make([]byte, 16))
}

func BenchmarkChacha20Poly1305Seal_16(b *testing.B) {
	benchamarkChaCha20Poly1305Seal(b, make([]byte, 16))
}

func BenchmarkChacha20Poly1305Open_64(b *testing.B) {
	benchamarkChaCha20Poly1305Open(b, make([]byte, 64))
}

func BenchmarkChacha20Poly1305Seal_64(b *testing.B) {
	benchamarkChaCha20Poly1305Seal(b, make([]byte, 64))
}

func BenchmarkChacha20Poly1305Open_256(b *testing.B) {
	benchamarkChaCha20Poly1305Open(b, make([]byte, 256))
}

func BenchmarkChacha20Poly1305Seal_256(b *testing.B) {
	benchamarkChaCha20Poly1305Seal(b, make([]byte, 256))
}

func BenchmarkChacha20Poly1305Open_1K(b *testing.B) {
	benchamarkChaCha20Poly1305Open(b, make([]byte, 1024))
}

func BenchmarkChacha20Poly1305Seal_1K(b *testing.B) {
	benchamarkChaCha20Poly1305Seal(b, make([]byte, 1024))
}

func BenchmarkChacha20Poly1305Open_1350(b *testing.B) {
	benchamarkChaCha20Poly1305Open(b, make([]byte, 1350))
}

func BenchmarkChacha20Poly1305Seal_1350(b *testing.B) {
	benchamarkChaCha20Poly1305Seal(b, make([]byte, 1350))
}

func BenchmarkChacha20Poly1305Open_8K(b *testing.B) {
	benchamarkChaCha20Poly1305Open(b, make([]byte, 8*1024))
}

func BenchmarkChacha20Poly1305Seal_8K(b *testing.B) {
	benchamarkChaCha20Poly1305Seal(b, make([]byte, 8*1024))
}

func BenchmarkChacha20Poly1305Open_16K(b *testing.B) {
	benchamarkChaCha20Poly1305Open(b, make([]byte, 16*1024))
}

func BenchmarkChacha20Poly1305Seal_16K(b *testing.B) {
	benchamarkChaCha20Poly1305Seal(b, make([]byte, 16*1024))
}
