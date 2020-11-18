package hpke

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/dh/sidh"
)

func randomBytes(size int) []byte {
	out := make([]byte, size)
	rand.Read(out)
	return out
}

func TestKEMSchemes(t *testing.T) {
	schemes := []KEMScheme{
		&dhkemScheme{group: x25519Scheme{}},
		&dhkemScheme{group: ecdhScheme{curve: elliptic.P256(), KDF: hkdfScheme{hash: crypto.SHA256}}},
		&dhkemScheme{group: ecdhScheme{curve: elliptic.P521(), KDF: hkdfScheme{hash: crypto.SHA256}}},
		&sikeScheme{field: sidh.Fp503, KDF: hkdfScheme{hash: crypto.SHA512}},
		&sikeScheme{field: sidh.Fp751, KDF: hkdfScheme{hash: crypto.SHA512}},
	}

	for i, s := range schemes {
		ikm := make([]byte, s.PrivateKeySize())
		rand.Reader.Read(ikm)

		skR, pkR, err := s.DeriveKeyPair(ikm)
		if err != nil {
			t.Fatalf("[%d] Error generating KEM key pair: %v", i, err)
		}

		sharedSecretI, enc, err := s.Encap(rand.Reader, pkR)
		if err != nil {
			t.Fatalf("[%d] Error in KEM encapsulation: %v", i, err)
		}

		sharedSecretR, err := s.Decap(enc, skR)
		if err != nil {
			t.Fatalf("[%d] Error in KEM decapsulation: %v", i, err)
		}

		if !bytes.Equal(sharedSecretI, sharedSecretR) {
			t.Fatalf("[%d] Asymmetric KEM results [%x] != [%x]", i, sharedSecretI, sharedSecretR)
		}
	}
}

func TestDHSchemes(t *testing.T) {
	schemes := []dhScheme{
		ecdhScheme{curve: elliptic.P256(), KDF: hkdfScheme{hash: crypto.SHA256}},
		ecdhScheme{curve: elliptic.P521(), KDF: hkdfScheme{hash: crypto.SHA512}},
		x25519Scheme{},
	}

	for i, s := range schemes {
		ikm := make([]byte, s.PrivateKeySize())
		rand.Reader.Read(ikm)
		skA, pkA, err := s.DeriveKeyPair(ikm)
		if err != nil {
			t.Fatalf("[%d] Error generating DH key pair: %v", i, err)
		}

		rand.Reader.Read(ikm)
		skB, pkB, err := s.DeriveKeyPair(ikm)
		if err != nil {
			t.Fatalf("[%d] Error generating DH key pair: %v", i, err)
		}

		enc := s.Serialize(pkA)
		_, err = s.Deserialize(enc)
		if err != nil {
			t.Fatalf("[%d] Error parsing DH public key: %v", i, err)
		}

		sharedSecretAB, err := s.DH(skA, pkB)
		if err != nil {
			t.Fatalf("[%d] Error performing DH operation: %v", i, err)
		}

		sharedSecretBA, err := s.DH(skB, pkA)
		if err != nil {
			t.Fatalf("[%d] Error performing DH operation: %v", i, err)
		}

		if !bytes.Equal(sharedSecretAB, sharedSecretBA) {
			t.Fatalf("[%d] Asymmetric DH results [%x] != [%x]", i, sharedSecretAB, sharedSecretBA)
		}

		if len(s.Serialize(pkA)) != len(s.Serialize(pkB)) {
			t.Fatalf("[%d] Non-constant public key size [%x] != [%x]", i, len(s.Serialize(pkA)), len(s.Serialize(pkB)))
		}
	}
}

func TestAEADSchemes(t *testing.T) {
	schemes := []AEADScheme{
		aesgcmScheme{keySize: 16},
		aesgcmScheme{keySize: 32},
		chachaPolyScheme{},
	}

	for i, s := range schemes {
		key := randomBytes(int(s.KeySize()))
		nonce := randomBytes(int(s.NonceSize()))
		pt := randomBytes(1024)
		aad := randomBytes(1024)

		aead, err := s.New(key)
		if err != nil {
			t.Fatalf("[%d] Error instantiating AEAD: %v", i, err)
		}

		ctWithAAD := aead.Seal(nil, nonce, pt, aad)
		ptWithAAD, err := aead.Open(nil, nonce, ctWithAAD, aad)
		if err != nil {
			t.Fatalf("[%d] Error decrypting with AAD: %v", i, err)
		}

		if !bytes.Equal(ptWithAAD, pt) {
			t.Fatalf("[%d] Incorrect decryption [%x] != [%x]", i, ptWithAAD, pt)
		}

		ctWithoutAAD := aead.Seal(nil, nonce, pt, nil)
		ptWithoutAAD, err := aead.Open(nil, nonce, ctWithoutAAD, nil)
		if err != nil {
			t.Fatalf("[%d] Error decrypting without AAD: %v", i, err)
		}

		if !bytes.Equal(ptWithoutAAD, pt) {
			t.Fatalf("[%d] Incorrect decryption [%x] != [%x]", i, ptWithoutAAD, pt)
		}

		if bytes.Equal(ctWithAAD, ctWithoutAAD) {
			t.Fatalf("[%d] AAD not included in ciphertext", i)
		}
	}
}
