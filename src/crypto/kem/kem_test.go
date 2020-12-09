package kem

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestKemAPI(t *testing.T) {
	tests := []struct {
		name  string
		kemID ID
	}{
		{"Kem25519", KEM25519},
		{"SIKEp434", SIKEp434},
		{"Kyber512", Kyber512},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publicKey, privateKey, err := GenerateKey(rand.Reader, tt.kemID)
			if err != nil {
				t.Fatal(err)
			}
			ss, ct, err := Encapsulate(rand.Reader, publicKey)
			if err != nil {
				t.Fatal(err)
			}

			ss2, err := Decapsulate(privateKey, ct)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ss, ss2) {
				t.Fatal("Decapsulated differing shared secret")
			}

			data, _ := publicKey.MarshalBinary()
			pk2 := new(PublicKey)
			err = pk2.UnmarshalBinary(data)
			if err != nil {
				t.Fatal("error unmarshaling")
			}
			if pk2.KEMId != publicKey.KEMId {
				t.Fatal("Difference in Id")
			}
			if !bytes.Equal(publicKey.PublicKey, publicKey.PublicKey) {
				t.Fatal("Difference in data for public keys")
			}
		})
	}

	// check if nonexisting kem fails
	invalidKemID := ID(0)
	if _, _, err := GenerateKey(rand.Reader, invalidKemID); err == nil {
		t.Fatal("This KEM should've been invalid and failed")
	}

}
