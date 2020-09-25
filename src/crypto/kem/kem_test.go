package tls

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestKemAPI(t *testing.T) {
	tests := []struct {
		name string
		kem  KemID
	}{
		{"Kem25519", Kem25519},
		{"SIKEp434", SIKEp434},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publicKey, privateKey, err := Keypair(rand.Reader, tt.kem)
			if err != nil {
				t.Fatal(err)
			}
			ss, ct, err := Encapsulate(rand.Reader, &publicKey)
			if err != nil {
				t.Fatal(err)
			}

			ss2, err := Decapsulate(&privateKey, ct)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ss, ss2) {
				t.Fatal("Decapsulated differing shared secret")
			}
		})
	}

	// check if nonexisting kem fails
	fakeKem := KemID(0)
	if _, _, err := Keypair(rand.Reader, fakeKem); err == nil {
		t.Fatal("This KEM should've been invalid and failed")
	}

}
