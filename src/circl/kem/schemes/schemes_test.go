package schemes_test

import (
	"bytes"
	"testing"

	"circl/kem/schemes"
)

func TestCaseSensitivity(t *testing.T) {
	if schemes.ByName("kyber512") != schemes.ByName("Kyber512") {
		t.Fatal()
	}
}

func BenchmarkGenerateKey(b *testing.B) {
	allSchemes := schemes.All()
	for _, scheme := range allSchemes {
		scheme := scheme
		b.Run(scheme.Name(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, _ = scheme.GenerateKey()
			}
		})
	}
}

func BenchmarkEncapsulate(b *testing.B) {
	allSchemes := schemes.All()
	for _, scheme := range allSchemes {
		scheme := scheme
		pk, _, _ := scheme.GenerateKey()
		b.Run(scheme.Name(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, _ = scheme.Encapsulate(pk)
			}
		})
	}
}

func BenchmarkDecapsulate(b *testing.B) {
	allSchemes := schemes.All()
	for _, scheme := range allSchemes {
		scheme := scheme
		pk, sk, _ := scheme.GenerateKey()
		ct, _, _ := scheme.Encapsulate(pk)
		b.Run(scheme.Name(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = scheme.Decapsulate(sk, ct)
			}
		})
	}
}

func TestApi(t *testing.T) {
	allSchemes := schemes.All()
	for _, scheme := range allSchemes {
		scheme := scheme
		t.Run(scheme.Name(), func(t *testing.T) {
			if scheme == nil {
				t.Fatal()
			}

			pk, sk, err := scheme.GenerateKey()
			if err != nil {
				t.Fatal()
			}

			packedPk, err := pk.MarshalBinary()
			if err != nil {
				t.Fatal()
			}

			if len(packedPk) != scheme.PublicKeySize() {
				t.Fatal()
			}

			packedSk, err := sk.MarshalBinary()
			if err != nil {
				t.Fatal()
			}

			if len(packedSk) != scheme.PrivateKeySize() {
				t.Fatal()
			}

			pk2, err := scheme.UnmarshalBinaryPublicKey(packedPk)
			if err != nil {
				t.Fatal()
			}

			sk2, err := scheme.UnmarshalBinaryPrivateKey(packedSk)
			if err != nil {
				t.Fatal()
			}

			if !sk.Equal(sk2) {
				t.Fatal()
			}

			if !pk.Equal(pk2) {
				t.Fatal()
			}

			ct, ss, err := scheme.Encapsulate(pk2)
			if err != nil {
				t.Fatal(err)
			}
			if len(ct) != scheme.CiphertextSize() {
				t.Fatal()
			}
			if len(ss) != scheme.SharedKeySize() {
				t.Fatal()
			}

			ss2, err := scheme.Decapsulate(sk2, ct)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ss, ss2) {
				t.Fatal()
			}
		})
	}
}
