package tls

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/hpke"
)

// If the client uses the wrong KEM algorithm to offer ECH, the ECH provider
// should reject rather than abort. We check for this condition by looking at
// the error returned by hpke.Receiver.Setup(). This test asserts that the
// CIRCL's HPKE implementation returns the error we expect.
func TestCirclHpkeKemAlgorithmMismatchError(t *testing.T) {
	kem := hpke.KEM_P256_HKDF_SHA256
	kdf := hpke.KDF_HKDF_SHA256
	aead := hpke.AEAD_AES128GCM
	suite := hpke.NewSuite(kem, kdf, aead)
	_, sk, err := kem.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	incorrectKEM := hpke.KEM_X25519_HKDF_SHA256
	incorrectSuite := hpke.NewSuite(incorrectKEM, kdf, aead)
	incorrectPK, _, err := incorrectKEM.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Generate an encapsulated key share with the incorrect KEM algorithm.
	incorrectSender, err := incorrectSuite.NewSender(incorrectPK, []byte("some info string"))
	if err != nil {
		t.Fatal(err)
	}
	incorrectEnc, _, err := incorrectSender.Setup(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Attempt to parse an encapsulated key generated using the incorrect KEM
	// algorithm.
	receiver, err := suite.NewReceiver(sk, []byte("some info string"))
	if err != nil {
		t.Fatal(err)
	}

	expectedErrorString := "hpke: invalid KEM public key"
	if _, err := receiver.Setup(incorrectEnc); err == nil {
		t.Errorf("expected error; got success")
	} else if err.Error() != expectedErrorString {
		t.Errorf("incorrect error string: got '%s'; want '%s'", err, expectedErrorString)
	}
}
