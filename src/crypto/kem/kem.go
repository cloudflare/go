package kem

import (
	"circl/kem/schemes"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/curve25519"
)

// ID identifies each type of KEM.
type ID uint16

const (
	// KEM25519 is X25519 as a KEM. Not quantum-safe.
	KEM25519 ID = 0x01fb
	// Kyber512 is a post-quantum KEM, as defined in: https://pq-crystals.org/kyber/ .
	Kyber512 ID = 0x01fc

	// minimum KEM to be used.
	minKEM = KEM25519
	// maximum KEM to be used.
	maxKEM = Kyber512
)

// PrivateKey is a KEM private key.
type PrivateKey struct {
	KEMId      ID
	PrivateKey []byte
}

// PublicKey is a KEM public key.
type PublicKey struct {
	KEMId     ID
	PublicKey []byte
}

// MarshalBinary returns the byte representation of a KEM public key.
func (pubKey *PublicKey) MarshalBinary() ([]byte, error) {
	var b cryptobyte.Builder

	b.AddUint16(uint16(pubKey.KEMId))
	b.AddBytes(pubKey.PublicKey)

	return b.BytesOrPanic(), nil
}

// UnmarshalBinary produces a PublicKey from a byte array.
func (pubKey *PublicKey) UnmarshalBinary(raw []byte) error {
	s := cryptobyte.String(raw)

	var id uint16
	if !s.ReadUint16(&id) {
		return errors.New("crypto/kem: invalid algorithm")
	}

	kemID := ID(id)
	if kemID < minKEM || kemID > maxKEM {
		return errors.New("crypto/kem: invalid KEM type")
	}

	pubKey.KEMId = kemID
	pubKey.PublicKey = raw[2:]
	return nil
}

// GenerateKey generates a keypair for a given KEM.
// It returns a KEM public and private key.
func GenerateKey(rand io.Reader, kemID ID) (*PublicKey, *PrivateKey, error) {
	switch kemID {
	case Kyber512:
		scheme := schemes.ByName("Kyber512")
		seed := make([]byte, scheme.SeedSize())
		if _, err := io.ReadFull(rand, seed); err != nil {
			return nil, nil, err
		}
		publicKey, privateKey := scheme.DeriveKeyPair(seed)
		pk, _ := publicKey.MarshalBinary()
		sk, _ := privateKey.MarshalBinary()

		return &PublicKey{KEMId: kemID, PublicKey: pk}, &PrivateKey{KEMId: kemID, PrivateKey: sk}, nil
	case KEM25519:
		privateKey := make([]byte, curve25519.ScalarSize)
		if _, err := io.ReadFull(rand, privateKey); err != nil {
			return nil, nil, err
		}
		publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
		if err != nil {
			return nil, nil, err
		}
		return &PublicKey{KEMId: kemID, PublicKey: publicKey}, &PrivateKey{KEMId: kemID, PrivateKey: privateKey}, nil
	default:
		return nil, nil, fmt.Errorf("crypto/kem: internal error: unsupported KEM %d", kemID)
	}
}

// Encapsulate returns a shared secret and a ciphertext.
func Encapsulate(rand io.Reader, pk *PublicKey) ([]byte, []byte, error) {
	switch pk.KEMId {
	case Kyber512:
		scheme := schemes.ByName("Kyber512")
		pub, err := scheme.UnmarshalBinaryPublicKey(pk.PublicKey)
		if err != nil {
			return nil, nil, err
		}

		seed := make([]byte, scheme.EncapsulationSeedSize())
		if _, err := io.ReadFull(rand, seed); err != nil {
			return nil, nil, err
		}

		ct, ss, err := scheme.EncapsulateDeterministically(pub, seed)
		if err != nil {
			return nil, nil, err
		}
		return ss, ct, nil
	case KEM25519:
		privateKey := make([]byte, curve25519.ScalarSize)
		if _, err := io.ReadFull(rand, privateKey); err != nil {
			return nil, nil, err
		}
		ciphertext, err := curve25519.X25519(privateKey, curve25519.Basepoint)
		if err != nil {
			return nil, nil, err
		}
		sharedSecret, err := curve25519.X25519(privateKey, pk.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		return sharedSecret, ciphertext, nil
	default:
		return nil, nil, errors.New("crypto/kem: internal error: unsupported KEM in Encapsulate")
	}
}

// Decapsulate returns the shared secret given the private key and the ciphertext.
func Decapsulate(privateKey *PrivateKey, ciphertext []byte) ([]byte, error) {
	switch privateKey.KEMId {
	case Kyber512:
		scheme := schemes.ByName("Kyber512")
		sk, err := scheme.UnmarshalBinaryPrivateKey(privateKey.PrivateKey)
		if err != nil {
			return nil, err
		}
		if len(ciphertext) != scheme.CiphertextSize() {
			return nil, fmt.Errorf("crypto/kem: ciphertext is of len %d, expected %d", len(ciphertext), scheme.CiphertextSize())
		}
		ss, err := scheme.Decapsulate(sk, ciphertext)
		if err != nil {
			return nil, err
		}
		return ss, nil
	case KEM25519:
		sharedSecret, err := curve25519.X25519(privateKey.PrivateKey, ciphertext)
		if err != nil {
			return nil, err
		}
		return sharedSecret, nil
	default:
		return nil, errors.New("crypto/kem: internal error: unsupported KEM in Decapsulate")
	}
}
