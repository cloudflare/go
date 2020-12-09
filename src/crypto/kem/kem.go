package kem

import (
	"circl/dh/sidh"
	"circl/kem/schemes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

// ID identifies each flavor of KEM.
type ID uint16

const (
	// KEM25519 is X25519 as a KEM. Not quantum-safe.
	KEM25519 ID = 0x01fb
	// Kyber512 is a post-quantum KEM based on MLWE
	Kyber512 ID = 0x01fc
	// SIKEp434 is a post-quantum KEM
	SIKEp434 ID = 0x01fd

	// minimum
	minKEM = KEM25519
	// maximum
	maxKEM = SIKEp434
)

// PrivateKey is a private key.
type PrivateKey struct {
	KEMId      ID
	PrivateKey []byte
}

// PublicKey is a public key.
type PublicKey struct {
	KEMId     ID
	PublicKey []byte
}

// MarshalBinary returns the byte representation of a public key.
func (pubKey *PublicKey) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 2+len(pubKey.PublicKey))
	binary.LittleEndian.PutUint16(buf, uint16(pubKey.KEMId))
	copy(buf[2:], pubKey.PublicKey)
	return buf, nil
}

// UnmarshalBinary produces a PublicKey from a byte array.
func (pubKey *PublicKey) UnmarshalBinary(data []byte) error {
	id := ID(binary.LittleEndian.Uint16(data[:2]))
	if id < minKEM || id > maxKEM {
		return errors.New("Invalid KEM type")
	}

	pubKey.KEMId = id
	pubKey.PublicKey = data[2:]
	return nil
}

// GenerateKey generates a keypair for a given KEM.
// It returns a public and private key.
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
	case SIKEp434:
		privateKey := sidh.NewPrivateKey(sidh.Fp434, sidh.KeyVariantSike)
		publicKey := sidh.NewPublicKey(sidh.Fp434, sidh.KeyVariantSike)
		if err := privateKey.Generate(rand); err != nil {
			return nil, nil, err
		}
		privateKey.GeneratePublicKey(publicKey)

		pubBytes := make([]byte, publicKey.Size())
		privBytes := make([]byte, privateKey.Size())
		publicKey.Export(pubBytes)
		privateKey.Export(privBytes)
		return &PublicKey{KEMId: kemID, PublicKey: pubBytes}, &PrivateKey{KEMId: kemID, PrivateKey: privBytes}, nil
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
	case SIKEp434:
		kem := sidh.NewSike434(rand)
		sikepk := sidh.NewPublicKey(sidh.Fp434, sidh.KeyVariantSike)
		err := sikepk.Import(pk.PublicKey)
		if err != nil {
			return nil, nil, err
		}

		ct := make([]byte, kem.CiphertextSize())
		ss := make([]byte, kem.SharedSecretSize())
		err = kem.Encapsulate(ct, ss, sikepk)
		if err != nil {
			return nil, nil, err
		}

		return ss, ct, nil
	default:
		return nil, nil, errors.New("crypto/kem: internal error: unsupported KEM in Encapsulate")
	}
}

// Decapsulate generates the shared secret.
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
	case SIKEp434:
		kem := sidh.NewSike434(nil)
		sikesk := sidh.NewPrivateKey(sidh.Fp434, sidh.KeyVariantSike)
		err := sikesk.Import(privateKey.PrivateKey)
		if err != nil {
			return nil, err
		}

		sikepk := sidh.NewPublicKey(sidh.Fp434, sidh.KeyVariantSike)
		sikesk.GeneratePublicKey(sikepk)
		ss := make([]byte, kem.SharedSecretSize())
		err = kem.Decapsulate(ss, sikesk, sikepk, ciphertext)
		if err != nil {
			return nil, err
		}

		return ss, nil
	default:
		return nil, errors.New("crypto/kem: internal error: unsupported KEM in Decapsulate")
	}
}
