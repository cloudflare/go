package tls

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	sidh "circl/dh/sidh"

	"golang.org/x/crypto/curve25519"
)

// KemID identifies the KEM we use
type KemID uint16

const (
	// Kem25519 is X25519 as a KEM. Not quantum-safe.
	Kem25519 KemID = 0x01fb
	// CSIDH is a post-quantum NIKE
	CSIDH KemID = 0x01fc
	// Kyber512 is a post-quantum KEM based on MLWE
	Kyber512 KemID = 0x01fd
	// SIKEp434 is a post-quantum KEM
	SIKEp434 KemID = 0x01fe

	// minimum
	minimum_id = Kem25519
	// maximum
	max_id = SIKEp434
)

// PrivateKey is a private key
type PrivateKey struct {
	Id         KemID
	PrivateKey []byte
}

// PublicKey is a public key
type PublicKey struct {
	Id        KemID
	PublicKey []byte
}

func (pubKey *PublicKey) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 4+len(pubKey.PublicKey))
	binary.LittleEndian.PutUint16(buf, uint16(pubKey.Id))
	copy(buf[4:], pubKey.PublicKey)
	return buf, nil
}

func (pubKey *PublicKey) UnmarshalBinary(data []byte) error {
	keyid := KemID(binary.LittleEndian.Uint16(data[:4]))
	if keyid < minimum_id || keyid > max_id {
		return errors.New("Unknown KEM id")
	}
	pubKey.Id = keyid
	pubKey.PublicKey = data[4:]
	return nil
}

// Keypair generates a keypair for a given KEM
// returns (public, private, err)
func Keypair(rand io.Reader, kemID KemID) (*PublicKey, *PrivateKey, error) {
	switch kemID {
	case Kem25519:
		privateKey := make([]byte, curve25519.ScalarSize)
		if _, err := io.ReadFull(rand, privateKey); err != nil {
			return nil, nil, err
		}
		publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
		if err != nil {
			return nil, nil, err
		}
		pk := new(PublicKey)
		pk.Id = kemID
		pk.PublicKey = publicKey
		sk := new(PrivateKey)
		sk.Id = kemID
		sk.PrivateKey = privateKey
		return pk, sk, nil
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
		pk := new(PublicKey)
		sk := new(PrivateKey)
		pk.Id = kemID
		sk.Id = kemID
		pk.PublicKey = pubBytes
		sk.PrivateKey = privBytes
		return pk, sk, nil
	default:
		return nil, nil, fmt.Errorf("crypto/kem: internal error: unsupported KEM %d", kemID)
	}

}

// Encapsulate returns (shared secret, ciphertext)
func Encapsulate(rand io.Reader, pk *PublicKey) ([]byte, []byte, error) {
	switch pk.Id {
	case Kem25519:
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
		if err := sikepk.Import(pk.PublicKey); err != nil {
			return nil, nil, err
		}
		ct := make([]byte, kem.CiphertextSize())
		ss := make([]byte, kem.SharedSecretSize())
		if err := kem.Encapsulate(ct, ss, sikepk); err != nil {
			return nil, nil, err
		}
		return ss, ct, nil
	default:
		return nil, nil, errors.New("crypto/kem: internal error: unsupported KEM in Encapsulate")
	}

}

// Decapsulate generates the shared secret
func Decapsulate(privateKey *PrivateKey, ciphertext []byte) ([]byte, error) {
	switch privateKey.Id {
	case Kem25519:
		sharedSecret, err := curve25519.X25519(privateKey.PrivateKey, ciphertext)
		if err != nil {
			return nil, err
		}
		return sharedSecret, nil
	case SIKEp434:
		kem := sidh.NewSike434(nil)
		sikesk := sidh.NewPrivateKey(sidh.Fp434, sidh.KeyVariantSike)
		if err := sikesk.Import(privateKey.PrivateKey); err != nil {
			return nil, err
		}
		sikepk := sidh.NewPublicKey(sidh.Fp434, sidh.KeyVariantSike)
		sikesk.GeneratePublicKey(sikepk)
		ss := make([]byte, kem.SharedSecretSize())
		if err := kem.Decapsulate(ss, sikesk, sikepk, ciphertext); err != nil {
			return nil, err
		}
		return ss, nil
	default:
		return nil, errors.New("crypto/kem: internal error: unsupported KEM")
	}
}
