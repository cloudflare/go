package tls

import (
	"encoding/binary"
	"errors"
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

// MarshalPublicKey produces the public key in bytes for the network
func MarshalPublicKey(pubKey PublicKey) []byte {
	buf := make([]byte, 4+len(pubKey.PublicKey))
	binary.LittleEndian.PutUint16(buf, uint16(pubKey.Id))
	copy(buf[4:], pubKey.PublicKey)
	return buf
}

// UnmarshalPublicKey produces a PublicKey from a byte array
func UnmarshalPublicKey(algorithm KemID, input []byte) PublicKey {
	return PublicKey{
		Id:        algorithm,
		PublicKey: input,
	}
}

// Keypair generates a keypair for a given KEM
// returns (public, private, err)
func Keypair(rand io.Reader, kemID KemID) (PublicKey, PrivateKey, error) {
	switch kemID {
	case Kem25519:
		privateKey := make([]byte, curve25519.ScalarSize)
		if _, err := io.ReadFull(rand, privateKey); err != nil {
			return PublicKey{}, PrivateKey{}, err
		}
		publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
		if err != nil {
			return PublicKey{}, PrivateKey{}, err
		}
		return PublicKey{Id: kemID, PublicKey: publicKey}, PrivateKey{Id: kemID, PrivateKey: privateKey}, nil
	case SIKEp434:
		privateKey := sidh.NewPrivateKey(sidh.Fp434, sidh.KeyVariantSike)
		publicKey := sidh.NewPublicKey(sidh.Fp434, sidh.KeyVariantSike)
		if err := privateKey.Generate(rand); err != nil {
			return PublicKey{}, PrivateKey{}, err
		}
		privateKey.GeneratePublicKey(publicKey)

		pubBytes := make([]byte, publicKey.Size())
		privBytes := make([]byte, privateKey.Size())
		return PublicKey{Id: kemID, PublicKey: pubBytes}, PrivateKey{Id: kemID, PrivateKey: privBytes}, nil
	default:
		return PublicKey{}, PrivateKey{}, errors.New("tls: internal error: unsupported KEM")
	}

}

// Encapsulate returns (shared secret, ciphertext)
func Encapsulate(rand io.Reader, pk *PublicKey) ([]byte, []byte, error) {
	if pk.Id != Kem25519 {
		return nil, nil, errors.New("tls: internal error: unsupported KEM")
	}

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
}

// Decapsulate generates the shared secret
func Decapsulate(privateKey *PrivateKey, ciphertext []byte) ([]byte, error) {
	if privateKey.Id != Kem25519 {
		return nil, errors.New("tls: internal error: unsupported KEM")
	}

	sharedSecret, err := curve25519.X25519(privateKey.PrivateKey, ciphertext)
	if err != nil {
		return nil, err
	}

	return sharedSecret, nil
}
