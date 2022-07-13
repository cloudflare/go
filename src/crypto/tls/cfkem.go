// Glue to add Circl's (post-quantum) hybrid KEMs to quic-go.
//
// To enable set CurvePreferences with the desired scheme as the first element:
//
//   import (
//      "github.com/cloudflare/circl/kem/tls"
//      "github.com/cloudflare/circl/kem/hybrid"
//
//          [...]
//
//   config.CurvePreferences = []tls.CurveID{
//      hybrid.Kyber512X25519().(tls.TLSScheme).TLSCurveID(),
//      qtls.X25519,
//      qtls.P256,
//   }

package tls

import (
	"io"

	"circl/kem"
	"circl/kem/hybrid"
)

// Either ecdheParameters or kem.PrivateKey
type clientKeySharePrivate interface{}

var (
	kyber512X25519CurveID = CurveID(0xFF01)
	kyber768X25519CurveID = CurveID(0xFF02)
	invalidCurveID        = CurveID(0xFFFF)
)

func kemSchemeKeyToCurveID(s kem.Scheme) CurveID {
	switch s.Name() {
	case "Kyber512-X25519":
		return kyber512X25519CurveID
	case "Kyber768-X25519":
		return kyber768X25519CurveID
	default:
		return invalidCurveID
	}
}

// Extract CurveID from clientKeySharePrivate
func clientKeySharePrivateCurveID(ks clientKeySharePrivate) CurveID {
	switch v := ks.(type) {
	case kem.PrivateKey:
		return kemSchemeKeyToCurveID(v.Scheme())
	case ecdheParameters:
		return v.CurveID()
	default:
		panic("cfkem: internal error: unknown clientKeySharePrivate")
	}
}

// Returns scheme by CurveID if supported by Circl
func curveIdToCirclScheme(id CurveID) kem.Scheme {
    switch id {
    case kyber512X25519CurveID:
		return hybrid.Kyber512X25519()
    case kyber768X25519CurveID:
		return hybrid.Kyber768X25519()
	}
	return nil
}

// Generate a new shared secret and encapsulates it for the packed
// public key in ppk using randomness from rnd.
func encapsulateForKem(scheme kem.Scheme, rnd io.Reader, ppk []byte) (
	ct, ss []byte, internalErr bool, err error) {
	pk, err := scheme.UnmarshalBinaryPublicKey(ppk)
	if err != nil {
		return nil, nil, false, err
	}
	seed := make([]byte, scheme.EncapsulationSeedSize())
	if _, err := io.ReadFull(rnd, seed); err != nil {
		return nil, nil, true, err
	}
	ct, ss, err = scheme.EncapsulateDeterministically(pk, seed)
	return ct, ss, false, err
}

// Generate a new keypair using randomness from rnd.
func generateKemKeyPair(scheme kem.Scheme, rnd io.Reader) (
	kem.PublicKey, kem.PrivateKey, error) {
	seed := make([]byte, scheme.SeedSize())
	if _, err := io.ReadFull(rnd, seed); err != nil {
		return nil, nil, err
	}
	pk, sk := scheme.DeriveKeyPair(seed)
	return pk, sk, nil
}
