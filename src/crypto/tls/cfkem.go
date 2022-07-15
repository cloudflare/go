// Copyright 2022 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.
//
// Glue to add Circl's (post-quantum) hybrid KEMs.
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
//      tls.X25519,
//      tls.P256,
//   }

package tls

import (
	"fmt"
	"io"

	"circl/kem"
	"circl/kem/hybrid"
)

// Either ecdheParameters or kem.PrivateKey
type clientKeySharePrivate interface{}

var (
	kyber512X25519CurveID = CurveID(0xfe30)
	kyber768X25519CurveID = CurveID(0xfe31)
	invalidCurveID        = CurveID(0)
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
		ret := kemSchemeKeyToCurveID(v.Scheme())
		if ret == invalidCurveID {
			panic("cfkem: internal error: don't know CurveID for this KEM")
		}
		return ret
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
	ct, ss []byte, alert alert, err error) {
	pk, err := scheme.UnmarshalBinaryPublicKey(ppk)
	if err != nil {
		return nil, nil, alertIllegalParameter, fmt.Errorf("unpack pk: %w", err)
	}
	seed := make([]byte, scheme.EncapsulationSeedSize())
	if _, err := io.ReadFull(rnd, seed); err != nil {
		return nil, nil, alertInternalError, fmt.Errorf("random: %w", err)
	}
	ct, ss, err = scheme.EncapsulateDeterministically(pk, seed)
	return ct, ss, alertIllegalParameter, err
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
