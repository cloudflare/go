// Copyright 2020 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// There is a slight mismatch between the API exported by HPKE and the API
// required to implement the ECH logic in the TLS stack. Namely, an "HPKE
// ciphersuite" is a (KEM, KDF, AEAD) triple, and as such, the API of the HPKE
// implementation we use, github.com/cisco/go-hpke, presumes all three
// algorithms are known prior to any HPKE operation. In contrast, an "ECH
// ciphersuite" is a (KDF, AEAD) pair, meaning the KDF and AEAD may not be known
// when doing a KEM operation, e.g., generating a KEM key pair. This library
// provides a thin wrapper around github.com/cisco/go-hpke that resolves this
// mismatch.
//
// NOTE: The vendored version of "github.com/cisco/go-hpke" MUST implement
// draft-irtf-cfrg-hpke-05 and MUST support X25519, HKDF-SHA256, and AES128-GCM.
package ech

import (
	"fmt"
	"io"

	"github.com/cisco/go-hpke"
)

const (
	// Supported KEMs
	HPKE_KEM_DHKEM_X25519_HKDF_SHA256 = uint16(hpke.DHKEM_X25519)
	HPKE_KEM_DHKEM_P256_HKDF_SHA256   = uint16(hpke.DHKEM_P256)

	// Supported KDFs
	HPKE_KDF_HKDF_SHA256 = uint16(hpke.KDF_HKDF_SHA256)
	HPKE_KDF_HKDF_SHA384 = uint16(hpke.KDF_HKDF_SHA384)

	// Supported AEADs
	HPKE_AEAD_AES128_GCM        = uint16(hpke.AEAD_AESGCM128)
	HPKE_AEAD_CHACHA20_POLY1305 = uint16(hpke.AEAD_CHACHA20POLY1305)

	// Stand-in values for algorithms that are unknown prior to a particular
	// operation.
	dummyKemId  = HPKE_KEM_DHKEM_X25519_HKDF_SHA256
	dummyKdfId  = HPKE_KDF_HKDF_SHA256
	dummyAeadId = HPKE_AEAD_AES128_GCM

	// The maximum output length of the Extract() operation among the set of
	// supported KDFs. Currently this is 64, which is the number of extracted
	// bytes for HKDF-SHA512.
	MAX_HPKE_KDF_EXTRACT_LEN uint16 = 64
)

// assembleHpkeCipherSuite maps the codepoints for an HPKE ciphersuite to the
// ciphersuite's internal representation, verifying that the host supports the
// cipher suite.
//
// NOTE: draft-irtf-cfrg-hpke-05 reserves the `0x0000` code point for dummy KEM,
// KDF, and AEAD identifiers. `AssembleCipherSuite` interprets '0x000' as an
// invalid algorithm.
func assembleHpkeCipherSuite(kemId, kdfId, aeadId uint16) (hpke.CipherSuite, error) {
	if kemId != HPKE_KEM_DHKEM_X25519_HKDF_SHA256 &&
		kemId != HPKE_KEM_DHKEM_P256_HKDF_SHA256 {
		return hpke.CipherSuite{}, fmt.Errorf("KEM not supported")
	}

	if kdfId != HPKE_KDF_HKDF_SHA256 &&
		kdfId != HPKE_KDF_HKDF_SHA384 {
		return hpke.CipherSuite{}, fmt.Errorf("KDF not supported")
	}

	if aeadId != HPKE_AEAD_AES128_GCM &&
		aeadId != HPKE_AEAD_CHACHA20_POLY1305 {
		return hpke.CipherSuite{}, fmt.Errorf("AEAD not supported")
	}

	// Verify that the ciphersuite is supported by github.com/cisco/go-hpke and
	// return the ciphersuite's internal representation.
	return hpke.AssembleCipherSuite(hpke.KEMID(kemId), hpke.KDFID(kdfId), hpke.AEADID(aeadId))
}

// generateHpkeKeyPair generates a KEM key pair. Returns an error if the KEM
// named by `kemId` is not supported supported or reading from `rand` fails.
func generateHpkeKeyPair(rand io.Reader, kemId uint16) (*hpkePublicKey, *hpkeSecretKey, error) {
	// NOTE: Per the HPKE spec (draft-irtf-cfrg-hpke-05), the choice of KDF and
	// AEAD is irrelevant to key generation. Thus, it is safe to supply stand-in
	// values for these here.
	hpkeSuite, err := assembleHpkeCipherSuite(kemId, dummyKdfId, dummyAeadId)
	if err != nil {
		return nil, nil, err
	}

	// Generate the initial key material.
	ikm := make([]byte, hpkeSuite.KEM.PrivateKeySize())
	if n, err := rand.Read(ikm); err != nil {
		return nil, nil, err
	} else if n < len(ikm) {
		return nil, nil, fmt.Errorf("rand did not produce enough data")
	}

	// Derive the key pair.
	kemSk, kemPk, err := hpkeSuite.KEM.DeriveKeyPair(ikm)
	if err != nil {
		return nil, nil, err
	}

	return &hpkePublicKey{nil, kemPk, kemId}, &hpkeSecretKey{nil, kemSk, kemId}, nil
}

// hpkePublicKey represents a KEM public key.
type hpkePublicKey struct {
	raw   []byte
	kemPk hpke.KEMPublicKey
	kemId uint16
}

// unmarshalHpkePublicKey parses a serialized public key for the KEM algorithm
// identified by `kemId`.
func unmarshalHpkePublicKey(raw []byte, kemId uint16) (*hpkePublicKey, error) {
	// NOTE: Stand-in values for KDF/AEAD algorithms are ignored.
	hpkeSuite, err := assembleHpkeCipherSuite(kemId, dummyKdfId, dummyAeadId)
	if err != nil {
		return nil, err
	}
	kemPk, err := hpkeSuite.KEM.Deserialize(raw)
	if err != nil {
		return nil, err
	}
	return &hpkePublicKey{raw, kemPk, kemId}, nil
}

// marshaled returns the serialized public key.
func (pk *hpkePublicKey) marshaled() []byte {
	if pk.raw == nil {
		// NOTE: Stand-in values for KDF/AEAD algorithms are ignored.
		hpkeSuite, err := assembleHpkeCipherSuite(pk.kemId, dummyKdfId, dummyAeadId)
		if err != nil {
			// Handle unsupported HPKE ciphersuite as an internal bug. It
			// shouldn't be possible to construct an hpkePublicKey for a
			// ciphersuite we don't support.
			panic(fmt.Sprintf("internal error: %s", err))
		}
		pk.raw = hpkeSuite.KEM.Serialize(pk.kemPk)
	}
	return pk.raw
}

// hpkeSecretKey represents a KEM secret key.
type hpkeSecretKey struct {
	raw   []byte
	kemSk hpke.KEMPrivateKey
	kemId uint16
}

// unmarshalHpkeSecretKey parses a serialized secret key for the KEM algorithm
// identified by `kemId`.
func unmarshalHpkeSecretKey(raw []byte, kemId uint16) (*hpkeSecretKey, error) {
	// NOTE: Stand-in values for KDF/AEAD algorithms are ignored.
	hpkeSuite, err := assembleHpkeCipherSuite(kemId, dummyKdfId, dummyAeadId)
	if err != nil {
		return nil, err
	}
	kemSk, err := hpkeSuite.KEM.DeserializePrivate(raw)
	if err != nil {
		return nil, err
	}
	return &hpkeSecretKey{raw, kemSk, kemId}, nil
}

// marshaled returns the serialized secret key.
func (sk *hpkeSecretKey) marshaled() []byte {
	if sk.raw == nil {
		// NOTE: Stand-in values for KDF/AEAD algorithms are ignored.
		hpkeSuite, err := assembleHpkeCipherSuite(sk.kemId, dummyKdfId, dummyAeadId)
		if err != nil {
			// Handle unsupported HPKE ciphersuite as an internal bug. It
			// shouldn't be possible to construct an hpkePublicKey for a
			// ciphersuite we don't support.
			panic(fmt.Sprintf("internal error: %s", err))
		}
		sk.raw = hpkeSuite.KEM.SerializePrivate(sk.kemSk)
	}
	return sk.raw
}

// hpkeKdfDerive returns Expand(Extract(salt, ikm), info, Nh), where Expand(),
// Extract(), and Nh are KDF operations corresponding to `kdfId`.
func hpkeKdfDerive(ikm, salt, info []byte, kdfId uint16) ([]byte, error) {
	// NOTE: Stand-in values for KEM/AEAD algorithms are ignored.
	hpkeSuite, err := assembleHpkeCipherSuite(dummyKemId, kdfId, dummyAeadId)
	if err != nil {
		return nil, err
	}
	prk := hpkeSuite.KDF.Extract(salt, ikm)
	return hpkeSuite.KDF.Expand(prk, info, hpkeSuite.KDF.OutputSize()), nil
}
