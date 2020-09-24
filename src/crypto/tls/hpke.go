// Copyright 2020 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package tls

import (
	"crypto/tls/internal/hpke"
	"errors"
	"fmt"
)

const (
	// Supported KEMs
	hpkeKemDhKemX25519HkdfSha256 = uint16(hpke.DHKEM_X25519)
	hpkeKemDhKemP256kdfSha256    = uint16(hpke.DHKEM_P256)

	// Supported KDFs
	hpkeKdfHkdfSha256 = uint16(hpke.KDF_HKDF_SHA256)
	hpkeKdfHkdfSha384 = uint16(hpke.KDF_HKDF_SHA384)

	// Supported AEADs
	hpkeAeadAes128Gcm        = uint16(hpke.AEAD_AESGCM128)
	hpkeAeadChaCha20Poly1305 = uint16(hpke.AEAD_CHACHA20POLY1305)

	// Stand-in values for algorithms that are unknown prior to a particular
	// operation. Note that these are mandatory-to-implement algorithms for ECH
	// since draft-ietf-tls-esni-08.
	//
	// There is a slight mismatch between the API exported by HPKE and the API
	// required to implement the ECH logic in the TLS stack. Namely, an "HPKE
	// ciphersuite" is a (KEM, KDF, AEAD) triple, and as such, the API of the
	// HPKE implementation we use, github.com/cisco/go-hpke, presumes all three
	// algorithms are known prior to any HPKE operation. In contrast, an "ECH
	// ciphersuite" is a (KDF, AEAD) pair, meaning the KDF and AEAD may not be
	// known when doing a KEM operation, e.g., generating a KEM key pair. This
	// library provides a thin wrapper around github.com/cisco/go-hpke that
	// resolves this mismatch.
	dummyKemId  = hpkeKemDhKemX25519HkdfSha256
	dummyKdfId  = hpkeKdfHkdfSha256
	dummyAeadId = hpkeAeadAes128Gcm

	// The ciphertext expansion incurred by the AEAD identified by dummyAeadId.
	dummyAeadOverheadLen = 16

	// The output size of "Expand()" for the KDF identified by dummyKdfId.
	dummyKdfOutputLen = 32
)

func init() {
	// Ensure that this package supports the mandatory-to-implement cipher suite
	// for the ECH extension.
	_, err := hpkeAssembleCipherSuite(hpkeKemDhKemX25519HkdfSha256, hpkeKdfHkdfSha256, hpkeAeadAes128Gcm)
	if err != nil {
		panic(fmt.Errorf("internal error: ech: failed to assemble MTI cipher suite: %s", err))
	}
}

// hpkeAssembleHpkeCipherSuite maps the codepoints for an HPKE ciphersuite to
// the ciphersuite's internal representation, verifying that the host supports
// the cipher suite.
//
// NOTE: draft-irtf-cfrg-hpke-05 reserves the `0x0000` code point for dummy KEM,
// KDF, and AEAD identifiers. `AssembleCipherSuite` interprets '0x0000' as an
// invalid algorithm.
func hpkeAssembleCipherSuite(kemId, kdfId, aeadId uint16) (hpke.CipherSuite, error) {
	if kemId != hpkeKemDhKemX25519HkdfSha256 &&
		kemId != hpkeKemDhKemP256kdfSha256 {
		return hpke.CipherSuite{}, errors.New("KEM not supported")
	}

	if kdfId != hpkeKdfHkdfSha256 &&
		kdfId != hpkeKdfHkdfSha384 {
		return hpke.CipherSuite{}, errors.New("KDF not supported")
	}

	if aeadId != hpkeAeadAes128Gcm &&
		aeadId != hpkeAeadChaCha20Poly1305 {
		return hpke.CipherSuite{}, errors.New("AEAD not supported")
	}

	// Verify that the ciphersuite is supported by github.com/cisco/go-hpke and
	// return the ciphersuite's internal representation.
	return hpke.AssembleCipherSuite(hpke.KEMID(kemId), hpke.KDFID(kdfId), hpke.AEADID(aeadId))
}
