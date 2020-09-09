// Copyright 2020 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package ech

import (
	"fmt"
	"io"

	"github.com/cisco/go-hpke"
)

const (
	// Constants for HPKE operations
	echHpkeInfoInnerDigest     = "tls13 ech inner digest"
	echHpkeInfoConfigId        = "tls13 ech config id"
	echHpkeInfoSetup           = "tls13 ech"
	echHpkeInfoSetupHrr        = "tls13 ech hrr"
	echHpkeHrrKeyExportContext = "tls13 ech hrr key"
	echHpkeHrrKeyId            = "hrr key"
	echHpkeHrrKeyLen           = 16
)

// Content represents an HPKE context, as specified in irtf-cfrg-hpke-05.
type Context struct {
	enc    *hpke.EncryptContext
	dec    *hpke.DecryptContext
	client bool
	Suite  CipherSuite
}

// SetupClientContext generates the client's HPKE context for use with the ECH
// extension. Returns the context and corresponding encapsulated key `enc`.  If
// `hrrPsk` is set, then SetupPSKS() is used to generate the context.
// Otherwise, SetupBaseR() is used. (See irtf-cfrg-hpke-05 for details.)
func (config *Config) SetupClientContext(hrrPsk []byte, rand io.Reader) (context *Context, enc []byte, err error) {
	// Ensure we know how to proceed. Currently only draft-ietf-tls-esni-08 is
	// supported.
	if config.Version != VersionDraft08 {
		return nil, nil, fmt.Errorf("version not supported")
	}

	if config.pk == nil {
		// Parse the public key.
		config.pk, err = unmarshalHpkePublicKey(config.contents.PublicKey, config.contents.KemId)
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing public key: %s", err)
		}
	}

	// Pick a ciphersuite supported by both the client and client-facing server.
	suite, err := config.negotiateCipherSuite()
	if err != nil {
		return nil, nil, err
	}

	hpkeSuite, err := assembleHpkeCipherSuite(config.pk.kemId, suite.KdfId, suite.AeadId)
	if err != nil {
		return nil, nil, err
	}

	var encryptContext *hpke.EncryptContext
	if hrrPsk != nil {
		enc, encryptContext, err = hpke.SetupPSKS(hpkeSuite, rand, config.pk.kemPk, hrrPsk, []byte(echHpkeHrrKeyId), []byte(echHpkeInfoSetupHrr))
		if err != nil {
			return nil, nil, err
		}
	} else {
		enc, encryptContext, err = hpke.SetupBaseS(hpkeSuite, rand, config.pk.kemPk, []byte(echHpkeInfoSetup))
		if err != nil {
			return nil, nil, err
		}
	}

	return &Context{encryptContext, nil, true, suite}, enc, nil
}

// SetupServerContext computes the HPKE context used by the server in the ECH
// extension.  If `hrrPsk` is set, then SetupPSKS() is used to generate the
// context.  Otherwise, SetupBaseR() is used. (See irtf-cfrg-hpke-05 for
// details.)
func (key *Key) SetupServerContext(enc, hrrPsk []byte, suite CipherSuite) (*Context, error) {
	hpkeSuite, err := assembleHpkeCipherSuite(key.sk.kemId, suite.KdfId, suite.AeadId)
	if err != nil {
		return nil, err
	}

	var decryptContext *hpke.DecryptContext
	if hrrPsk != nil {
		decryptContext, err = hpke.SetupPSKR(hpkeSuite, key.sk.kemSk, enc, hrrPsk, []byte(echHpkeHrrKeyId), []byte(echHpkeInfoSetupHrr))
		if err != nil {
			return nil, err
		}
	} else {
		decryptContext, err = hpke.SetupBaseR(hpkeSuite, key.sk.kemSk, enc, []byte(echHpkeInfoSetup))
		if err != nil {
			return nil, err
		}
	}
	return &Context{nil, decryptContext, false, suite}, nil
}

// UnmarshalServerContext parses the server's HPKE context.
func UnmarshalServerContext(raw []byte) (*Context, error) {
	decryptContext, err := hpke.UnmarshalDecryptContext(raw)
	if err != nil {
		return nil, err
	}

	suite := CipherSuite{uint16(decryptContext.KDFID), uint16(decryptContext.AEADID)}
	if !isCipherSuiteSupported(suite) {
		return nil, fmt.Errorf("cipher suite not supported")
	}

	return &Context{nil, decryptContext, false, suite}, nil
}

// MarshalServer serializes the server's HPKE context.
func (context *Context) MarshalServer() ([]byte, error) {
	return context.dec.Marshal()
}

// Encrypt seals the ClientHelloInner `inner` in the client's HPKE context and
// returns the payload of the "encrypted_client_hello" extension.
func (context *Context) Encrypt(inner []byte) (payload []byte) {
	if !context.client {
		panic("Encrypt() is not defined for server")
	}

	return context.enc.Seal(nil, inner)
}

// Decrypt opens `payload`, the payload of the "encrypted_client_hello"
// extension.
func (context *Context) Decrypt(payload []byte) (inner []byte, err error) {
	if context.client {
		panic("Decrypt() is not defined for client")
	}
	return context.dec.Open(nil, payload)
}

// ExportHRRKey exports the PSK used to bind the first ClientHelloOuter to the
// second in case the backend server sends a HelloRetryRequest.
func (context *Context) ExportHRRKey() []byte {
	if context.client {
		return context.enc.Export([]byte(echHpkeHrrKeyExportContext), echHpkeHrrKeyLen)
	}
	return context.dec.Export([]byte(echHpkeHrrKeyExportContext), echHpkeHrrKeyLen)
}

// DeriveInnerDigest computes the value of OuterExtensions.hash for the
// "outer_extension" extension.
func (context *Context) DeriveInnerDigest(inner []byte) []byte {
	out, err := hpkeKdfDerive(inner, nil, []byte(echHpkeInfoInnerDigest), context.Suite.KdfId)
	if err != nil {
		panic(fmt.Sprintf("internal error: %s", err))
	}
	return out
}
