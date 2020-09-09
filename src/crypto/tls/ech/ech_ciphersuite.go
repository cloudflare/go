// Copyright 2020 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package ech

import (
	"fmt"
)

// CipherSuite represents an ECH ciphersuite, a KDF/AEAD algorithm pair.
//
// NOTE: This is different from an HPKE ciphersuite, which represents a KEM,
// KDF, and an AEAD algorithm.
type CipherSuite struct {
	KdfId, AeadId uint16
}

// IsSupported returns true if the host supports the KEM and at least one
// ECH ciphersuite.
func (config *Config) IsSupported() bool {
	_, err := config.negotiateCipherSuite()
	if err != nil || !isKemSupported(config.contents.KemId) {
		return false
	}
	return true
}

// IsPeerCipherSuiteSupported returns true if this configuration supports the
// given ECH ciphersuite.
func (config *Config) IsPeerCipherSuiteSupported(suite CipherSuite) bool {
	for _, configSuite := range config.CipherSuites() {
		if suite == configSuite {
			return true
		}
	}
	return false
}

// negotiateCipherSuite returns the first ciphersuite indicated by this
// configuration that is supported by the host.
func (config *Config) negotiateCipherSuite() (CipherSuite, error) {
	for i, _ := range config.contents.CipherSuites {
		if isCipherSuiteSupported(config.contents.CipherSuites[i]) {
			return config.contents.CipherSuites[i], nil
		}
	}
	return CipherSuite{}, fmt.Errorf("could not negotiate a ciphersuite")
}

// isCipherSuiteSupported returns true if the host supports the given ECH
// ciphersuite.
func isCipherSuiteSupported(suite CipherSuite) bool {
	// NOTE: Stand-in values for KEM algorithm is ignored.
	_, err := assembleHpkeCipherSuite(dummyKemId, suite.KdfId, suite.AeadId)
	return err == nil
}

// isKemSupported returns true if the host supports the given KEM.
func isKemSupported(kemId uint16) bool {
	// NOTE: Stand-in values for KDF/AEAD algorithms are ignored.
	_, err := assembleHpkeCipherSuite(kemId, dummyKdfId, dummyAeadId)
	return err == nil
}
