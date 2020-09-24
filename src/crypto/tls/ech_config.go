// Copyright 2020 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package tls

import (
	"crypto/tls/internal/hpke"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

var (
	echUnrecognizedVersionError = errors.New("unrecognized version")
)

// ECHConfig represents an ECH configuration.
type ECHConfig struct {
	pk  hpke.KEMPublicKey
	raw []byte

	// Parsed from raw
	version           uint16
	rawPublicName     []byte
	rawPublicKey      []byte
	kemId             uint16
	suites            []echCipherSuite
	maxNameLen        uint16
	ignoredExtensions []byte
}

// UnmarshalECHConfigs parses a sequence of ECH configurations.
func UnmarshalECHConfigs(raw []byte) ([]ECHConfig, error) {
	var err error
	var config ECHConfig
	configs := make([]ECHConfig, 0)
	s := cryptobyte.String(raw)
	var t, contents cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&t) || !s.Empty() {
		return configs, errors.New("error parsing configs")
	}
	raw = raw[2:]
	for !t.Empty() {
		l := len(t)
		if !t.ReadUint16(&config.version) ||
			!t.ReadUint16LengthPrefixed(&contents) {
			return nil, errors.New("error parsing config")
		}
		n := l - len(t)
		if config.version == extensionECH {
			if !readConfigContents(&contents, &config) {
				return nil, errors.New("error parsing config contents")
			}
			config.pk, err = echUnmarshalHpkePublicKey(config.rawPublicKey, config.kemId)
			if err != nil {
				return nil, err
			}
			config.raw = raw[:n]
			configs = append(configs, config)
		}
		raw = raw[n:]
	}
	return configs, nil
}

func echUnmarshalConfig(raw []byte) (*ECHConfig, error) {
	var err error
	config := new(ECHConfig)
	s := cryptobyte.String(raw)
	var contents cryptobyte.String
	if !s.ReadUint16(&config.version) ||
		!s.ReadUint16LengthPrefixed(&contents) ||
		!s.Empty() {
		return nil, errors.New("error parsing config")
	}
	if config.version != extensionECH {
		return nil, echUnrecognizedVersionError
	}
	if !readConfigContents(&contents, config) || !s.Empty() {
		return nil, errors.New("error parsing config contents")
	}
	config.pk, err = echUnmarshalHpkePublicKey(config.rawPublicKey, config.kemId)
	if err != nil {
		return nil, err
	}
	config.raw = raw
	return config, nil
}

func readConfigContents(contents *cryptobyte.String, config *ECHConfig) bool {
	var t cryptobyte.String
	if !contents.ReadUint16LengthPrefixed(&t) ||
		!t.ReadBytes(&config.rawPublicName, len(t)) ||
		!contents.ReadUint16LengthPrefixed(&t) ||
		!t.ReadBytes(&config.rawPublicKey, len(t)) ||
		!contents.ReadUint16(&config.kemId) ||
		!contents.ReadUint16LengthPrefixed(&t) ||
		len(t)%4 != 0 {
		return false
	}

	for !t.Empty() {
		var kdfId, aeadId uint16
		if !t.ReadUint16(&kdfId) || !t.ReadUint16(&aeadId) {
			// This indicates an internal bug.
			panic("internal error while parsing contents.cipher_suites")
		}
		config.suites = append(config.suites, echCipherSuite{kdfId, aeadId})
	}

	if !contents.ReadUint16(&config.maxNameLen) ||
		!contents.ReadUint16LengthPrefixed(&t) ||
		!t.ReadBytes(&config.ignoredExtensions, len(t)) ||
		!contents.Empty() {
		return false
	}
	return true
}

// setupClientContext generates the client's HPKE context for use with the ECH
// extension. Returns the context and corresponding encapsulated key. If hrrPsK
// is set, then "SetupPSKS()" is used to generate the context. Otherwise,
// "SetupBaseS()" is used. (See irtf-cfrg-hpke-05 for details.)
func (config *ECHConfig) setupClientContext(hrrPsk []byte, rand io.Reader) (ctx *echContext, enc []byte, err error) {
	suite, err := config.selectCipherSuite()
	if err != nil {
		return nil, nil, err
	}

	hpkeSuite, err := hpkeAssembleCipherSuite(config.kemId, suite.kdfId, suite.aeadId)
	if err != nil {
		return nil, nil, err
	}

	info := append(append([]byte(echHpkeInfoSetup), 0), config.raw...)
	var encryptedContext *hpke.EncryptContext
	if hrrPsk != nil {
		enc, encryptedContext, err = hpke.SetupPSKS(hpkeSuite, rand, config.pk, hrrPsk, []byte(echHpkeHrrKeyId), info)
		if err != nil {
			return nil, nil, err
		}
	} else {
		enc, encryptedContext, err = hpke.SetupBaseS(hpkeSuite, rand, config.pk, info)
		if err != nil {
			return nil, nil, err
		}
	}
	return &echContext{encryptedContext, nil, true, hpkeSuite}, enc, nil
}

// isSupported returns true if the caller supports the KEM and at least one ECH
// ciphersuite indicated by this configuration.
func (config *ECHConfig) isSupported() bool {
	_, err := config.selectCipherSuite()
	if err != nil || !echIsKemSupported(config.kemId) {
		return false
	}
	return true
}

// isPeerCipherSuiteSupported returns true if this configuration indicates
// support for the given ciphersuite.
func (config *ECHConfig) isPeerCipherSuiteSupported(suite echCipherSuite) bool {
	for _, configSuite := range config.suites {
		if suite == configSuite {
			return true
		}
	}
	return false
}

// selectCipherSuite returns the first ciphersuite indicated by this
// configuration that is supported by the caller.
func (config *ECHConfig) selectCipherSuite() (echCipherSuite, error) {
	for i := range config.suites {
		if echIsCipherSuiteSupported(config.suites[i]) {
			return config.suites[i], nil
		}
	}
	return echCipherSuite{}, fmt.Errorf("could not negotiate a ciphersuite")
}
