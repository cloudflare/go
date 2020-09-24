// Copyright 2020 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package tls

import (
	"crypto/rand"
	"crypto/tls/internal/hpke"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

const (
	echTestBackendServerName      = "example.com"
	echTestClientFacingServerName = "cloudflare-esni.com"

	maxConfigIdLen = 255
)

// The client's root CA certificate.
const echTestCertRootPEM = `
-----BEGIN CERTIFICATE-----
MIICQTCCAeigAwIBAgIUYGSqOFcpxSleCzSCaveKL8lV4N0wCgYIKoZIzj0EAwIw
fzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xHzAdBgNVBAoTFkludGVybmV0IFdpZGdldHMsIEluYy4xDDAK
BgNVBAsTA1dXVzEUMBIGA1UEAxMLZXhhbXBsZS5jb20wHhcNMjAwOTIyMTcwNjAw
WhcNMjUwOTIxMTcwNjAwWjB/MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZv
cm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEfMB0GA1UEChMWSW50ZXJuZXQg
V2lkZ2V0cywgSW5jLjEMMAoGA1UECxMDV1dXMRQwEgYDVQQDEwtleGFtcGxlLmNv
bTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNcFaBtPRgekRBKTBvuKdTy3raqs
4IizMLFup434MfQ5oH71mYpKndfBzxcZDTMYeocKlt1pVYwvZ3ZdpRsW6yWjQjBA
MA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQ2GJIW
+4m3/qpkage5tEvMg3NwPTAKBggqhkjOPQQDAgNHADBEAiB6J8UqRvdhLOiaDYqH
KG+TuveHOqlfQqQgXo4/hNKMiAIgV79TTPHu+Ymn/tcCy9LVWZcpgnCEjrZi0ou5
et8BX9s=
-----END CERTIFICATE-----`

// Certificate of the client-facing server. The server name is
// "cloudflare-esni.com".
const echTestCertClientFacingPEM = `
-----BEGIN CERTIFICATE-----
MIICIjCCAcigAwIBAgIUCXySp2MadlDlcvFrSm4BtLUY70owCgYIKoZIzj0EAwIw
fzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xHzAdBgNVBAoTFkludGVybmV0IFdpZGdldHMsIEluYy4xDDAK
BgNVBAsTA1dXVzEUMBIGA1UEAxMLZXhhbXBsZS5jb20wHhcNMjAwOTIyMTcxMDAw
WhcNMjEwOTIyMTcxMDAwWjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7nP/
Txinb0JPE/xdjv5d3zrWJqXo7qwP67oVaMKJp5ausJ+0IZfiMWz8pa6T7pyyLrC5
xvQNkfVkpP9/FxmNFaOBoDCBnTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYI
KwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFNN7Afv+
CgPAxRr4QdZn8JFvQ9nTMB8GA1UdIwQYMBaAFDYYkhb7ibf+qmRqB7m0S8yDc3A9
MB4GA1UdEQQXMBWCE2Nsb3VkZmxhcmUtZXNuaS5jb20wCgYIKoZIzj0EAwIDSAAw
RQIgZ4VlBtjTRludP/JwfaNQyGKZFWFqRsECvGPbk+ZHLZwCIQCTjuMAFrnjf/j5
3RNw67l7+QQPrmurSO86l1IlDWNtcA==
-----END CERTIFICATE-----`

// Signing key of the client-facing server.
const echTestKeyClientFacingPEM = `
-----BEGIN PRIVATE KEY-----
MHcCAQEEIPpCcU8mu+h4xHAm18NJvn73Ko9fjH9QxDCpRt7kCIq9oAoGCCqGSM49
AwEHoUQDQgAE7nP/Txinb0JPE/xdjv5d3zrWJqXo7qwP67oVaMKJp5ausJ+0IZfi
MWz8pa6T7pyyLrC5xvQNkfVkpP9/FxmNFQ==
-----END PRIVATE KEY-----`

// Certificate of the backend server. The server name is "example.com".
const echTestCertBackendPEM = `
-----BEGIN CERTIFICATE-----
MIICGTCCAcCgAwIBAgIUQJSSdOZs9wag1Toanlt9lol0uegwCgYIKoZIzj0EAwIw
fzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xHzAdBgNVBAoTFkludGVybmV0IFdpZGdldHMsIEluYy4xDDAK
BgNVBAsTA1dXVzEUMBIGA1UEAxMLZXhhbXBsZS5jb20wHhcNMjAwOTIyMTcwOTAw
WhcNMjEwOTIyMTcwOTAwWjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElq+q
E01Z87KIPHWdEAk0cWssHkRnS4aQCDfstoxDIWQ4rMwHvrWGFy/vytRwyjhHuX9n
tc5ArCpwbAmY+oW/46OBmDCBlTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYI
KwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFPz9Ct9U
EIjBEcUpv/yxHYccUDo1MB8GA1UdIwQYMBaAFDYYkhb7ibf+qmRqB7m0S8yDc3A9
MBYGA1UdEQQPMA2CC2V4YW1wbGUuY29tMAoGCCqGSM49BAMCA0cAMEQCICDBEzzE
DF529x9Z4BkOKVxNDicfWSjxrcMohevjeCWDAiBaxXS5+6I2fcred0JGMsJgo7ts
S8GYhuKE99mQA0/mug==
-----END CERTIFICATE-----`

// Signing key of the backend server.
const echTestKeyBackendPEM = `
-----BEGIN PRIVATE KEY-----
MHcCAQEEIIJsLXmfzw6FDlqyRRLhY6lVB6ws5ewjUQjnS4DXsQ60oAoGCCqGSM49
AwEHoUQDQgAElq+qE01Z87KIPHWdEAk0cWssHkRnS4aQCDfstoxDIWQ4rMwHvrWG
Fy/vytRwyjhHuX9ntc5ArCpwbAmY+oW/4w==
-----END PRIVATE KEY-----`

// The sequence of ECH configurations used by the client.
const echTestConfigs = `-----BEGIN ECH CONFIGS-----
AMf+CABPABNjbG91ZGZsYXJlLWVzbmkuY29tACD683Skz2S4bDVHT+GAv5KAUyyl
3r5cLeq4qvMBI9ibPAAgABAAAQABAAEAAwACAAEAAgADAAAAAP4IAHAAE2Nsb3Vk
ZmxhcmUtZXNuaS5jb20AQQSZfpA6fzxJ6D8QM/skU24lfUPjdeVWBNqPFLLRjT8m
jDldpNzqsIwgmnNrD2uY3nhSdLVnLJho07qFju+2VmjYABAAEAABAAEAAQADAAIA
AQACAAMAAAAA
-----END ECH CONFIGS-----`

// An invalid sequence of ECH configurations.
const echTestInvalidConfigs = `-----BEGIN ECH CONFIGS-----
AFP+CABPABNjbG91ZGZsYXJlLWVzbmkuY29tACBcOATtuDyCM0u6yNprD7YeSJH9
gQYYei3M1ZzJe2JbTAAgABAAAQABAAEAAwACAAEAAgADAAAAAA==
-----END ECH CONFIGS-----`

// The ECH keys corresponding to echTestConfigs, used by the client-facing
// server.
const echTestKeys = `-----BEGIN ECH KEYS-----
ACATTNkMz0kX/6CSrh/KlO82oKyy/JIwBwqb61sKbzKrigBT/ggATwATY2xvdWRm
bGFyZS1lc25pLmNvbQAg+vN0pM9kuGw1R0/hgL+SgFMspd6+XC3quKrzASPYmzwA
IAAQAAEAAQABAAMAAgABAAIAAwAAAAAAIBhXMi4tyQeKOjmFeDYWmebWgVUj+IQd
Ir/qaiw2V5bIAHT+CABwABNjbG91ZGZsYXJlLWVzbmkuY29tAEEEmX6QOn88Seg/
EDP7JFNuJX1D43XlVgTajxSy0Y0/Jow5XaTc6rCMIJpzaw9rmN54UnS1ZyyYaNO6
hY7vtlZo2AAQABAAAQABAAEAAwACAAEAAgADAAAAAA==
-----END ECH KEYS-----`

// echKeySet implements the ECHProvider interface for a sequence of ECH keys.
type echKeySet struct {
	// The serialized ECHConfigs, in order of the server's preference.
	configs []byte

	// Maps a configuration identifier to its secret key.
	sk map[[maxConfigIdLen + 1]byte]echKey
}

// echNewKeySet constructs an echKeySet.
func echNewKeySet(keys []echKey) (*echKeySet, error) {
	keySet := new(echKeySet)
	keySet.sk = make(map[[maxConfigIdLen + 1]byte]echKey)
	configs := make([]byte, 0)
	for _, key := range keys {
		// Compute the set of KDF algorithms supported by this configuration.
		kdfIds := make(map[uint16]bool)
		for _, suite := range key.config.suites {
			kdfIds[suite.kdfId] = true
		}

		// Compute the configuration identifier for each KDF.
		for kdfId, _ := range kdfIds {
			kdf, err := echCreateHpkeKdf(kdfId)
			if err != nil {
				return nil, err
			}
			configId := kdf.Expand(kdf.Extract(nil, key.config.raw), []byte(echHpkeInfoConfigId), kdf.OutputSize())
			var b cryptobyte.Builder
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(configId)
			})
			var id [maxConfigIdLen + 1]byte // Initialized to zero
			copy(id[:], b.BytesOrPanic())
			keySet.sk[id] = key
		}

		configs = append(configs, key.config.raw...)
	}

	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(configs)
	})
	keySet.configs = b.BytesOrPanic()

	return keySet, nil
}

// GetContext is required by the ECHProvider interface.
func (keySet *echKeySet) GetContext(rawHandle, hrrPsk []byte, version uint16) (res ECHProviderResult) {
	// Ensure we know how to proceed. Currently only draft-ietf-tls-esni-08 is
	// supported.
	if version != extensionECH {
		res.Status = ECHProviderAbort
		res.Alert = uint8(alertInternalError)
		res.Error = errors.New("version not supported")
		return // Abort
	}

	// Parse the handle.
	s := cryptobyte.String(rawHandle)
	handle := new(echContextHandle)
	if !echReadContextHandle(&s, handle) || !s.Empty() {
		res.Status = ECHProviderAbort
		res.Alert = uint8(alertIllegalParameter)
		res.Error = errors.New("error parsing context handle")
		return // Abort
	}
	handle.raw = rawHandle

	// Look up the secret key for the configuration indicated by the client.
	var id [maxConfigIdLen + 1]byte // Initialized to zero
	var b cryptobyte.Builder
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(handle.configId)
	})
	copy(id[:], b.BytesOrPanic())
	key, ok := keySet.sk[id]
	if !ok {
		res.Status = ECHProviderReject
		res.RetryConfigs = keySet.configs
		return // Reject
	}

	// Ensure that support for the selected ciphersuite is indicated by the
	// configuration.
	suite := handle.suite
	if !key.config.isPeerCipherSuiteSupported(suite) {
		res.Status = ECHProviderAbort
		res.Alert = uint8(alertIllegalParameter)
		res.Error = errors.New("peer cipher suite is not supported")
		return // Abort
	}

	// Ensure the version indicated by the client matches the version supported
	// by the configuration.
	if version != key.config.version {
		res.Status = ECHProviderAbort
		res.Alert = uint8(alertIllegalParameter)
		res.Error = errors.New("peer version not supported")
		return // Abort
	}

	// Compute the decryption context.
	context, err := key.setupServerContext(handle.enc, hrrPsk, suite)
	if err != nil {
		res.Status = ECHProviderAbort
		res.Alert = uint8(alertInternalError)
		res.Error = err
		return // Abort
	}

	// Serialize the decryption context.
	res.Context, err = context.marshalServer()
	if err != nil {
		res.Status = ECHProviderAbort
		res.Alert = uint8(alertInternalError)
		res.Error = err
		return // Abort
	}

	res.Status = ECHProviderSuccess
	// Send retry configs just in case the caller needs to reject.
	res.RetryConfigs = keySet.configs
	return // May accept
}

// echKey represents an ECH key and its corresponding configuration. The
// encoding of an ECH Key has following structure (in TLS syntax):
//
// struct {
//     opaque private_key<0..2^16-1>
//     uint16 length<0..2^16-1> // length of config
//     ECHConfig config;        // as defined in draft-ietf-tls-esni-08
// } ECHKey;
//
// NOTE(cjpatton): This format is not specified in the ECH draft.
type echKey struct {
	config ECHConfig
	sk     hpke.KEMPrivateKey
}

// echUnmarshalKeys parses a sequence of ECH keys.
func echUnmarshalKeys(raw []byte) ([]echKey, error) {
	s := cryptobyte.String(raw)
	keys := make([]echKey, 0)
	var key echKey
	for !s.Empty() {
		var rawSecretKey, rawConfig cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&rawSecretKey) ||
			!s.ReadUint16LengthPrefixed(&rawConfig) {
			return nil, fmt.Errorf("error parsing key")
		}
		config, err := echUnmarshalConfig(rawConfig)
		if err != nil {
			if err == echUnrecognizedVersionError {
				// Skip config with unrecognized version.
				continue
			}
			return nil, err
		}
		key.config = *config
		key.sk, err = echUnmarshalHpkeSecretKey(rawSecretKey, key.config.kemId)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// setupServerContext computes the HPKE context used by the server in the ECH
// extension. If hrrPsk is set, then "SetupPSKR()" is used to generate the
// context. Otherwise, "SetupBaseR()" is used. (See irtf-cfrg-hpke-05 for
// details.)
func (key *echKey) setupServerContext(enc, hrrPsk []byte, suite echCipherSuite) (*echContext, error) {
	hpkeSuite, err := hpkeAssembleCipherSuite(key.config.kemId, suite.kdfId, suite.aeadId)
	if err != nil {
		return nil, err
	}

	info := append(append([]byte(echHpkeInfoSetup), 0), key.config.raw...)
	var decryptechContext *hpke.DecryptContext
	if hrrPsk != nil {
		decryptechContext, err = hpke.SetupPSKR(hpkeSuite, key.sk, enc, hrrPsk, []byte(echHpkeHrrKeyId), info)
		if err != nil {
			return nil, err
		}
	} else {
		decryptechContext, err = hpke.SetupBaseR(hpkeSuite, key.sk, enc, info)
		if err != nil {
			return nil, err
		}
	}
	return &echContext{nil, decryptechContext, false, hpkeSuite}, nil
}

// echTestProviderAlwaysAbort mocks an ECHProvider that, in response to any
// request, sets an alert and returns an error. The client-facing server must
// abort the handshake.
type echTestProviderAlwaysAbort struct{}

// Required by the ECHProvider interface.
func (p echTestProviderAlwaysAbort) GetContext(_, _ []byte, _ uint16) (res ECHProviderResult) {
	res.Status = ECHProviderAbort
	res.Alert = uint8(alertInternalError)
	res.Error = errors.New("provider failed")
	return // Abort
}

// echTestProviderAlwaysReject simulates fallover of the ECH provider. In
// response to any query, it rejects without sending retry configurations., in response to any
type echTestProviderAlwaysReject struct{}

// Required by the ECHProvider interface.
func (p echTestProviderAlwaysReject) GetContext(_, _ []byte, _ uint16) (res ECHProviderResult) {
	res.Status = ECHProviderReject
	return // Reject without retry configs
}

// echTestProviderRejectAfterHRR accepts the client ECH configuration on the
// first call, but fails on further invocations. This simulates a scenario where
// the server performs key rotation while a HRR was triggered. Even if the
// client uses the same ECHConfig after a HRR, the server will be unable to
// process it.
type echTestProviderRejectAfterHRR struct {
	keySet      *echKeySet // Used on the first call
	invocations int
}

// Required by the ECHProvider interface.
func (p *echTestProviderRejectAfterHRR) GetContext(handle, hrrPsk []byte, version uint16) (res ECHProviderResult) {
	p.invocations++
	if p.invocations > 1 {
		res.Status = ECHProviderReject
		res.RetryConfigs = []byte("invalid config")
		return // Reject
	}
	return p.keySet.GetContext(handle, hrrPsk, version)
}

func echTestLoadConfigs(pemData string) []ECHConfig {
	block, rest := pem.Decode([]byte(pemData))
	if block == nil || block.Type != "ECH CONFIGS" || len(rest) > 0 {
		panic("pem decoding fails")
	}

	configs, err := UnmarshalECHConfigs(block.Bytes)
	if err != nil {
		panic(err)
	}

	return configs
}

func echTestLoadKeySet() *echKeySet {
	block, rest := pem.Decode([]byte(echTestKeys))
	if block == nil || block.Type != "ECH KEYS" || len(rest) > 0 {
		panic("pem decoding fails")
	}

	keys, err := echUnmarshalKeys(block.Bytes)
	if err != nil {
		panic(err)
	}

	keySet, err := echNewKeySet(keys)
	if err != nil {
		panic(err)
	}

	return keySet
}

type echTestCase struct {
	name string

	// expected outcomes
	expectClientAbort       bool // client aborts
	expectServerAbort       bool // server aborts
	expectOffered           bool // server indicates that ECH was offered
	expectBypassed          bool // server indciates that ECH was bypassed
	expectAccepted          bool // server indicates ECH acceptance
	expectRejected          bool // server indicates ECH rejection
	expectGrease            bool // server indicates dummy ECH was detected
	expectBackendServerName bool // client verified backend server name

	// client config
	clientEnabled        bool // client enables ECH
	clientInvalidConfigs bool // client offers ECH with invalid config
	clientNoConfigs      bool // client sends dummy ECH if ECH enabled
	clientInvalidVersion bool // client does not offer 1.3

	// server config
	serverEnabled                bool // server enables ECH
	serverProviderAlwaysAbort    bool // ECH provider always aborts
	serverProviderAlwaysReject   bool // ECH provider always rejects
	serverProviderRejectAfterHRR bool // ECH provider rejects after HRR
	serverInvalidVersion         bool // server does not offer 1.3

	// code path triggers
	triggerHRR                    bool // server triggers HRR
	triggerECHBypassAfterHRR      bool // client bypasses after HRR
	triggerECHBypassBeforeHRR     bool // client bypasses before HRR
	triggerIllegalHandleAfterHRR  bool // client sends illegal ECH extension after HRR
	triggerOuterExtMany           bool // client sends many (not just one) outer extensions
	triggerOuterExtIncorrectOrder bool // client sends malformed outer extensions
	triggerOuterExtNone           bool // client does not incorporate outer extensions
	triggerPayloadDecryptError    bool // client sends inauthentic ciphertext
}

// TODO(cjpatton): Add test cases for PSK interactions:
//  - ECH bypassed, backend server consumes early data (baseline test config)
//  - ECH accepted, backend server consumes early data
//  - ECH rejected, client-facing server ignores early data intended for backend
var echTestCases = []echTestCase{
	{
		// The client offers ECH and it is accepted by the server
		name:                    "success / accepted",
		expectOffered:           true,
		expectAccepted:          true,
		expectBackendServerName: true,
		clientEnabled:           true,
		serverEnabled:           true,
	},
	{
		// The client bypasses ECH, i.e., it neither offers ECH nor sends a
		// dummy ECH extension.
		name:                    "success / bypassed: not offered",
		expectBypassed:          true,
		expectBackendServerName: true,
		serverEnabled:           true,
	},
	{
		// The client sends dummy (i.e., "GREASEd") ECH. The server sends retry
		// configs in case the client meant to offer ECH. The client does not
		// signal rejection, so the server concludes ECH was not offered.
		name:                    "success / bypassed: grease",
		expectGrease:            true,
		expectBackendServerName: true,
		clientEnabled:           true,
		clientNoConfigs:         true,
		serverEnabled:           true,
	},
	{
		// The client sends dummy ECH because it has enabled ECH but not TLS
		// 1.3. The server sends retry configs in case the client meant to offer
		// ECH. The client does not signal rejection, so the server concludes
		// ECH was not offered.
		name:                    "success / bypassed: client invalid version",
		expectGrease:            true,
		expectBackendServerName: true,
		clientInvalidVersion:    true,
		clientEnabled:           true,
		serverEnabled:           true,
	},
	{
		// The client offers ECH with an invalid (e.g., stale) config. The
		// server sends retry configs. The client signals rejection by sending
		// an "ech_required" alert.
		name:                 "success / rejected: invalid config",
		expectOffered:        true,
		expectRejected:       true,
		expectClientAbort:    true,
		expectServerAbort:    true,
		clientInvalidConfigs: true,
		clientEnabled:        true,
		serverEnabled:        true,
	},
	{
		// The client offers ECH, but the payload is mangled in transit. The
		// server sends retry configurations. The client signals rejection by
		// sending an "ech_required" alert.
		name:                       "success / rejected: inauthentic ciphertext",
		expectOffered:              true,
		expectRejected:             true,
		expectClientAbort:          true,
		expectServerAbort:          true,
		clientEnabled:              true,
		serverEnabled:              true,
		triggerPayloadDecryptError: true,
	},
	{
		// The client offered ECH, but client-facing server terminates the
		// connection without sending retry configurations. The client aborts
		// with "ech_required" and regards ECH as securely disabled by the
		// server.
		name:              "success / rejected: not supported by client-facing server",
		expectOffered:     true,
		expectBypassed:    true,
		expectClientAbort: true,
		expectServerAbort: true,
		clientEnabled:     true,
	},
	{
		// The client offers ECH. The server ECH rejects without sending retry
		// configurations, simulating fallover of the ECH provider. The client
		// signals rejection.
		name:                       "success / rejected: provider falls over",
		expectServerAbort:          true,
		expectOffered:              true,
		expectBypassed:             true,
		expectClientAbort:          true,
		clientEnabled:              true,
		serverEnabled:              true,
		serverProviderAlwaysReject: true,
	},
	{
		// The client offers ECH. The server does not support TLS 1.3, so it
		// ignores the extension and continues as usual. The client does not
		// signal rejection because TLS 1.2 has been negotiated.
		name:                 "downgraded: client-facing invalid version",
		expectBypassed:       true,
		clientEnabled:        true,
		serverEnabled:        true,
		serverInvalidVersion: true,
	},
	{
		// The client offers ECH. The ECH provider encounters an unrecoverable
		// error, causing the server to abort.
		name:                      "server abort: provider hard fails",
		expectServerAbort:         true,
		expectClientAbort:         true,
		clientEnabled:             true,
		serverEnabled:             true,
		serverProviderAlwaysAbort: true,
	},
	{
		// The client offers ECH and it is accepted by the server. The HRR code
		// path is triggered.
		name:                    "hrr / accepted",
		expectOffered:           true,
		expectAccepted:          true,
		expectBackendServerName: true,
		triggerHRR:              true,
		clientEnabled:           true,
		serverEnabled:           true,
	},
	{
		// The client sends a dummy ECH extension. The server sends retry
		// configs in case the client meant to offer ECH. The client does not
		// signal rejection, so the server concludes ECH was not offered. The
		// HRR code path is triggered.
		name:                    "hrr / bypassed: grease",
		expectGrease:            true,
		expectBackendServerName: true,
		clientEnabled:           true,
		clientNoConfigs:         true,
		serverEnabled:           true,
		triggerHRR:              true,
	},
	{
		// The client offers ECH with an invalid (e.g., stale) config. The
		// server sends retry configs. The client signals rejection. The HRR
		// code path is triggered.
		name:                 "hrr / rejected: invalid config",
		expectOffered:        true,
		expectRejected:       true,
		expectClientAbort:    true,
		expectServerAbort:    true,
		clientEnabled:        true,
		clientInvalidConfigs: true,
		serverEnabled:        true,
		triggerHRR:           true,
	},
	{
		// The HRR code path is triggered. The client offered ECH in the second
		// CH but not the first.
		name:                      "hrr / server abort: offer after bypass",
		expectServerAbort:         true,
		expectClientAbort:         true,
		clientEnabled:             true,
		serverEnabled:             true,
		triggerHRR:                true,
		triggerECHBypassBeforeHRR: true,
	},
	{
		// The HRR code path is triggered. The client offered ECH in the first
		// CH but not the second.
		name:                     "hrr / server abort: bypass after offer",
		expectServerAbort:        true,
		expectClientAbort:        true,
		clientEnabled:            true,
		serverEnabled:            true,
		triggerHRR:               true,
		triggerECHBypassAfterHRR: true,
	},
	{
		// The HRR code path is triggered. The client offers ECH. The server
		// accepts for the first CH but must reject it for the second, causing
		// the server to abort. This simulates what happens if the ECH provider
		// falls over after the HRR is sent but before the second CH is
		// consumed.
		name:                         "hrr / server abort: reject after accept",
		expectServerAbort:            true,
		expectClientAbort:            true,
		clientEnabled:                true,
		serverEnabled:                true,
		serverProviderRejectAfterHRR: true,
		triggerHRR:                   true,
	},
	{
		// The HRR code path is triggered. In the second CH, the value of the
		// context handle changes illegally.
		name:                         "hrr / server abort: illegal handle",
		expectServerAbort:            true,
		expectClientAbort:            true,
		clientEnabled:                true,
		serverEnabled:                true,
		triggerHRR:                   true,
		triggerIllegalHandleAfterHRR: true,
	},
	{
		// The client offers ECH and it is accepted by the server. The client
		// incorporates many outer extensions instead of just one (the default
		// behavior).
		name:                    "outer extensions, many / accepted",
		expectBackendServerName: true,
		expectOffered:           true,
		expectAccepted:          true,
		clientEnabled:           true,
		serverEnabled:           true,
		triggerOuterExtMany:     true,
	},
	{
		// The client offers ECH and it is accepted by the server. The client
		// incorporates no outer extensions.
		name:                    "outer extensions, none / accepted",
		expectBackendServerName: true,
		expectOffered:           true,
		expectAccepted:          true,
		clientEnabled:           true,
		serverEnabled:           true,
		triggerOuterExtNone:     true,
	},
	{
		// The client offers ECH but does not implement the "outer_extension"
		// mechanism correctly,
		name:                          "outer extensions, incorrect order / server abort: incorrect transcript",
		expectServerAbort:             true,
		expectClientAbort:             true,
		clientEnabled:                 true,
		serverEnabled:                 true,
		triggerOuterExtIncorrectOrder: true,
	},
}

// echTestResult represents the ECH status and error status of a connection.
type echTestResult struct {
	status  ECHStatus
	offered bool
	err     error
}

// Returns the base configurations for the client and client-facing server,
func echSetupConnTest() (clientConfig, serverConfig *Config) {
	echTestNow := time.Date(2020, time.September, 23, 0, 0, 0, 0, time.UTC)
	echTestConfig := &Config{
		Time: func() time.Time {
			return echTestNow
		},
		Rand:               rand.Reader,
		CipherSuites:       allCipherSuites(),
		InsecureSkipVerify: false,
	}

	clientFacingCert, err := X509KeyPair([]byte(echTestCertClientFacingPEM), []byte(echTestKeyClientFacingPEM))
	if err != nil {
		panic(err)
	}

	backendCert, err := X509KeyPair([]byte(echTestCertBackendPEM), []byte(echTestKeyBackendPEM))
	if err != nil {
		panic(err)
	}

	block, rest := pem.Decode([]byte(echTestCertRootPEM))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) > 0 {
		panic("pem decoding fails")
	}

	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}

	clientConfig = echTestConfig.Clone()
	clientConfig.ServerName = echTestBackendServerName
	clientConfig.RootCAs = x509.NewCertPool()
	clientConfig.RootCAs.AddCert(rootCert)

	serverConfig = echTestConfig.Clone()
	serverConfig.GetCertificate = func(info *ClientHelloInfo) (*Certificate, error) {
		if info.ServerName == echTestBackendServerName {
			return &backendCert, nil
		} else if info.ServerName == echTestClientFacingServerName {
			return &clientFacingCert, nil
		}
		return nil, nil
	}
	return
}

// echTestConn runs the handshake and returns the ECH and error status of the
// client and server. It also returns the server name verified by the client.
func echTestConn(t *testing.T, clientConfig, serverConfig *Config) (serverName string, clientRes, serverRes echTestResult) {
	testMessage := []byte("hey bud")
	buf := make([]byte, len(testMessage))
	ln := newLocalListener(t)
	defer ln.Close()

	serverCh := make(chan echTestResult, 1)
	go func() {
		var res echTestResult
		serverConn, err := ln.Accept()
		if err != nil {
			res.err = err
			serverCh <- res
			return
		}
		server := Server(serverConn, serverConfig)
		if err := server.Handshake(); err != nil {
			res.err = err
			serverCh <- res
			return
		}
		defer server.Close()

		if _, err = server.Read(buf); err != nil {
			res.err = err
		}

		st := server.ConnectionState()
		res.offered = st.ECHOffered
		res.status = st.ECHStatus
		serverCh <- res
	}()

	client, err := Dial("tcp", ln.Addr().String(), clientConfig)
	if err != nil {
		serverRes = <-serverCh
		clientRes.err = err
		return
	}
	defer client.Close()

	_, err = client.Write(testMessage)
	if err != nil {
		serverRes = <-serverCh
		clientRes.err = err
		return
	}

	st := client.ConnectionState()
	serverName = st.ServerName
	clientRes.offered = st.ECHOffered
	clientRes.status = st.ECHStatus
	serverRes = <-serverCh
	return
}

func TestECHHandshake(t *testing.T) {
	defer func() {
		// Reset testing triggers after the test completes.
		testingTriggerHRR = false
		testingECHTriggerBypassAfterHRR = false
		testingECHTriggerBypassBeforeHRR = false
		testingECHIllegalHandleAfterHRR = false
		testingECHOuterExtMany = false
		testingECHOuterExtNone = false
		testingECHOuterExtIncorrectOrder = false
		testingECHTriggerPayloadDecryptError = false
	}()

	invalidConfigs := echTestLoadConfigs(echTestInvalidConfigs)
	configs := echTestLoadConfigs(echTestConfigs)
	keySet := echTestLoadKeySet()

	clientConfig, serverConfig := echSetupConnTest()
	for i, test := range echTestCases {
		t.Run(fmt.Sprintf("%02d", i), func(t *testing.T) {
			// Configure the client.
			n := 0
			if test.clientNoConfigs {
				clientConfig.ClientECHConfigs = nil
				n++
			}
			if test.clientInvalidConfigs {
				clientConfig.ClientECHConfigs = invalidConfigs
				n++
			}
			if n == 0 {
				clientConfig.ClientECHConfigs = configs
			} else if n > 1 {
				panic("invalid test configuration")
			}

			if test.clientEnabled {
				clientConfig.ECHEnabled = true
			} else {
				clientConfig.ECHEnabled = false
			}

			if test.clientInvalidVersion {
				clientConfig.MinVersion = VersionTLS10
				clientConfig.MaxVersion = VersionTLS12
			} else {
				clientConfig.MinVersion = VersionTLS10
				clientConfig.MaxVersion = VersionTLS13
			}

			// Configure the client-facing server.
			if test.serverEnabled {
				serverConfig.ECHEnabled = true
			} else {
				serverConfig.ECHEnabled = false
			}

			n = 0
			if test.serverProviderAlwaysAbort {
				serverConfig.ServerECHProvider = &echTestProviderAlwaysAbort{}
				n++
			}
			if test.serverProviderAlwaysReject {
				serverConfig.ServerECHProvider = &echTestProviderAlwaysReject{}
				n++
			}
			if test.serverProviderRejectAfterHRR {
				serverConfig.ServerECHProvider = &echTestProviderRejectAfterHRR{
					keySet: keySet,
				}
				n++
			}
			if n == 0 {
				serverConfig.ServerECHProvider = keySet
			} else if n > 1 {
				panic("invalid test configuration")
			}

			if test.serverInvalidVersion {
				serverConfig.MinVersion = VersionTLS10
				serverConfig.MaxVersion = VersionTLS12
			} else {
				serverConfig.MinVersion = VersionTLS10
				serverConfig.MaxVersion = VersionTLS13
			}

			testingTriggerHRR = false
			if test.triggerHRR {
				testingTriggerHRR = true
			}

			testingECHTriggerBypassAfterHRR = false
			if test.triggerECHBypassAfterHRR {
				testingECHTriggerBypassAfterHRR = true
			}

			testingECHTriggerBypassBeforeHRR = false
			if test.triggerECHBypassBeforeHRR {
				testingECHTriggerBypassBeforeHRR = true
			}

			testingECHTriggerPayloadDecryptError = false
			if test.triggerPayloadDecryptError {
				testingECHTriggerPayloadDecryptError = true
			}

			n = 0
			testingECHOuterExtMany = false
			if test.triggerOuterExtMany {
				testingECHOuterExtMany = true
				n++
			}
			testingECHOuterExtNone = false
			if test.triggerOuterExtNone {
				testingECHOuterExtNone = true
				n++
			}
			testingECHOuterExtIncorrectOrder = false
			if test.triggerOuterExtIncorrectOrder {
				testingECHOuterExtIncorrectOrder = true
				n++
			}
			testingECHIllegalHandleAfterHRR = false
			if test.triggerIllegalHandleAfterHRR {
				testingECHIllegalHandleAfterHRR = true
				n++
			}
			if n > 1 {
				panic("invalid test configuration")
			}

			t.Logf("%s", test.name)

			// Run the handshake.
			serverName, client, server := echTestConn(t, clientConfig, serverConfig)
			if !test.expectClientAbort && client.err != nil {
				t.Error("client aborts; want success")
			}

			if !test.expectServerAbort && server.err != nil {
				t.Error("server aborts; want success")
			}

			if test.expectClientAbort && client.err == nil {
				t.Error("client succeeds; want abort")
			} else {
				t.Logf("client err: %s", client.err)
			}

			if test.expectServerAbort && server.err == nil {
				t.Errorf("server succeeds; want abort")
			} else {
				t.Logf("server err: %s", server.err)
			}

			rejected := server.status != ECHStatusBypassed &&
				server.err != nil && server.err.Error() == "remote error: tls: "+alertText[alertECHRequired]
			if test.expectRejected != rejected {
				t.Errorf("got rejected=%v; want %v", rejected, test.expectRejected)
			}

			if test.expectOffered != server.offered {
				t.Errorf("got offered=%v; want %v", server.offered, test.expectOffered)
			}

			if got := server.status == ECHStatusBypassed; got != test.expectBypassed && server.err == nil {
				t.Errorf("got bypassed=%v; want %v", got, test.expectBypassed)
			}

			if got := server.status == ECHStatusAccepted; got != test.expectAccepted {
				t.Errorf("got accepted=%v; want %v", got, test.expectAccepted)
			}

			if got := server.status == ECHStatusRejected; got != test.expectRejected {
				t.Errorf("got rejected=%v; want %v", got, test.expectRejected)
			}

			if got := server.status == ECHStatusGrease; got != test.expectGrease {
				t.Errorf("got grease=%v; want %v", got, test.expectGrease)
			}

			if client.err != nil {
				return
			}

			if test.expectBackendServerName != (serverName == echTestBackendServerName) {
				t.Errorf("got backend server name=%v; want %v", serverName == echTestBackendServerName, test.expectBackendServerName)
			}

			if client.status != server.status {
				t.Errorf("client and server disagree on usage")
				t.Errorf("client status=%+v; offered=%v", client.status, client.offered)
				t.Errorf("server status=%+v; offered=%v", server.status, server.offered)
			}
		})
	}
}
