// Copyright 2020 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"
	"time"
)

const (
	echTestBackendServerName      = "example.com"
	echTestClientFacingServerName = "cloudflare-esni.com"
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

// The ECH keys used by the client-facing server.
const echTestKeys = `-----BEGIN ECH KEYS-----
ACA/SG/gkFYqQ0vvrgz8CRtn8QBhUdmJIHrpLRa4MHbjpgBT/gkATwATY2xvdWRm
bGFyZS1lc25pLmNvbQAgRcve568ZJiCCyZJvwrIx0FIoSCQihzse5EJM36v98BcA
IAAQAAEAAQABAAMAAgABAAIAAwAAAAAAIOpdZ5c3Q1EIq5eztNrW+7GcUiPKPDhm
6JqulMAt5NLmAHT+CQBwABNjbG91ZGZsYXJlLWVzbmkuY29tAEEEpVCefVOCJ4vL
Ae6XXPx/d6w/yu4qP2asEfG/aYceggNFRS13f2FhfmTsFsctRsrfi0KR4fPlE469
PxZnNLJ8wAAQABAAAQABAAEAAwACAAEAAgADAAAAAA==
-----END ECH KEYS-----`

// A sequence of ECH keys with unsupported versions.
const echTestInvalidVersionKeys = `-----BEGIN ECH KEYS-----
ACChoR9Zm0Y7YJLxh4NHlF9cDWOYVdtbpsXNsLbEejCw4gBTvu8ATwATY2xvdWRm
bGFyZS1lc25pLmNvbQAg3on70PKtaF9Mp5WQghrykTszqKlaX02Pi+WYpbCza1gA
IAAQAAEAAQABAAMAAgABAAIAAwAAAAA=
-----END ECH KEYS-----`

// The sequence of ECH configurations corresponding to echTestKeys.
const echTestConfigs = `-----BEGIN ECH CONFIGS-----
AMf+CQBPABNjbG91ZGZsYXJlLWVzbmkuY29tACBFy97nrxkmIILJkm/CsjHQUihI
JCKHOx7kQkzfq/3wFwAgABAAAQABAAEAAwACAAEAAgADAAAAAP4JAHAAE2Nsb3Vk
ZmxhcmUtZXNuaS5jb20AQQSlUJ59U4Ini8sB7pdc/H93rD/K7io/ZqwR8b9phx6C
A0VFLXd/YWF+ZOwWxy1Gyt+LQpHh8+UTjr0/Fmc0snzAABAAEAABAAEAAQADAAIA
AQACAAMAAAAA
-----END ECH CONFIGS-----`

// An invalid sequence of ECH configurations.
const echTestStaleConfigs = `-----BEGIN ECH CONFIGS-----
AFP+CQBPABNjbG91ZGZsYXJlLWVzbmkuY29tACDA9Z4YbY7f6HMlsUUhSHdioVr9
s6vH9g5PPTkgR83MIwAgABAAAQABAAEAAwACAAEAAgADAAAAAA==
-----END ECH CONFIGS-----`

// echTestProviderAlwaysAbort mocks an ECHProvider that, in response to any
// request, sets an alert and returns an error. The client-facing server must
// abort the handshake.
type echTestProviderAlwaysAbort struct{}

// Required by the ECHProvider interface.
func (p echTestProviderAlwaysAbort) GetDecryptionContext(_ []byte, _ uint16) (res ECHProviderResult) {
	res.Status = ECHProviderAbort
	res.Alert = uint8(alertInternalError)
	res.Error = errors.New("provider failed")
	return // Abort
}

// echTestProviderAlwaysReject simulates fallover of the ECH provider. In
// response to any query, it rejects without sending retry configurations., in response to any
type echTestProviderAlwaysReject struct{}

// Required by the ECHProvider interface.
func (p echTestProviderAlwaysReject) GetDecryptionContext(_ []byte, _ uint16) (res ECHProviderResult) {
	res.Status = ECHProviderReject
	return // Reject without retry configs
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

func echTestLoadKeySet(pemData string) *EXP_ECHKeySet {
	block, rest := pem.Decode([]byte(pemData))
	if block == nil || block.Type != "ECH KEYS" || len(rest) > 0 {
		panic("pem decoding fails")
	}

	keys, err := EXP_UnmarshalECHKeys(block.Bytes)
	if err != nil {
		panic(err)
	}

	keySet, err := EXP_NewECHKeySet(keys)
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
	expectClientBypassed    bool // server bypasses ECH
	expectServerBypassed    bool // server indicates that ECH was bypassed by client
	expectAccepted          bool // server indicates ECH acceptance
	expectRejected          bool // server indicates ECH rejection
	expectGrease            bool // server indicates dummy ECH was detected
	expectBackendServerName bool // client verified backend server name

	// client config
	clientEnabled           bool // client enables ECH
	clientStaleConfigs      bool // client offers ECH with invalid config
	clientNoConfigs         bool // client sends dummy ECH if ECH enabled
	clientInvalidTLSVersion bool // client does not offer 1.3

	// server config
	serverEnabled                bool // server enables ECH
	serverProviderAlwaysAbort    bool // ECH provider always aborts
	serverProviderAlwaysReject   bool // ECH provider always rejects
	serverProviderInvalidVersion bool // ECH provider uses configs with unsupported version
	serverInvalidTLSVersion      bool // server does not offer 1.3

	// code path triggers
	triggerHRR                    bool // server triggers HRR
	triggerECHBypassAfterHRR      bool // client bypasses after HRR
	triggerECHBypassBeforeHRR     bool // client bypasses before HRR
	triggerIllegalHandleAfterHRR  bool // client sends illegal ECH extension after HRR
	triggerOuterExtMany           bool // client sends many (not just one) outer extensions
	triggerOuterExtIncorrectOrder bool // client sends malformed outer extensions
	triggerOuterExtIllegal        bool // client sends malformed outer extensions
	triggerOuterExtNone           bool // client does not incorporate outer extensions
	triggerOuterIsInner           bool // client sends "ech_is_inner" in ClientHelloOuter
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
		expectClientBypassed:    true,
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
		clientInvalidTLSVersion: true,
		clientEnabled:           true,
		serverEnabled:           true,
	},
	{
		// The client offers ECH with an invalid (e.g., stale) config. The
		// server sends retry configs. The client signals rejection by sending
		// an "ech_required" alert.
		name:               "success / rejected: invalid config",
		expectOffered:      true,
		expectRejected:     true,
		expectClientAbort:  true,
		expectServerAbort:  true,
		clientStaleConfigs: true,
		clientEnabled:      true,
		serverEnabled:      true,
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
		name:                 "success / rejected: not supported by client-facing server",
		expectServerBypassed: true,
		expectClientAbort:    true,
		expectServerAbort:    true,
		clientEnabled:        true,
	},
	{
		// The client offers ECH. The server ECH rejects without sending retry
		// configurations, simulating fallover of the ECH provider. The client
		// signals rejection.
		name:                       "success / rejected: provider falls over",
		expectServerAbort:          true,
		expectOffered:              true,
		expectServerBypassed:       true,
		expectClientAbort:          true,
		clientEnabled:              true,
		serverEnabled:              true,
		serverProviderAlwaysReject: true,
	},
	{
		// The client offers ECH. The server ECH rejects without sending retry
		// configurations because the ECH provider returns configurations with
		// unsupported versions only.
		name:                         "success / rejected: provider invalid version",
		expectServerAbort:            true,
		expectOffered:                true,
		expectServerBypassed:         true,
		expectClientAbort:            true,
		clientEnabled:                true,
		serverEnabled:                true,
		serverProviderInvalidVersion: true,
	},
	{
		// The client offers ECH. The server does not support TLS 1.3, so it
		// ignores the extension and continues as usual. The client does not
		// signal rejection because TLS 1.2 has been negotiated.
		name:                    "success / bypassed: client-facing invalid version",
		expectServerBypassed:    true,
		clientEnabled:           true,
		serverEnabled:           true,
		serverInvalidTLSVersion: true,
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
		// The client offers ECH, but sends the "ech_is_inner" extension in the
		// ClientHelloOuter, causing the server to abort.
		name:                "server abort: hello marked as inner and outer",
		expectServerAbort:   true,
		expectClientAbort:   true,
		clientEnabled:       true,
		serverEnabled:       true,
		triggerOuterIsInner: true,
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
		name:               "hrr / rejected: invalid config",
		expectOffered:      true,
		expectRejected:     true,
		expectClientAbort:  true,
		expectServerAbort:  true,
		clientEnabled:      true,
		clientStaleConfigs: true,
		serverEnabled:      true,
		triggerHRR:         true,
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
		expectOffered:            true,
		expectAccepted:           true,
		expectServerAbort:        true,
		expectClientAbort:        true,
		clientEnabled:            true,
		serverEnabled:            true,
		triggerHRR:               true,
		triggerECHBypassAfterHRR: true,
	},
	{
		// The HRR code path is triggered. In the second CH, the value of the
		// context handle changes illegally. Specifically, the client sends a
		// non-empty "config_id" and "enc".
		name:                         "hrr / server abort: illegal handle",
		expectOffered:                true,
		expectAccepted:               true,
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
		// mechanism correctly. Specifically, it sends them in the wrong order,
		// causing the client and server to compute different transcripts.
		name:                          "outer extensions, incorrect order / server abort: incorrect transcript",
		expectOffered:                 true,
		expectAccepted:                true,
		expectServerAbort:             true,
		expectClientAbort:             true,
		clientEnabled:                 true,
		serverEnabled:                 true,
		triggerOuterExtIncorrectOrder: true,
	},
	{
		// The client offers ECH but does not implement the "outer_extension"
		// mechanism correctly. Specifically, the "outer extensions" contains
		// the codepoint for the ECH extension itself.
		name:                   "outer extensions, illegal: illegal parameter",
		expectServerAbort:      true,
		expectClientAbort:      true,
		clientEnabled:          true,
		serverEnabled:          true,
		triggerOuterExtIllegal: true,
	},
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

// echTestResult represents the ECH status and error status of a connection.
type echTestResult struct {
	// Operational parameters
	clientDone, serverDone bool
	// Results
	clientStatus EXP_EventECHClientStatus
	serverStatus EXP_EventECHServerStatus
	connState    ConnectionState
	err          error
}

func (r *echTestResult) eventHandler(event EXP_Event) {
	switch e := event.(type) {
	case EXP_EventECHClientStatus:
		if r.clientDone {
			panic("expected at most one client ECH status event")
		}
		r.clientStatus = e
		r.clientDone = true
	case EXP_EventECHServerStatus:
		if r.serverDone {
			panic("expected at most one server ECH status event")
		}
		r.serverStatus = e
		r.clientDone = true
	}
}

// echTestConn runs the handshake and returns the ECH and error status of the
// client and server. It also returns the server name verified by the client.
func echTestConn(t *testing.T, clientConfig, serverConfig *Config) (clientRes, serverRes echTestResult) {
	testMessage := []byte("hey bud")
	buf := make([]byte, len(testMessage))
	ln := newLocalListener(t)
	defer ln.Close()

	serverCh := make(chan echTestResult, 1)
	go func() {
		var res echTestResult
		serverConfig.EXP_EventHandler = res.eventHandler
		serverConn, err := ln.Accept()
		if err != nil {
			res.err = err
			serverCh <- res
			return
		}

		server := Server(serverConn, serverConfig)
		defer func() {
			server.Close()
			serverCh <- res
		}()

		if err := server.Handshake(); err != nil {
			res.err = err
			return
		}

		if _, err = server.Read(buf); err != nil {
			res.err = err
		}

		res.connState = server.ConnectionState()
	}()

	clientConfig.EXP_EventHandler = clientRes.eventHandler
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

	clientRes.connState = client.ConnectionState()
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
		testingECHOuterExtIllegal = false
		testingECHOuterIsInner = false
		testingECHTriggerPayloadDecryptError = false
	}()

	staleConfigs := echTestLoadConfigs(echTestStaleConfigs)
	configs := echTestLoadConfigs(echTestConfigs)
	keySet := echTestLoadKeySet(echTestKeys)
	invalidVersionKeySet := echTestLoadKeySet(echTestInvalidVersionKeys)

	clientConfig, serverConfig := echSetupConnTest()
	for i, test := range echTestCases {
		t.Run(fmt.Sprintf("%02d", i), func(t *testing.T) {
			// Configure the client.
			n := 0
			if test.clientNoConfigs {
				clientConfig.ClientECHConfigs = nil
				n++
			}
			if test.clientStaleConfigs {
				clientConfig.ClientECHConfigs = staleConfigs
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

			if test.clientInvalidTLSVersion {
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
			if test.serverProviderInvalidVersion {
				serverConfig.ServerECHProvider = invalidVersionKeySet
				n++
			}
			if n == 0 {
				serverConfig.ServerECHProvider = keySet
			} else if n > 1 {
				panic("invalid test configuration")
			}

			if test.serverInvalidTLSVersion {
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
			testingECHOuterExtIllegal = false
			if test.triggerOuterExtIllegal {
				testingECHOuterExtIllegal = true
				n++
			}
			testingECHOuterIsInner = false
			if test.triggerOuterIsInner {
				testingECHOuterIsInner = true
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
			client, server := echTestConn(t, clientConfig, serverConfig)
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

			if got := server.clientStatus.Offered(); got != test.expectOffered {
				t.Errorf("got offered=%v; want %v", got, test.expectOffered)
			}

			if got := server.clientStatus.Greased(); got != test.expectGrease {
				t.Errorf("got grease=%v; want %v", got, test.expectGrease)
			}

			if got := server.clientStatus.Bypassed(); got != test.expectClientBypassed && server.err == nil {
				t.Errorf("got clientBypassed=%v; want %v", got, test.expectClientBypassed)
			}

			if got := server.serverStatus.Bypassed(); got != test.expectServerBypassed && server.err == nil {
				t.Errorf("got serverBypassed=%v; want %v", got, test.expectServerBypassed)
			}

			if got := server.serverStatus.Accepted(); got != test.expectAccepted {
				t.Errorf("got accepted=%v; want %v", got, test.expectAccepted)
			}

			if got := server.serverStatus.Rejected(); got != test.expectRejected {
				t.Errorf("got rejected=%v; want %v", got, test.expectRejected)
			}

			if client.err != nil {
				return
			}

			if name := client.connState.ServerName; test.expectBackendServerName != (name == echTestBackendServerName) {
				t.Errorf("got backend server name=%v; want %v", name == echTestBackendServerName, test.expectBackendServerName)
			}

			if client.clientStatus.Greased() != server.clientStatus.Greased() ||
				client.clientStatus.Bypassed() != server.clientStatus.Bypassed() ||
				client.serverStatus.Bypassed() != server.serverStatus.Bypassed() ||
				client.serverStatus.Accepted() != server.serverStatus.Accepted() ||
				client.serverStatus.Rejected() != server.serverStatus.Rejected() {
				t.Error("client and server disagree on ech usage")
				t.Errorf("client=%+v", client)
				t.Errorf("server=%+v", server)
			}

			if accepted := client.connState.ECHAccepted; accepted != client.serverStatus.Accepted() {
				t.Errorf("client got ECHAccepted=%v; want %v", accepted, client.serverStatus.Accepted())
			}

			if accepted := server.connState.ECHAccepted; accepted != server.serverStatus.Accepted() {
				t.Errorf("server got ECHAccepted=%v; want %v", accepted, server.serverStatus.Accepted())
			}
		})
	}
}

func TestUnmarshalConfigs(t *testing.T) {
	block, rest := pem.Decode([]byte(echTestConfigs))
	if block == nil || block.Type != "ECH CONFIGS" || len(rest) > 0 {
		t.Fatal("pem decoding fails")
	}

	configs, err := UnmarshalECHConfigs(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	for _, config := range configs {
		if len(config.raw) == 0 {
			t.Error("raw config not set")
		}
	}
}

func TestUnmarshalKeys(t *testing.T) {
	block, rest := pem.Decode([]byte(echTestKeys))
	if block == nil || block.Type != "ECH KEYS" || len(rest) > 0 {
		t.Fatal("pem decoding fails")
	}

	keys, err := EXP_UnmarshalECHKeys(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	for _, key := range keys {
		if len(key.config.raw) == 0 {
			t.Error("raw config not set")
		}
	}
}

func testECHProvider(t *testing.T, p ECHProvider, handle []byte, version uint16, want ECHProviderResult) {
	got := p.GetDecryptionContext(handle, version)
	if got.Status != want.Status {
		t.Errorf("incorrect status: got %+v; want %+v", got.Status, want.Status)
	}
	if got.Alert != want.Alert {
		t.Errorf("incorrect alert: got %+v; want %+v", got.Alert, want.Alert)
	}
	if got.Error != want.Error {
		t.Errorf("incorrect error: got %+v; want %+v", got.Error, want.Error)
	}
	if !bytes.Equal(got.RetryConfigs, want.RetryConfigs) {
		t.Errorf("incorrect retry configs: got %+v; want %+v", got.RetryConfigs, want.RetryConfigs)
	}
	if !bytes.Equal(got.Context, want.Context) {
		t.Errorf("incorrect context: got %+v; want %+v", got.Context, want.Context)
	}
}

func TestECHProvider(t *testing.T) {
	p := echTestLoadKeySet(echTestKeys)
	t.Run("ok", func(t *testing.T) {
		handle := []byte{
			0, 1, 0, 1, 8, 202, 62, 220, 1, 243, 58, 247, 102, 0, 32, 40, 52,
			167, 167, 21, 125, 151, 32, 250, 255, 1, 125, 206, 103, 62, 96, 189,
			112, 126, 48, 221, 41, 198, 146, 100, 149, 29, 133, 103, 87, 87, 78,
		}
		context := []byte{
			1, 0, 32, 0, 1, 0, 1, 32, 236, 67, 192, 226, 245, 110, 78, 204, 212,
			236, 85, 28, 234, 9, 249, 154, 158, 25, 69, 140, 83, 156, 41, 237,
			146, 108, 142, 83, 130, 231, 162, 53, 16, 80, 114, 44, 28, 184, 124,
			105, 82, 228, 226, 156, 178, 245, 44, 171, 175, 12, 97, 213, 61,
			253, 64, 224, 125, 59, 223, 107, 24, 119, 12, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0,
		}
		testECHProvider(t, p, handle, extensionECH, ECHProviderResult{
			Status:       ECHProviderSuccess,
			RetryConfigs: p.configs,
			Context:      context,
		})
	})
	t.Run("invalid config id", func(t *testing.T) {
		handle := []byte{
			0, 1, 0, 1, 6, 202, 62, 220, 1, 243, 58, 0, 32, 40, 52, 167, 167,
			21, 125, 151, 32, 250, 255, 1, 125, 206, 103, 62, 96, 189, 112, 126,
			48, 221, 41, 198, 146, 100, 149, 29, 133, 103, 87, 87, 78,
		}
		testECHProvider(t, p, handle, extensionECH, ECHProviderResult{
			Status:       ECHProviderReject,
			RetryConfigs: p.configs,
		})
	})
	t.Run("invalid cipher suite", func(t *testing.T) {
		handle := []byte{
			99, 99, 0, 1, 8, 202, 62, 220, 1, 243, 58, 247, 102, 0, 32, 40, 52,
			167, 167, 21, 125, 151, 32, 250, 255, 1, 125, 206, 103, 62, 96, 189,
			112, 126, 48, 221, 41, 198, 146, 100, 149, 29, 133, 103, 87, 87, 78,
		}
		testECHProvider(t, p, handle, extensionECH, ECHProviderResult{
			Status:       ECHProviderReject,
			RetryConfigs: p.configs,
		})
	})
	t.Run("malformed", func(t *testing.T) {
		handle := []byte{
			0, 1, 0, 1, 8, 202, 62, 220, 1,
		}
		testECHProvider(t, p, handle, extensionECH, ECHProviderResult{
			Status:       ECHProviderReject,
			RetryConfigs: p.configs,
		})
	})
}
