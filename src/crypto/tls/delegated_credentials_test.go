// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

// dcAndPrivateKey stores a delegated credential and its corresponding private
// key.
type dcAndPrivateKey struct {
	*DelegatedCredential
	privateKey crypto.PrivateKey
}

// These test keys were generated with the following program, available in the
// crypto/tls directory:
//
//	go run generate_cert.go -ecdsa-curve P256 -host 127.0.0.1 -allowDC
//
var delegatorCertPEMP256 = `-----BEGIN CERTIFICATE-----
MIIBeDCCAR2gAwIBAgIQEK4SYiNrt/z9uw5eC4WVcjAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTIwMTEyMzIxMjA1NFoXDTIxMTEyMzIxMjA1NFow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJCe
WthOWUGc49uluMdyW3T3Md4M47MPaAq811dHebAsgPdOw6qiVqFNe/4rCITlQG1H
JvYpe22Ld/N9oO62y9ejVTBTMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggr
BgEFBQcDATAMBgNVHRMBAf8EAjAAMA0GCSsGAQQBgtpLLAQAMA8GA1UdEQQIMAaH
BH8AAAEwCgYIKoZIzj0EAwIDSQAwRgIhAPEY8YHsMB91rxGmAKh4byqCanLQBL7K
GooeyxL9DBLJAiEAyhSg49wqKlqjKwcpaidjjfb6/xrOHWMmW3atpUIlezQ=
-----END CERTIFICATE-----
`

var delegatorKeyPEMP256 = `-----BEGIN EC PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgdBt0rSFYyGeJ2HZ9
XGbbjCnfLPMGJEH5ympFORvqMtahRANCAASQnlrYTllBnOPbpbjHclt09zHeDOOz
D2gKvNdXR3mwLID3TsOqolahTXv+KwiE5UBtRyb2KXtti3fzfaDutsvX
-----END EC PRIVATE KEY-----
`

//	go run generate_cert.go -ecdsa-curve P384 -host 127.0.0.1 -allowDC

var delegatorCertPEMP384 = `-----BEGIN CERTIFICATE-----
MIIBtTCCATqgAwIBAgIQdw0YRKWKReLXUESTYK+78jAKBggqhkjOPQQDAzASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTIwMTIwNzE0MzgyMloXDTIxMTIwNzE0MzgyMlow
EjEQMA4GA1UEChMHQWNtZSBDbzB2MBAGByqGSM49AgEGBSuBBAAiA2IABOKRdVWP
Vxuboi9QBJxDXMxOmph4NTqDMziJLjFQgHtqp0eukPx9SUprt1palTX+A1wH+g8U
Npy5mFmZ+pu0M4edXCKR1ckPCdQRF5Fh3NvHgHt7kDux3bLTYV+CL0JxjaNVMFMw
DgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQC
MAAwDQYJKwYBBAGC2kssBAAwDwYDVR0RBAgwBocEfwAAATAKBggqhkjOPQQDAwNp
ADBmAjEAvXX0ePSaI9KafIXrULgvwUispzbT0fNv1mH4T782Rh16emeMhMq11BUG
69Kn9FBOAjEAi7wNSKmi0cyJODV/EZCMPyMLuoS0vrutl6VnFoe8DOzp/hbLERWh
j/YIlsqcYa7p
-----END CERTIFICATE-----
`

var delegatorKeyPEMP384 = `-----BEGIN EC PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCVtlN89Viz5G4sf8YC
V1kPX8Sns0tfi9yF/TErZhUjBmcm4jRTLkMDb/h05zBezW+hZANiAATikXVVj1cb
m6IvUAScQ1zMTpqYeDU6gzM4iS4xUIB7aqdHrpD8fUlKa7daWpU1/gNcB/oPFDac
uZhZmfqbtDOHnVwikdXJDwnUEReRYdzbx4B7e5A7sd2y02Ffgi9CcY0=
-----END EC PRIVATE KEY-----
`

//	go run generate_cert.go -ecdsa-curve P521 -host 127.0.0.1 -allowDC

var delegatorCertPEMP521 = `-----BEGIN CERTIFICATE-----
MIIB/zCCAWGgAwIBAgIRAOcfIAcYC062FWanVdZdlOYwCgYIKoZIzj0EAwQwEjEQ
MA4GA1UEChMHQWNtZSBDbzAeFw0yMDEyMDcxNDQ0NTlaFw0yMTEyMDcxNDQ0NTla
MBIxEDAOBgNVBAoTB0FjbWUgQ28wgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAGo
D75Wmtx6Xw/g5YnhOgLlDN/9OsTX478M/Bwu1ARqi+Xy2Bt/PKKvyqaYyEAu0WY/
Kj3wAuHwEgN/VVav2NW0UAD/CrjetL3305iZlojvhDIEg8laX2xe1P79ZxK/CLaP
zc6sRooNXmYOQzWiavDy2krKevJBxb7cxPakJ1XsUweNiKNVMFMwDgYDVR0PAQH/
BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwDQYJKwYB
BAGC2kssBAAwDwYDVR0RBAgwBocEfwAAATAKBggqhkjOPQQDBAOBiwAwgYcCQQO4
7FbhJUJ9gGWsxoBVSUuoHB0z9UfF9Jiud16eNvjMXRFUEgL7kY3XwXjilaic4cW3
Svh1thgW7V9GbIonPanAAkIBi43WrE18UmULEkzhsXGg/ZyqfoU2+LcL4PeWfMVI
b4GXrl4LRuoRh2cip0Hqbk5thJEIA7Sg/FlIuPM0pB+0gIM=
-----END CERTIFICATE-----
`

var delegatorKeyPEMP521 = `-----BEGIN EC PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBwj6NUziPVsrT3paN
MIjkaX3LLLga8nLSCPLFrpWuU+GSeD7RU4TqNE623HkeqJr56iGak7rWeov1xR41
/2kO4PWhgYkDgYYABAGoD75Wmtx6Xw/g5YnhOgLlDN/9OsTX478M/Bwu1ARqi+Xy
2Bt/PKKvyqaYyEAu0WY/Kj3wAuHwEgN/VVav2NW0UAD/CrjetL3305iZlojvhDIE
g8laX2xe1P79ZxK/CLaPzc6sRooNXmYOQzWiavDy2krKevJBxb7cxPakJ1XsUweN
iA==
-----END EC PRIVATE KEY-----
`

//	go run generate_cert.go -ed25519 -host 127.0.0.1 -allowDC

var delegatorCertPEMEd25519 = `-----BEGIN CERTIFICATE-----
MIIBNzCB6qADAgECAhEAhIMJAR5dapYcV5cjRuRApzAFBgMrZXAwEjEQMA4GA1UE
ChMHQWNtZSBDbzAeFw0yMDEyMDcxNDQ5MzlaFw0yMTEyMDcxNDQ5MzlaMBIxEDAO
BgNVBAoTB0FjbWUgQ28wKjAFBgMrZXADIQATTnuZqoSPBSEdEWFoJmUuOy8xfNdt
+ognUFnPTdDX/KNVMFMwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUF
BwMBMAwGA1UdEwEB/wQCMAAwDQYJKwYBBAGC2kssBAAwDwYDVR0RBAgwBocEfwAA
ATAFBgMrZXADQQAnjfw84mKloi7s2REzkZ9aP+GH9UgmuJo6zFvyOfuJ8ddTbApA
62iMnRsuFZNqoTd4zdjJ59Vkh0Of0w2b4kUA
-----END CERTIFICATE-----
`

var delegatorKeyPEMEd25519 = `-----BEGIN EC PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIGdj/sgeHjl1QqIiIn23CUci/6nYVQjsixBwLJamHDqo
-----END EC PRIVATE KEY-----
`

var nonDelegatorCertPEM = `-----BEGIN CERTIFICATE-----
MIIBaDCCAQ6gAwIBAgIQcMnAGu3NQYTGYf2HK+JodTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTIwMDgxODA1NDg1NloXDTIxMDgxODA1NDg1Nlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPAi
QzOthHUdwLTPo9P7Vk1I2W5RHW5nIkq9zYqqMZ5mHQ6vmmrpklvTNHtY93PlokjN
pnlhzEsxK/QrBoAQ8fajRjBEMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggr
BgEFBQcDATAMBgNVHRMBAf8EAjAAMA8GA1UdEQQIMAaHBH8AAAEwCgYIKoZIzj0E
AwIDSAAwRQIgbOxx7/KWTD47UTWIBcFB95BPrFp2SaFBUyjhzMDXsQkCIQDnwtye
V1OlcMigjCsQuGRacYFP3f1ASpYVv58t/ZeVCw==
-----END CERTIFICATE-----
`

var nonDelegatorKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgD9Q9131NamLDe4ud
dU9rg+gO0vv8lXYErf7P5GQlZD6hRANCAATwIkMzrYR1HcC0z6PT+1ZNSNluUR1u
ZyJKvc2KqjGeZh0Or5pq6ZJb0zR7WPdz5aJIzaZ5YcxLMSv0KwaAEPH2
-----END EC PRIVATE KEY-----
`

var dcTestConfig *Config
var dcTestCerts map[string]*Certificate
var serverDC []*dcAndPrivateKey
var clientDC []*dcAndPrivateKey
var dcNow time.Time
var dcTestDCScheme = []SignatureScheme{ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512, Ed25519}

func init() {
	dcTestConfig = &Config{
		Time: func() time.Time {
			return dcNow
		},
		Rand:         zeroSource{},
		Certificates: nil,
		MinVersion:   VersionTLS10,
		MaxVersion:   VersionTLS13,
		CipherSuites: allCipherSuites(),
	}

}

func initialize() {
	// Use a static time for testing at which time the test certificates are
	// valid.
	dcNow = time.Date(2020, time.December, 31, 11, 0, 0, 234234, time.UTC)

	// The certificates of the server.
	dcTestCerts = make(map[string]*Certificate)
	var err error

	// The delegation P256 certificate.
	dcCertP256 := new(Certificate)
	*dcCertP256, err = X509KeyPair([]byte(delegatorCertPEMP256), []byte(delegatorKeyPEMP256))
	if err != nil {
		panic(err)
	}

	dcCertP256.Leaf, err = x509.ParseCertificate(dcCertP256.Certificate[0])
	if err != nil {
		panic(err)
	}
	dcTestCerts["dcP256"] = dcCertP256

	// The delegation P384 certificate.
	dcCertP384 := new(Certificate)
	*dcCertP384, err = X509KeyPair([]byte(delegatorCertPEMP384), []byte(delegatorKeyPEMP384))
	if err != nil {
		panic(err)
	}

	dcCertP384.Leaf, err = x509.ParseCertificate(dcCertP384.Certificate[0])
	if err != nil {
		panic(err)
	}
	dcTestCerts["dcP384"] = dcCertP384

	// The delegation P521 certificate.
	dcCertP521 := new(Certificate)
	*dcCertP521, err = X509KeyPair([]byte(delegatorCertPEMP521), []byte(delegatorKeyPEMP521))
	if err != nil {
		panic(err)
	}

	dcCertP521.Leaf, err = x509.ParseCertificate(dcCertP521.Certificate[0])
	if err != nil {
		panic(err)
	}
	dcTestCerts["dcP521"] = dcCertP521

	// The delegation Ed25519 certificate.
	dcCertEd25519 := new(Certificate)
	*dcCertEd25519, err = X509KeyPair([]byte(delegatorCertPEMEd25519), []byte(delegatorKeyPEMEd25519))
	if err != nil {
		panic(err)
	}

	dcCertEd25519.Leaf, err = x509.ParseCertificate(dcCertEd25519.Certificate[0])
	if err != nil {
		panic(err)
	}
	dcTestCerts["dcEd25519"] = dcCertEd25519

	// The non-delegation certificate.
	noDcCert := new(Certificate)
	*noDcCert, err = X509KeyPair([]byte(nonDelegatorCertPEM), []byte(nonDelegatorKeyPEM))
	if err != nil {
		panic(err)
	}
	noDcCert.Leaf, err = x509.ParseCertificate(noDcCert.Certificate[0])
	if err != nil {
		panic(err)
	}
	dcTestCerts["no dc"] = noDcCert

	// The root certificates for the client.
	dcTestConfig.RootCAs = x509.NewCertPool()

	for _, c := range dcTestCerts {
		dcRoot, err := x509.ParseCertificate(c.Certificate[len(c.Certificate)-1])
		if err != nil {
			panic(err)
		}
		dcTestConfig.RootCAs.AddCert(dcRoot)
	}

	for i := 0; i < len(dcTestDCScheme); i++ {
		dc, sk, err := NewDelegatedCredential(dcCertP256, dcTestDCScheme[i], dcNow.Sub(dcCertP256.Leaf.NotBefore)+dcMaxTTL, DCServer)
		if err != nil {
			panic(err)
		}
		serverDC = append(serverDC, &dcAndPrivateKey{dc, sk})

		dc, sk, err = NewDelegatedCredential(dcCertP256, dcTestDCScheme[i], dcNow.Sub(dcCertP256.Leaf.NotBefore)+dcMaxTTL, DCClient)
		if err != nil {
			panic(err)
		}
		clientDC = append(clientDC, &dcAndPrivateKey{dc, sk})
	}

}

func publicKeysEqual(publicKey, publicKey2 crypto.PublicKey, algo SignatureScheme) error {
	switch publicKey.(type) {
	case *ecdsa.PublicKey:
		curve := getCurve(algo)
		pk := publicKey.(*ecdsa.PublicKey)
		pk2 := publicKey2.(*ecdsa.PublicKey)

		serPubKey := elliptic.Marshal(curve, pk.X, pk.Y)
		serPubKey2 := elliptic.Marshal(curve, pk2.X, pk2.Y)
		if !bytes.Equal(serPubKey2, serPubKey) {
			return errors.New("ecdsa public Keys mismatch")
		}
	case ed25519.PublicKey:
		pk := publicKey.(ed25519.PublicKey)
		pk2 := publicKey2.(ed25519.PublicKey)

		if !bytes.Equal(pk, pk2) {
			return errors.New("ed25519 Public Keys mismatch")
		}
	}

	return nil
}

func equal(dc, dc2 *DelegatedCredential) error {
	if dc2.cred.validTime != dc.cred.validTime {
		return fmt.Errorf("ValidTime mismatch: got %d; want %d", dc2.cred.validTime, dc.cred.validTime)
	}

	if dc2.cred.expCertVerfAlgo != dc.cred.expCertVerfAlgo {
		return fmt.Errorf("scheme mismatch: got %04x; want %04x", dc2.cred.expCertVerfAlgo, dc.cred.expCertVerfAlgo)
	}

	return publicKeysEqual(dc.cred.publicKey, dc2.cred.publicKey, dc.cred.expCertVerfAlgo)
}

// Test delegation and validation of credentials.
func TestDelegateCredentialsValidate(t *testing.T) {
	initialize()
	cert := dcTestCerts["dcP384"]
	validTime := dcNow.Sub(cert.Leaf.NotBefore) + dcMaxTTL

	delegatedCred, _, err := NewDelegatedCredential(cert, ECDSAWithP384AndSHA384, validTime, DCServer)
	if err != nil {
		t.Fatal(err)
	} else if delegatedCred == nil {
		t.Fatal("unable to generate a Delegated Credential")
	}

	rand := rand.New(rand.NewSource(time.Now().UnixNano()))
	m := &certificateVerifyMsg{}
	m.hasSignatureAlgorithm = true
	m.signatureAlgorithm = ECDSAWithP384AndSHA384
	m.signature = randomBytes(rand.Intn(15)+1, rand)

	// Valid Delegated Credential
	if !delegatedCred.Validate(cert.Leaf, DCServer, dcNow, m) {
		t.Error("generated valid Delegated Credential is rendered invalid")
	}

	// Expired Delegated Credential
	expired := dcNow.Add(dcMaxTTL).Add(time.Nanosecond)
	if delegatedCred.Validate(cert.Leaf, DCServer, expired, m) {
		t.Error("expired delegated credential is valid; want invalid")
	}

	// Test validation of Delegated Credential which TTL is too long
	invalidDelegatedCred, _, err := NewDelegatedCredential(cert, ECDSAWithP384AndSHA384, validTime+time.Second, DCServer)
	if err != nil {
		t.Fatal(err)
	}
	if invalidDelegatedCred.Validate(cert.Leaf, DCServer, dcNow, m) {
		t.Error("Delegated Credential validation with long TTL succeeded; want failure")
	}

	shortValidTime := dcNow.Sub(cert.Leaf.NotBefore) + time.Second

	// Test validation of Delegated Credential which TTL is short
	delegatedCred, _, err = NewDelegatedCredential(cert, ECDSAWithP384AndSHA384, shortValidTime, DCServer)
	if err != nil {
		t.Fatal(err)
	}
	if !delegatedCred.Validate(cert.Leaf, DCServer, dcNow, m) {
		t.Error("valid Delegated Credential is invalid; want valid")
	}

	delegatedCred.algorithm = ECDSAWithP521AndSHA512

	// Test signature algorithm binding
	if delegatedCred.Validate(cert.Leaf, DCServer, dcNow, m) {
		t.Error("Delegated Credential with wrong scheme is valid; want invalid")
	}

	delegatedCred.algorithm = ECDSAWithP384AndSHA384

	// Test delegation certificate binding
	cert.Leaf.Raw[0] ^= byte(42)
	if delegatedCred.Validate(cert.Leaf, DCServer, dcNow, m) {
		t.Error("Delegated Credential with wrong certificate is valid; want invalid")
	}

	// Test validation of DC using a certificate that can't delegate.
	if delegatedCred.Validate(dcTestCerts["no dc"].Leaf, DCServer, dcNow, m) {
		t.Error("Delegated Credential with non-delegation cert is valid; want invalid")
	}

	// Test DC with another certificate
	cert = dcTestCerts["dcP521"]
	validTime = dcNow.Sub(cert.Leaf.NotBefore) + dcMaxTTL
	delegatedCred, _, err = NewDelegatedCredential(cert, ECDSAWithP384AndSHA384, validTime, DCServer)
	if err != nil {
		t.Fatal(err)
	} else if delegatedCred == nil {
		t.Fatal("unable to generate a Delegated Credential")
	}

	// Valid Delegated Credential
	if !delegatedCred.Validate(cert.Leaf, DCServer, dcNow, m) {
		t.Error("generated valid Delegated Credential is rendered invalid")
	}
}

// Test encoding/decoding of delegated credentials.
func TestDelegatedCredentialMarshal(t *testing.T) {
	initialize()
	cert := dcTestCerts["dcEd25519"]
	time := dcNow.Sub(cert.Leaf.NotBefore) + dcMaxTTL

	for _, sig := range dcTestDCScheme {
		delegatedCred, _, err := NewDelegatedCredential(cert, sig, time, DCServer)
		if err != nil {
			t.Fatal(err)
		}

		ser, err := delegatedCred.marshal()
		if err != nil {
			t.Error(err)
		}

		delegatedCred2, err := unmarshalDelegatedCredential(ser)
		if err != nil {
			t.Error(err)
		}

		err = equal(delegatedCred, delegatedCred2)
		if err != nil {
			t.Error(err)
		}

		if delegatedCred.algorithm != delegatedCred2.algorithm {
			t.Errorf("scheme mismatch: got %04x; want %04x", delegatedCred2.algorithm, delegatedCred.algorithm)
		}

		if !bytes.Equal(delegatedCred2.signature, delegatedCred.signature) {
			t.Error("Signature mismatch")
		}
	}
}

var dcTests = []struct {
	clientDCSupport bool
	serverDCSupport bool
	clientMaxVers   uint16
	serverMaxVers   uint16
	expectSuccess   bool
	expectDC        bool
	name            string
}{
	{true, true, VersionTLS13, VersionTLS13, true, true, "tls13: DC server and client support"},
	{true, false, VersionTLS13, VersionTLS13, true, false, "DC not server support"},
	{false, true, VersionTLS13, VersionTLS13, true, false, "DC not client support"},
	{true, true, VersionTLS12, VersionTLS13, true, false, "client using TLS 1.2. No DC is supported in that version."},
	{true, true, VersionTLS13, VersionTLS12, true, false, "server using TLS 1.2. No DC is supported in that version."},
	{true, true, VersionTLS11, VersionTLS13, true, false, "client using TLS 1.1. No DC is supported in that version."},
	{true, true, VersionTLS13, VersionTLS10, false, false, "server using TLS 1.0. No DC is supported in that version."},
}

// Checks that the client suppports a version >= 1.3 and accepts delegated
// credentials. If so, it returns the delegation certificate; otherwise it
// returns a non-delegated certificate.
func testServerGetCertificate(ch *ClientHelloInfo) (*Certificate, error) {
	versOk := false
	for _, vers := range ch.SupportedVersions {
		versOk = versOk || (vers >= uint16(VersionTLS13))
	}

	if versOk && ch.SupportsDelegatedCredential {
		return dcTestCerts["dcP256"], nil
	}
	return dcTestCerts["no dc"], nil

}

// Checks that the client suppports a version >= 1.3 and accepts delegated
// credentials. If so, it returns the delegation certificate; otherwise it
// returns a non-delegated certificate.
func testClientGetCertificate(cr *CertificateRequestInfo) (*Certificate, error) {
	versOk := false
	if cr.Version == VersionTLS13 {
		versOk = true
	}

	if versOk && cr.SupportsDelegatedCredential {
		return dcTestCerts["dcP256"], nil
	}
	return dcTestCerts["no dc"], nil

}

var inc = 0

// Checks that the client supports the signature algorithm supported by the test
// server, and that the server has a Delegated Credential.
func testGetDelegatedCredential(ch *ClientHelloInfo, cr *CertificateRequestInfo) (*DelegatedCredential, crypto.PrivateKey, error) {
	if ch != nil {
		schemeOk := false
		for _, scheme := range ch.SignatureSchemesDC {
			schemeOk = schemeOk || (scheme == dcTestDCScheme[inc])
		}

		if schemeOk && ch.SupportsDelegatedCredential {
			return serverDC[inc].DelegatedCredential, serverDC[inc].privateKey, nil
		}
	} else if cr != nil {
		schemeOk := false
		for _, scheme := range cr.SignatureSchemesDC {
			schemeOk = schemeOk || (scheme == dcTestDCScheme[inc])
		}

		if schemeOk && cr.SupportsDelegatedCredential {
			return clientDC[inc].DelegatedCredential, clientDC[inc].privateKey, nil
		}
	}

	return nil, nil, nil
}

// Tests the handshake and one round of application data. Returns true if the
// connection correctly used a Delegated Credential.
func testConnWithDC(t *testing.T, clientMsg, serverMsg string, clientConfig, serverConfig *Config, peer string) (bool, error) {
	initialize()
	ln := newLocalListener(t)
	defer ln.Close()

	serverCh := make(chan *Conn, 1)
	var serverErr error
	go func() {
		serverConn, err := ln.Accept()
		if err != nil {
			serverErr = err
			serverCh <- nil
			return
		}
		server := Server(serverConn, serverConfig)
		if err := server.Handshake(); err != nil {
			serverErr = fmt.Errorf("handshake error: %v", err)
			serverCh <- nil
			return
		}
		serverCh <- server
	}()

	client, err := Dial("tcp", ln.Addr().String(), clientConfig)
	if err != nil {
		return false, err
	}
	defer client.Close()

	server := <-serverCh
	if server == nil {
		return false, serverErr
	}

	bufLen := len(clientMsg)
	if len(serverMsg) > len(clientMsg) {
		bufLen = len(serverMsg)
	}
	buf := make([]byte, bufLen)

	client.Write([]byte(clientMsg))
	n, err := server.Read(buf)
	if err != nil || n != len(clientMsg) || string(buf[:n]) != clientMsg {
		return false, fmt.Errorf("Server read = %d, buf= %q; want %d, %s", n, buf, len(clientMsg), clientMsg)
	}

	server.Write([]byte(serverMsg))
	n, err = client.Read(buf)
	if n != len(serverMsg) || err != nil || string(buf[:n]) != serverMsg {
		return false, fmt.Errorf("Client read = %d, %v, data %q; want %d, nil, %s", n, err, buf, len(serverMsg), serverMsg)
	}

	if peer == "server" {
		return (server.verifiedDC != nil), nil
	} else if peer == "client" {
		return (client.verifiedDC != nil), nil
	} else if peer == "both" {
		return (client.verifiedDC != nil && server.verifiedDC != nil), nil
	}

	return false, nil
}

// Test the server authentication with the delegated credential extension.
func TestDCHandshakeServerAuth(t *testing.T) {
	serverMsg := "hello, client"
	clientMsg := "hello, server"

	clientConfig := dcTestConfig.Clone()
	serverConfig := dcTestConfig.Clone()
	serverConfig.GetCertificate = testServerGetCertificate

	for i, test := range dcTests {
		clientConfig.SupportDelegatedCredential = test.clientDCSupport

		for inc < len(dcTestDCScheme)-1 {
			if test.serverDCSupport {
				serverConfig.GetDelegatedCredential = testGetDelegatedCredential
				inc++
			} else {
				serverConfig.GetDelegatedCredential = nil
			}

			clientConfig.MaxVersion = test.clientMaxVers
			serverConfig.MaxVersion = test.serverMaxVers

			usedDC, err := testConnWithDC(t, clientMsg, serverMsg, clientConfig, serverConfig, "client")

			if err != nil && test.expectSuccess {
				t.Errorf("test #%d (%s) fails: %s", i+1, test.name, err.Error())
			} else if err == nil && !test.expectSuccess {
				t.Errorf("test #%d (%s) succeeds; expected failure", i+1, test.name)
			}

			if usedDC != test.expectDC {
				t.Errorf("test #%d (%s) usedDC = %v; expected %v", i+1, test.name, usedDC, test.expectDC)
			}
		}
	}

	inc = 0
}

// Test the client authentication with the delegated credential extension.
func TestDCHandshakeClientAuth(t *testing.T) {
	clientMsg := "hello, server"
	serverMsg := "hello, client"

	serverConfig := dcTestConfig.Clone()
	serverConfig.ClientAuth = RequestClientCert
	serverConfig.GetCertificate = testServerGetCertificate
	clientConfig := dcTestConfig.Clone()
	clientConfig.GetClientCertificate = testClientGetCertificate

	for i, test := range dcTests {
		serverConfig.SupportDelegatedCredential = test.serverDCSupport

		for inc < len(dcTestDCScheme)-1 {
			if test.clientDCSupport {
				clientConfig.GetDelegatedCredential = testGetDelegatedCredential
				inc++
			} else {
				clientConfig.GetDelegatedCredential = nil
			}

			serverConfig.MaxVersion = test.serverMaxVers
			clientConfig.MaxVersion = test.clientMaxVers

			usedDC, err := testConnWithDC(t, clientMsg, serverMsg, clientConfig, serverConfig, "server")

			if err != nil && test.expectSuccess {
				t.Errorf("test #%d (%s) fails: %s", i+1, test.name, err.Error())
			} else if err == nil && !test.expectSuccess {
				t.Errorf("test #%d (%s) succeeds; expected failure", i+1, test.name)
			}

			if usedDC != test.expectDC {
				t.Errorf("test #%d (%s) usedDC = %v; expected %v", i+1, test.name, usedDC, test.expectDC)
			}
		}
	}
	inc = 0
}

// Test server and client authentication with the delegated credential extension.
func TestDCHandshakeClientAndServerAuth(t *testing.T) {
	clientMsg := "hello, server"
	serverMsg := "hello, client"

	serverConfig := dcTestConfig.Clone()
	serverConfig.ClientAuth = RequestClientCert
	serverConfig.GetCertificate = testServerGetCertificate
	clientConfig := dcTestConfig.Clone()
	clientConfig.GetClientCertificate = testClientGetCertificate

	serverConfig.SupportDelegatedCredential = true
	clientConfig.SupportDelegatedCredential = true
	clientConfig.GetDelegatedCredential = testGetDelegatedCredential
	serverConfig.GetDelegatedCredential = testGetDelegatedCredential

	serverConfig.MaxVersion = VersionTLS13
	clientConfig.MaxVersion = VersionTLS13

	usedDC, err := testConnWithDC(t, clientMsg, serverMsg, clientConfig, serverConfig, "both")

	if err != nil {
		t.Errorf("test server and client auth fails: %s", err.Error())
	}

	if usedDC != true {
		t.Errorf("test server and client auth does not succed")
	}
}
