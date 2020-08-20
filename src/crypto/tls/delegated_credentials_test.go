// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
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
//		go run generate_cert.go -ecdsa-curve P256 -host 127.0.0.1 -dc
//
var delegatorCertPEM = `-----BEGIN CERTIFICATE-----
MIIBdzCCAR2gAwIBAgIQZT2SMQ2ujsGE4TVAkGCNuzAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTIwMDgwNTA1MjM1M1oXDTIxMDgwNTA1MjM1M1ow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNEB
PGLSnwDMX/8P8fdt8c1pdFCEu4ORs65SV6lWoKPmz7l+dxzfgWXzqI9+G/fzGCmq
0MWOxnsob+xsPFOlpk6jVTBTMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggr
BgEFBQcDATAMBgNVHRMBAf8EAjAAMA8GA1UdEQQIMAaHBH8AAAEwDQYJKwYBBAGC
2kssBAAwCgYIKoZIzj0EAwIDSAAwRQIhAPGVHB65DXW5lr6GrU0eL1prYqf3/IXv
8HaRgHxPgpFNAiAjbN+tzCZMz3ygc+6DuxhnoB2XBnrJxQFCPq9r6yuIfQ==
-----END CERTIFICATE-----
`

var delegatorKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghfUUFcrzUrWtkFD0
kC2g/qtrYYFkWAD6g0e69c5zEpmhRANCAATRATxi0p8AzF//D/H3bfHNaXRQhLuD
kbOuUlepVqCj5s+5fncc34Fl86iPfhv38xgpqtDFjsZ7KG/sbDxTpaZO
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
var dcTest *dcAndPrivateKey
var dcNow time.Time
var dcTestDCScheme = ECDSAWithP521AndSHA512

func initialize() {
	// Use a static time for testing at which time the test certificates are
	// valid.
	dcNow = time.Date(2020, time.August, 18, 11, 0, 0, 234234, time.UTC)

	dcTestConfig = &Config{
		Time: func() time.Time {
			return dcNow
		},
		Rand:         zeroSource{},
		Certificates: nil,
		MinVersion:   VersionTLS13,
		MaxVersion:   VersionTLS13,
		CipherSuites: allCipherSuites(),
	}

	// The certificates of the server.
	dcTestCerts = make(map[string]*Certificate)
	var err error

	// The delegation certificate.
	dcCert := new(Certificate)
	*dcCert, err = X509KeyPair([]byte(delegatorCertPEM), []byte(delegatorKeyPEM))
	if err != nil {
		panic(err)
	}

	dcCert.Leaf, err = x509.ParseCertificate(dcCert.Certificate[0])
	if err != nil {
		panic(err)
	}
	dcTestCerts["dc"] = dcCert

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

	dcRoot, err := x509.ParseCertificate(dcCert.Certificate[len(dcCert.Certificate)-1])
	if err != nil {
		panic(err)
	}
	dcTestConfig.RootCAs.AddCert(dcRoot)

	noDcRoot, err := x509.ParseCertificate(noDcCert.Certificate[len(noDcCert.Certificate)-1])
	if err != nil {
		panic(err)
	}
	dcTestConfig.RootCAs.AddCert(noDcRoot)

	dc, sk, err := NewDelegatedCredential(dcCert, dcTestDCScheme, dcNow.Sub(dcCert.Leaf.NotBefore)+dcMaxTTL, "server")
	if err != nil {
		panic(err)
	}
	dcTest = &dcAndPrivateKey{dc, sk}
}

// TODO: generalize for all schemes
func publicKeysEqual(publicKey, publicKey2 crypto.PublicKey, algo SignatureScheme) error {
	curve := getCurve(algo)
	pk := publicKey.(*ecdsa.PublicKey)
	pk2 := publicKey2.(*ecdsa.PublicKey)

	serPubKey := elliptic.Marshal(curve, pk.X, pk.Y)
	serPubKey2 := elliptic.Marshal(curve, pk2.X, pk2.Y)
	if !bytes.Equal(serPubKey2, serPubKey) {
		return errors.New("Public Keys mismatch")
	}

	return nil
}

func equal(dc, dc2 *DelegatedCredential) error {
	if dc2.Cred.ValidTime != dc.Cred.ValidTime {
		return fmt.Errorf("ValidTime mismatch: got %d; want %d", dc2.Cred.ValidTime, dc.Cred.ValidTime)
	}

	if dc2.Cred.expCertVerfAlgo != dc.Cred.expCertVerfAlgo {
		return fmt.Errorf("scheme mismatch: got %04x; want %04x", dc2.Cred.expCertVerfAlgo, dc.Cred.expCertVerfAlgo)
	}

	return publicKeysEqual(dc.Cred.PublicKey, dc2.Cred.PublicKey, dc.Cred.expCertVerfAlgo)
}

// Test delegation and validation of credentials.
func TestDelegateCredentialsValidate(t *testing.T) {
	initialize()
	cert := dcTestCerts["dc"]
	validTime := dcNow.Sub(cert.Leaf.NotBefore) + dcMaxTTL

	delegatedCred, _, err := NewDelegatedCredential(cert, ECDSAWithP256AndSHA256, validTime, "server")
	if err != nil {
		t.Fatal(err)
	} else if delegatedCred == nil {
		t.Fatal("unable to generate a Delegated Credential")
	}

	// Valid Delegated Credential
	if v, err := delegatedCred.Validate(cert.Leaf, "server", dcNow); err != nil {
		t.Error(err)
	} else if !v {
		t.Error("generated valid Delegated Credential is rendered invalid")
	}

	// Expired Delegated Credential
	expired := dcNow.Add(dcMaxTTL).Add(time.Nanosecond)
	if v, err := delegatedCred.Validate(cert.Leaf, "server", expired); err == nil {
		t.Error("expired delegated credential validation succeeded; want failure")
	} else if v {
		t.Error("expired delegated credential is valid; want invalid")
	}

	// Test validation of Delegated Credential which TTL is too long
	invalidDelegatedCred, _, err := NewDelegatedCredential(cert, ECDSAWithP256AndSHA256, validTime+time.Second, "server")
	if err != nil {
		t.Fatal(err)
	}
	if v, err := invalidDelegatedCred.Validate(cert.Leaf, "server", dcNow); err == nil {
		t.Error("Delegated Credential validation with long TTL succeeded; want failure")
	} else if v {
		t.Error("Delegated Credential with long TTL is valid; want invalid")
	}

	shortValidTime := dcNow.Sub(cert.Leaf.NotBefore) + time.Second

	// Test validation of Delegated Credential which TTL is short
	delegatedCred, _, err = NewDelegatedCredential(cert, ECDSAWithP256AndSHA256, shortValidTime, "server")
	if err != nil {
		t.Fatal(err)
	}
	if v, err := delegatedCred.Validate(cert.Leaf, "server", dcNow); err != nil {
		t.Error(err)
	} else if !v {
		t.Error("valid Delegated Credential is invalid; want valid")
	}

	// Test validation of Delegated Credential with incorrect algorithm
	invalidDelegatedCred, _, err = NewDelegatedCredential(cert, ECDSAWithP256AndSHA256, shortValidTime, "server")
	if err != nil {
		t.Fatal(err)
	}

	//cert.Leaf.SignatureAlgorithm = x509.DSAWithSHA1
	//if v, err := invalidDelegatedCred.Validate(cert.Leaf, "server", dcNow); err == nil {
	//	t.Error("Delegated Credential validation with incorrect algorithm is valid; want failure")
	//} else if v {
	//	t.Error("invalid Delegated Credential is valid; want invalid")
	//}

	cert.Leaf.SignatureAlgorithm = x509.ECDSAWithSHA256
	delegatedCred.Algorithm = ECDSAWithP521AndSHA512

	// Test signature algorithm binding
	if v, err := delegatedCred.Validate(cert.Leaf, "server", dcNow); err != nil {
		t.Fatal(err)
	} else if !v {
		t.Error("Delegated Credential with wrong scheme is valid; want invalid")
	}

	delegatedCred.Algorithm = ECDSAWithP256AndSHA256

	// Test delegation certificate binding
	cert.Leaf.Raw[0] ^= byte(42)
	if v, err := delegatedCred.Validate(cert.Leaf, "server", dcNow); err != nil {
		t.Fatal(err)
	} else if !v {
		t.Error("Delegated Credential with wrong certificate is valid; want invalid")
	}

	// Test validation of DC using a certificate that can't delegate.
	if v, err := delegatedCred.Validate(dcTestCerts["no dc"].Leaf, "server", dcNow); err == nil {
		t.Error("Delegated Credential validation with non-delegation cert succeeded; want failure")
	} else if v {
		t.Error("Delegated Credential with non-delegation cert is valid; want invalid")
	}
}

// Test encoding/decoding of delegated credentials.
func TestDelegatedCredentialMarshal(t *testing.T) {
	initialize()
	cert := dcTestCerts["dc"]
	time := dcNow.Sub(cert.Leaf.NotBefore) + dcMaxTTL

	delegatedCred, _, err := NewDelegatedCredential(cert, ECDSAWithP256AndSHA256, time, "server")
	if err != nil {
		t.Fatal(err)
	}

	ser, err := delegatedCred.Marshal()
	if err != nil {
		t.Error(err)
	}

	delegatedCred2, err := UnmarshalDelegatedCredential(ser)
	if err != nil {
		t.Error(err)
	}

	err = equal(delegatedCred, delegatedCred2)
	if err != nil {
		t.Error(err)
	}

	if delegatedCred.Algorithm != delegatedCred2.Algorithm {
		t.Errorf("scheme mismatch: got %04x; want %04x", delegatedCred2.Algorithm, delegatedCred.Algorithm)
	}

	if !bytes.Equal(delegatedCred2.Signature, delegatedCred.Signature) {
		t.Error("Signature mismatch")
	}
}

var dcTests = []struct {
	clientDCSupport  bool
	serverDCSupport  bool
	clientSkipVerify bool
	clientMaxVers    uint16
	serverMaxVers    uint16
	expectSuccess    bool
	expectDC         bool
	name             string
}{
	{true, true, false, VersionTLS13, VersionTLS13, true, true, "tls13"},
	{true, true, true, VersionTLS13, VersionTLS13, true, true, "tls13, using server skip verify"},
	{false, true, false, VersionTLS13, VersionTLS13, true, false, "client no dc"},
	{true, false, false, VersionTLS13, VersionTLS13, true, false, "server no dc"},
}

// Checks that the client suppports a version >= 1.3 and accepts delegated
// credentials. If so, it returns the delegation certificate; otherwise it
// returns a non-delegated certificate.
func testServerGetCertificate(ch *ClientHelloInfo) (*Certificate, error) {
	versOk := false
	for _, vers := range ch.SupportedVersions {
		versOk = versOk || (vers >= uint16(VersionTLS13))
	}

	ch.SupportDelegatedCredential = true
	if versOk && ch.SupportDelegatedCredential {
		return dcTestCerts["dc"], nil
	}
	return dcTestCerts["no dc"], nil

}

// Checks that the client supports the signature algorithm supported by the test
// server, and that the server has a Delegated Credential.
func testServerGetDelegatedCredential(ch *ClientHelloInfo) (*DelegatedCredential, crypto.PrivateKey, error) {
	schemeOk := false
	for _, scheme := range ch.SignatureSchemes {
		schemeOk = schemeOk || (scheme == dcTestDCScheme)
	}

	ch.SupportDelegatedCredential = true
	if schemeOk && ch.SupportDelegatedCredential {
		return dcTest.DelegatedCredential, dcTest.privateKey, nil
	}
	return nil, nil, nil
}

// Tests the handshake and one round of application data. Returns true if the
// connection correctly used a Delegated Credential.
func testConnWithDC(t *testing.T, clientMsg, serverMsg string, clientConfig, serverConfig *Config) (bool, error) {
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
	if n != len(clientMsg) || string(buf[:n]) != clientMsg {
		return false, fmt.Errorf("Server read = %d, buf= %q; want %d, %s", n, buf, len(clientMsg), clientMsg)
	}

	server.Write([]byte(serverMsg))
	n, err = client.Read(buf)
	if n != len(serverMsg) || err != nil || string(buf[:n]) != serverMsg {
		return false, fmt.Errorf("Client read = %d, %v, data %q; want %d, nil, %s", n, err, buf, len(serverMsg), serverMsg)
	}

	return (client.verifiedDC != nil), nil
}

// Test the handshake with the delegated credential extension.
func TestDCHandshake(t *testing.T) {
	serverMsg := "hello, client"
	clientMsg := "hello, server"

	clientConfig := dcTestConfig.Clone()
	serverConfig := dcTestConfig.Clone()
	serverConfig.GetCertificate = testServerGetCertificate

	for i, test := range dcTests {
		clientConfig.SupportDelegatedCredential = test.clientDCSupport
		clientConfig.InsecureSkipVerify = test.clientSkipVerify

		if test.serverDCSupport {
			serverConfig.GetDelegatedCredential = testServerGetDelegatedCredential
		} else {
			serverConfig.GetDelegatedCredential = nil
		}

		clientConfig.MaxVersion = test.clientMaxVers
		serverConfig.MaxVersion = test.serverMaxVers

		usedDC, err := testConnWithDC(t, clientMsg, serverMsg, clientConfig, serverConfig)
		if err != nil && test.expectSuccess {
			t.Errorf("test #%d (%s) fails: %s", i+1, test.name, err)
		} else if err == nil && !test.expectSuccess {
			t.Errorf("test #%d (%s) succeeds; expected failure", i+1, test.name)
		}

		if usedDC != test.expectDC {
			t.Errorf("test #%d (%s) usedDC = %v; expected %v", i+1, test.name, usedDC, test.expectDC)
		}
	}
}
