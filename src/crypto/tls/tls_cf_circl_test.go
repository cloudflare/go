// Copyright 2022 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package tls

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/eddilithium3"
)

func TestPQSignatureSchemes(t *testing.T) {
	pqCert := createPQCert(t, eddilithium3.Scheme())
	rsaCert := Certificate{
		Certificate: [][]byte{testRSACertificate},
		PrivateKey:  testRSAPrivateKey,
	}
	pqAndRsaCerts := []Certificate{pqCert, rsaCert}
	rsaOnlyCerts := []Certificate{rsaCert}

	cases := []struct {
		clientPQ, serverPQ bool
		serverCerts        []Certificate
		expectedCertSigAlg x509.SignatureAlgorithm
	}{
		{
			clientPQ:           false,
			serverPQ:           false,
			serverCerts:        pqAndRsaCerts,
			expectedCertSigAlg: x509.SHA256WithRSA,
		},
		{
			clientPQ:           false,
			serverPQ:           true,
			serverCerts:        pqAndRsaCerts,
			expectedCertSigAlg: x509.SHA256WithRSA,
		},
		{
			// PQ is always selected when the clients supports it.
			clientPQ:           true,
			serverPQ:           false,
			serverCerts:        pqAndRsaCerts,
			expectedCertSigAlg: x509.PureEdDilithium3,
		},
		{
			clientPQ:           true,
			serverPQ:           true,
			serverCerts:        pqAndRsaCerts,
			expectedCertSigAlg: x509.PureEdDilithium3,
		},
		{
			clientPQ:           true,
			serverPQ:           true,
			serverCerts:        rsaOnlyCerts,
			expectedCertSigAlg: x509.SHA256WithRSA,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			clientConfig := testConfig.Clone()
			clientConfig.PQSignatureSchemesEnabled = tc.clientPQ

			serverConfig := testConfig.Clone()
			serverConfig.PQSignatureSchemesEnabled = tc.serverPQ
			serverConfig.Certificates = tc.serverCerts

			c, s := localPipe(t)
			done := make(chan error)
			defer c.Close()

			go func() {
				defer s.Close()
				done <- Server(s, serverConfig).Handshake()
			}()

			cli := Client(c, clientConfig)
			clientErr := cli.Handshake()
			serverErr := <-done
			if clientErr != nil {
				t.Errorf("client error: %s", clientErr)
			}
			if serverErr != nil {
				t.Errorf("server error: %s", serverErr)
			}
			serverCerts := cli.ConnectionState().PeerCertificates
			if len(serverCerts) != 1 {
				t.Errorf("expected 1 server cert, got %d", len(serverCerts))
			}
			if serverCerts[0].SignatureAlgorithm != tc.expectedCertSigAlg {
				t.Errorf("unexpected signature algorithm, got %s want %s", serverCerts[0].SignatureAlgorithm, tc.expectedCertSigAlg)
			}
		})
	}
}

func createPQCert(t *testing.T, sch sign.Scheme) Certificate {
	seed := make([]byte, sch.SeedSize())
	pub, priv := sch.DeriveKey(seed)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}

	return Certificate{
		Certificate: [][]byte{cert},
		PrivateKey:  priv,
	}
}
