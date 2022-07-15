// Copyright 2022 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package tls

import (
	"testing"

	"circl/kem"
	"circl/kem/hybrid"
)

func TestHybridKEX(t *testing.T) {
	for _, scheme := range []kem.Scheme{
		hybrid.Kyber512X25519(),
		hybrid.Kyber768X25519(),
	} {
		t.Run(scheme.Name(), func(t *testing.T) {
			var clientSelectedKEX *CurveID
			rsaCert := Certificate{
				Certificate: [][]byte{testRSACertificate},
				PrivateKey:  testRSAPrivateKey,
			}
			serverCerts := []Certificate{rsaCert}

			clientConfig := testConfig.Clone()
			clientConfig.CurvePreferences = []CurveID{
				kemSchemeKeyToCurveID(scheme),
				X25519,
			}
			clientConfig.CFEventHandler = func(ev CFEvent) {
				switch e := ev.(type) {
				case CFEventTLS13NegotiatedKEX:
					clientSelectedKEX = &e.KEX
				}
			}

			serverConfig := testConfig.Clone()
			serverConfig.CurvePreferences = []CurveID{
				kemSchemeKeyToCurveID(scheme),
				X25519,
			}
			serverConfig.Certificates = serverCerts

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
			if clientSelectedKEX == nil {
				t.Error("No TLS 1.3 KEX happened?")
			}
			if *clientSelectedKEX != kemSchemeKeyToCurveID(scheme) {
				t.Errorf("failed to negotiate hybrid group: expected %d, got %d",
					kemSchemeKeyToCurveID(scheme), *clientSelectedKEX)
			}
		})
	}
}
