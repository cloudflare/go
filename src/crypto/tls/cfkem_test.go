// Copyright 2022 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package tls

import (
	"fmt"
	"testing"

	"circl/kem"
	"circl/kem/hybrid"
)

func testHybridKEX(t *testing.T, scheme kem.Scheme, clientPQ bool, serverPQ bool) {
	var clientSelectedKEX *CurveID
	var retry bool

	rsaCert := Certificate{
		Certificate: [][]byte{testRSACertificate},
		PrivateKey:  testRSAPrivateKey,
	}
	serverCerts := []Certificate{rsaCert}

	clientConfig := testConfig.Clone()
	if clientPQ {
		clientConfig.CurvePreferences = []CurveID{
			kemSchemeKeyToCurveID(scheme),
			X25519,
		}
	}
	clientConfig.CFEventHandler = func(ev CFEvent) {
		switch e := ev.(type) {
		case CFEventTLS13NegotiatedKEX:
			clientSelectedKEX = &e.KEX
		case CFEventTLS13HRR:
			retry = true
		}
	}

	serverConfig := testConfig.Clone()
	if serverPQ {
		serverConfig.CurvePreferences = []CurveID{
			kemSchemeKeyToCurveID(scheme),
			X25519,
		}
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
	var expectedKEX CurveID
	var expectedRetry bool
	if clientPQ && serverPQ {
		expectedKEX = kemSchemeKeyToCurveID(scheme)
	} else {
		expectedKEX = X25519
	}
	if clientPQ && !serverPQ {
		expectedRetry = true
	}
	if *clientSelectedKEX != expectedKEX {
		t.Errorf("failed to negotiate: expected %d, got %d",
			expectedKEX, *clientSelectedKEX)
	}
	if expectedRetry != retry {
		t.Errorf("Expected retry=%v, got retry=%v", expectedRetry, retry)
	}
}

func TestHybridKEX(t *testing.T) {
	run := func(scheme kem.Scheme, clientPQ, serverPQ bool) {
		t.Run(fmt.Sprintf("%s serverPQ:%v clientPQ:%v", scheme.Name(),
			serverPQ, clientPQ), func(t *testing.T) {
			testHybridKEX(t, scheme, clientPQ, serverPQ)
		})
	}
	for _, scheme := range []kem.Scheme{
		hybrid.Kyber512X25519(),
		hybrid.Kyber768X25519(),
	} {
		run(scheme, true, true)
		run(scheme, true, false)
		run(scheme, false, true)
	}
}
