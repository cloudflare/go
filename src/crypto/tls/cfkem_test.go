// Copyright 2022 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package tls

import (
	"testing"

	"circl/kem/hybrid"
)

func TestHybridKEX(t *testing.T) {
	rsaCert := Certificate{
		Certificate: [][]byte{testRSACertificate},
		PrivateKey:  testRSAPrivateKey,
	}
	serverCerts := []Certificate{rsaCert}

	clientConfig := testConfig.Clone()
	clientConfig.CurvePreferences = []CurveID{
		kemSchemeKeyToCurveID(hybrid.Kyber512X25519()),
		X25519,
	}

	serverConfig := testConfig.Clone()
	serverConfig.CurvePreferences = []CurveID{
		kemSchemeKeyToCurveID(hybrid.Kyber512X25519()),
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
	if cli.selectedGroup != kemSchemeKeyToCurveID(hybrid.Kyber512X25519()) {
		t.Errorf("failed to negotiate hybrid group: expected %d, got %d", kemSchemeKeyToCurveID(hybrid.Kyber512X25519()), cli.selectedGroup)
	}
}
