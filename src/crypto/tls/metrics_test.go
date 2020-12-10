// Copyright 2020 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package tls

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"testing"
	"time"
)

type testTimingInfo struct {
	serverTimingInfo CFEventTLS13ServerHandshakeTimingInfo
	clientTimingInfo CFEventTLS13ClientHandshakeTimingInfo
}

func (t testTimingInfo) isMonotonicallyIncreasing() bool {
	serverIsMonotonicallyIncreasing :=
		t.serverTimingInfo.ProcessClientHello < t.serverTimingInfo.WriteServerHello &&
			t.serverTimingInfo.WriteServerHello < t.serverTimingInfo.WriteEncryptedExtensions &&
			t.serverTimingInfo.WriteEncryptedExtensions < t.serverTimingInfo.WriteCertificate &&
			t.serverTimingInfo.WriteCertificate < t.serverTimingInfo.WriteCertificateVerify &&
			t.serverTimingInfo.WriteCertificateVerify < t.serverTimingInfo.WriteServerFinished &&
			t.serverTimingInfo.WriteServerFinished < t.serverTimingInfo.ReadCertificate &&
			t.serverTimingInfo.ReadCertificate < t.serverTimingInfo.ReadCertificateVerify &&
			t.serverTimingInfo.ReadCertificateVerify < t.serverTimingInfo.ReadClientFinished

	clientIsMonotonicallyIncreasing :=
		t.clientTimingInfo.WriteClientHello < t.clientTimingInfo.ProcessServerHello &&
			t.clientTimingInfo.ProcessServerHello < t.clientTimingInfo.ReadEncryptedExtensions &&
			t.clientTimingInfo.ReadEncryptedExtensions < t.clientTimingInfo.ReadCertificate &&
			t.clientTimingInfo.ReadCertificate < t.clientTimingInfo.ReadCertificateVerify &&
			t.clientTimingInfo.ReadCertificateVerify < t.clientTimingInfo.ReadServerFinished &&
			t.clientTimingInfo.ReadServerFinished < t.clientTimingInfo.WriteCertificate &&
			t.clientTimingInfo.WriteCertificate < t.clientTimingInfo.WriteCertificateVerify &&
			t.clientTimingInfo.WriteCertificateVerify < t.clientTimingInfo.WriteClientFinished

	return (serverIsMonotonicallyIncreasing && clientIsMonotonicallyIncreasing)
}

func (r *testTimingInfo) eventHandler(event CFEvent) {
	switch e := event.(type) {
	case CFEventTLS13ServerHandshakeTimingInfo:
		r.serverTimingInfo = e
	case CFEventTLS13ClientHandshakeTimingInfo:
		r.clientTimingInfo = e
	}
}

func runHandshake(t *testing.T, clientConfig, serverConfig *Config) (timingState testTimingInfo, err error) {
	const sentinel = "SENTINEL\n"
	c, s := localPipe(t)
	errChan := make(chan error)

	go func() {
		cli := Client(c, clientConfig)
		cCtx := context.WithValue(context.Background(), CFEventHandlerContextKey{}, timingState.eventHandler)
		err := cli.HandshakeContext(cCtx)
		if err != nil {
			errChan <- fmt.Errorf("client: %v", err)
			c.Close()
			return
		}
		defer cli.Close()
		buf, err := ioutil.ReadAll(cli)
		if err != nil {
			t.Errorf("failed to call cli.Read: %v", err)
		}
		if got := string(buf); got != sentinel {
			t.Errorf("read %q from TLS connection, but expected %q", got, sentinel)
		}
		errChan <- nil
	}()

	server := Server(s, serverConfig)
	sCtx := context.WithValue(context.Background(), CFEventHandlerContextKey{}, timingState.eventHandler)
	err = server.HandshakeContext(sCtx)
	if err == nil {
		if _, err := io.WriteString(server, sentinel); err != nil {
			t.Errorf("failed to call server.Write: %v", err)
		}
		if err := server.Close(); err != nil {
			t.Errorf("failed to call server.Close: %v", err)
		}
		err = <-errChan
	} else {
		s.Close()
		<-errChan
	}

	return
}

func TestTLS13HandshakeTiming(t *testing.T) {
	issuer, err := x509.ParseCertificate(testRSACertificateIssuer)
	if err != nil {
		panic(err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(issuer)

	const serverName = "example.golang"

	baseConfig := &Config{
		Time:         time.Now,
		Rand:         zeroSource{},
		Certificates: make([]Certificate, 1),
		MaxVersion:   VersionTLS13,
		RootCAs:      rootCAs,
		ClientCAs:    rootCAs,
		ClientAuth:   RequireAndVerifyClientCert,
		ServerName:   serverName,
	}
	baseConfig.Certificates[0].Certificate = [][]byte{testRSACertificate}
	baseConfig.Certificates[0].PrivateKey = testRSAPrivateKey

	clientConfig := baseConfig.Clone()
	serverConfig := baseConfig.Clone()

	ts, err := runHandshake(t, clientConfig, serverConfig)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	if !ts.isMonotonicallyIncreasing() {
		t.Fatalf("Timing information is not monotonic")
	}
}
