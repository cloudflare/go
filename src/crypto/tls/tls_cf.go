// Copyright 2021 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package tls

import (
	circlPki "circl/pki"
	circlSign "circl/sign"

	"circl/sign/ed448"
	"circl/sign/eddilithium3"
	"circl/sign/eddilithium4"
	"time"
)

const (
	// Constants for ECH status events.
	echStatusBypassed = 1 + iota
	echStatusInner
	echStatusOuter
)

// To add a signature scheme from Circl
//
//   1. make sure it implements TLSScheme and CertificateScheme,
//   2. follow the instructions in crypto/x509/x509_cf.go
//   3. add a signature<NameOfAlg> to the iota in common.go
//   4. add row in the circlSchemes lists below

var circlSchemes = [...]struct {
	sigType uint8
	scheme  circlSign.Scheme
}{
	{signatureEdDilithium3, eddilithium3.Scheme()},
	{signatureEdDilithium4, eddilithium4.Scheme()},
	{signatureEd448, ed448.Scheme()},
}

func circlSchemeBySigType(sigType uint8) circlSign.Scheme {
	for _, cs := range circlSchemes {
		if cs.sigType == sigType {
			return cs.scheme
		}
	}
	return nil
}

func sigTypeByCirclScheme(scheme circlSign.Scheme) uint8 {
	for _, cs := range circlSchemes {
		if cs.scheme == scheme {
			return cs.sigType
		}
	}
	return 0
}

func init() {
	for _, cs := range circlSchemes {
		supportedSignatureAlgorithms = append(supportedSignatureAlgorithms,
			SignatureScheme(cs.scheme.(circlPki.TLSScheme).TLSIdentifier()))
	}
}

// CFEvent is a value emitted at various points in the handshake that is
// handled by the callback Config.CFEventHandler.
type CFEvent interface {
	Name() string
}

func experimentName(c *Conn) string {
	// Reports the experiment number
	exp := "exp"
	alg := ""
	switch true {
	case c.didKEMTLS:
		exp += "3"
		alg += c.verifiedDC.algorithm.String()
		break
	case c.didPQTLS:
		exp += "2"
		alg += c.verifiedDC.algorithm.String()
		break
	case c.verifiedDC != nil:
		exp += "1"
		alg += c.verifiedDC.algorithm.String()
		break
	case c.verifiedDC == nil:
		exp += "0"
		alg = CipherSuiteName(c.cipherSuite)
		break
	default:
		break
	}
	return exp + "_" + alg
}

// CFEventTLS13ClientHandshakeTimingInfo carries intra-stack time durations for
// TLS 1.3 client-state machine changes. It can be used for tracking metrics
// during a connection. Some durations may be sensitive, such as the amount of
// time to process a particular handshake message, so this event should only be
// used for experimental purposes.
type CFEventTLS13ClientHandshakeTimingInfo struct {
	timer                   func() time.Time
	start                   time.Time
	total                   time.Time
	WriteClientHello        time.Duration
	ProcessServerHello      time.Duration
	ReadEncryptedExtensions time.Duration
	ReadCertificate         time.Duration
	ReadCertificateVerify   time.Duration

	ReadServerFinished     time.Duration
	WriteCertificate       time.Duration
	WriteCertificateVerify time.Duration
	WriteClientFinished    time.Duration

	WriteKEMCiphertext time.Duration
	ReadKEMCiphertext  time.Duration
	FullProtocol       time.Duration

	ExperimentName string
}

// Name is required by the CFEvent interface.
func (e CFEventTLS13ClientHandshakeTimingInfo) Name() string {
	return "TLS13ClientHandshakeTimingInfo"
}

func (e CFEventTLS13ClientHandshakeTimingInfo) elapsedTime() time.Duration {
	if e.timer == nil {
		return 0
	}
	return e.timer().Sub(e.start)
}

func (e *CFEventTLS13ClientHandshakeTimingInfo) reset() {
	e.start = e.timer()
}

func (e *CFEventTLS13ClientHandshakeTimingInfo) finish() {
	e.FullProtocol = e.timer().Sub(e.total)
}

func createTLS13ClientHandshakeTimingInfo(timerFunc func() time.Time) CFEventTLS13ClientHandshakeTimingInfo {
	timer := time.Now
	if timerFunc != nil {
		timer = timerFunc
	}
	now := timer()
	return CFEventTLS13ClientHandshakeTimingInfo{
		timer: timer,
		start: now,
		total: now,
	}
}

// CFEventTLS13ServerHandshakeTimingInfo carries intra-stack time durations
// for TLS 1.3 state machine changes. It can be used for tracking metrics during a
// connection. Some durations may be sensitive, such as the amount of time to
// process a particular handshake message, so this event should only be used
// for experimental purposes.
type CFEventTLS13ServerHandshakeTimingInfo struct {
	timer                    func() time.Time
	start                    time.Time
	total                    time.Time
	ProcessClientHello       time.Duration
	WriteServerHello         time.Duration
	WriteEncryptedExtensions time.Duration
	WriteCertificate         time.Duration
	WriteCertificateVerify   time.Duration

	WriteServerFinished   time.Duration
	ReadCertificate       time.Duration
	ReadCertificateVerify time.Duration
	ReadClientFinished    time.Duration

	ReadKEMCiphertext  time.Duration
	WriteKEMCiphertext time.Duration
	FullProtocol       time.Duration

	ExperimentName string
}

// Name is required by the CFEvent interface.
func (e CFEventTLS13ServerHandshakeTimingInfo) Name() string {
	return "TLS13ServerHandshakeTimingInfo"
}

func (e CFEventTLS13ServerHandshakeTimingInfo) elapsedTime() time.Duration {
	if e.timer == nil {
		return 0
	}
	return e.timer().Sub(e.start)
}

func (e *CFEventTLS13ServerHandshakeTimingInfo) reset() {
	e.start = e.timer()
}

func (e *CFEventTLS13ServerHandshakeTimingInfo) finish() {
	e.FullProtocol = e.timer().Sub(e.total)
}

func createTLS13ServerHandshakeTimingInfo(timerFunc func() time.Time) CFEventTLS13ServerHandshakeTimingInfo {
	timer := time.Now
	if timerFunc != nil {
		timer = timerFunc
	}
	now := timer()
	return CFEventTLS13ServerHandshakeTimingInfo{
		timer: timer,
		start: now,
		total: now,
	}
}

// CFEventECHClientStatus is emitted once it is known whether the client
// bypassed, offered, or greased ECH.
type CFEventECHClientStatus int

// Bypassed returns true if the client bypassed ECH.
func (e CFEventECHClientStatus) Bypassed() bool {
	return e == echStatusBypassed
}

// Offered returns true if the client offered ECH.
func (e CFEventECHClientStatus) Offered() bool {
	return e == echStatusInner
}

// Greased returns true if the client greased ECH.
func (e CFEventECHClientStatus) Greased() bool {
	return e == echStatusOuter
}

// Name is required by the CFEvent interface.
func (e CFEventECHClientStatus) Name() string {
	return "ech client status"
}

// CFEventECHServerStatus is emitted once it is known whether the client
// bypassed, offered, or greased ECH.
type CFEventECHServerStatus int

// Bypassed returns true if the client bypassed ECH.
func (e CFEventECHServerStatus) Bypassed() bool {
	return e == echStatusBypassed
}

// Accepted returns true if the client offered ECH.
func (e CFEventECHServerStatus) Accepted() bool {
	return e == echStatusInner
}

// Rejected returns true if the client greased ECH.
func (e CFEventECHServerStatus) Rejected() bool {
	return e == echStatusOuter
}

// Name is required by the CFEvent interface.
func (e CFEventECHServerStatus) Name() string {
	return "ech server status"
}

// CFEventECHPublicNameMismatch is emitted if the outer SNI does not match
// match the public name of the ECH configuration. Note that we do not record
// the outer SNI in order to avoid collecting this potentially sensitive data.
type CFEventECHPublicNameMismatch struct{}

// Name is required by the CFEvent interface.
func (e CFEventECHPublicNameMismatch) Name() string {
	return "ech public name does not match outer sni"
}
