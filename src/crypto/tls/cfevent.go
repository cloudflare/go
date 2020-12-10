// Copyright 2023 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package tls

import "time"

// CFEvent is a value emitted at various points in the handshake that is
// handled by the callback Config.CFEventHandler.
type CFEvent interface {
	Name() string
}

// CFEventTLS13ClientHandshakeTimingInfo carries intra-stack time durations for
// TLS 1.3 client-state machine changes. It can be used for tracking metrics
// during a connection. Some durations may be sensitive, such as the amount of
// time to process a particular handshake message, so this event should only be
// used for experimental purposes.
type CFEventTLS13ClientHandshakeTimingInfo struct {
	timer                   func() time.Time
	start                   time.Time
	WriteClientHello        time.Duration
	ProcessServerHello      time.Duration
	ReadEncryptedExtensions time.Duration
	ReadCertificate         time.Duration
	ReadCertificateVerify   time.Duration
	ReadServerFinished      time.Duration
	WriteCertificate        time.Duration
	WriteCertificateVerify  time.Duration
	WriteClientFinished     time.Duration
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

func createTLS13ClientHandshakeTimingInfo(timerFunc func() time.Time) CFEventTLS13ClientHandshakeTimingInfo {
	timer := time.Now
	if timerFunc != nil {
		timer = timerFunc
	}

	return CFEventTLS13ClientHandshakeTimingInfo{
		timer: timer,
		start: timer(),
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
	ProcessClientHello       time.Duration
	WriteServerHello         time.Duration
	WriteEncryptedExtensions time.Duration
	WriteCertificate         time.Duration
	WriteCertificateVerify   time.Duration
	WriteServerFinished      time.Duration
	ReadCertificate          time.Duration
	ReadCertificateVerify    time.Duration
	ReadClientFinished       time.Duration
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

func createTLS13ServerHandshakeTimingInfo(timerFunc func() time.Time) CFEventTLS13ServerHandshakeTimingInfo {
	timer := time.Now
	if timerFunc != nil {
		timer = timerFunc
	}

	return CFEventTLS13ServerHandshakeTimingInfo{
		timer: timer,
		start: timer(),
	}
}
