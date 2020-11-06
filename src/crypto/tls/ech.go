// Copyright 2020 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/tls/internal/hpke"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

const (
	// Constants for TLS operations
	echTls13LabelAcceptConfirm = "ech accept confirmation"

	// Constants for HPKE operations
	echHpkeInfoInnerDigest = "tls ech inner digest"
	echHpkeInfoConfigId    = "tls ech config id"
	echHpkeInfoSetup       = "tls ech"
	echHpkeHrrKeyExporter  = "tls ech hrr key"
	echHpkeHrrKeyId        = "hrr key"
	echHpkeHrrKeyLen       = 32

	// Constants for ECH status events
	echStatusBypassed = 1 + iota
	echStatusInner
	echStatusOuter
)

// EXP_EventECHClientStatus is emitted once it is known whether the client
// bypassed, offered, or greased ECH.
//
// NOTE: This API is EXPERIMENTAL and subject to change.
type EXP_EventECHClientStatus int

// Bypassed returns true if the client bypassed ECH.
func (e EXP_EventECHClientStatus) Bypassed() bool {
	return e == echStatusBypassed
}

// Offered returns true if the client offered ECH.
func (e EXP_EventECHClientStatus) Offered() bool {
	return e == echStatusInner
}

// Greased returns true if the client greased ECH.
func (e EXP_EventECHClientStatus) Greased() bool {
	return e == echStatusOuter
}

// Name is required by the EXP_Event interface.
func (e EXP_EventECHClientStatus) Name() string {
	return "ech client status"
}

// EXP_EventECHServerStatus is emitted once it is known whether the client
// bypassed, offered, or greased ECH.
//
// NOTE: This API is EXPERIMENTAL and subject to change.
type EXP_EventECHServerStatus int

// Bypassed returns true if the client bypassed ECH.
func (e EXP_EventECHServerStatus) Bypassed() bool {
	return e == echStatusBypassed
}

// Accepted returns true if the client offered ECH.
func (e EXP_EventECHServerStatus) Accepted() bool {
	return e == echStatusInner
}

// Rejected returns true if the client greased ECH.
func (e EXP_EventECHServerStatus) Rejected() bool {
	return e == echStatusOuter
}

// Name is required by the EXP_Event interface.
func (e EXP_EventECHServerStatus) Name() string {
	return "ech server status"
}

// A dummy client-facing server public key used to generate covertext for the
// ECH extension. This is a random 32-byte string, which will be interpreted as
// an X25519 public key.
var echDummyX25519PublicKey = []byte{
	143, 38, 37, 36, 12, 6, 229, 30, 140, 27, 167, 73, 26, 100, 203, 107, 216,
	81, 163, 222, 52, 211, 54, 210, 46, 37, 78, 216, 157, 97, 241, 244,
}

// TODO(cjpatton): "[When offering ECH, the client] MUST NOT offer to resume any
// session for TLS 1.2 and below [in ClientHelloInner]."
//
// TODO(cjpatton): "[When offering ECH, the client] MUST NOT include the
// "pre_shared_key" extension [in ClientHelloOuter]." This is a "don't stick
// out" issue.
//
// TODO(cjpatton): Implement client-side padding.
func (c *Conn) echOfferOrGrease(helloBase *clientHelloMsg) (hello, helloInner *clientHelloMsg, err error) {
	config := c.config

	if !config.ECHEnabled ||
		(c.hrrTriggered && testingECHTriggerBypassAfterHRR) ||
		(!c.hrrTriggered && testingECHTriggerBypassBeforeHRR) {
		// Bypass ECH without providing covertext.
		return helloBase, nil, nil
	}

	// Decide whether to offer the ECH extension in this connection, If offered,
	// then hello is set to the ClientHelloOuter and helloInner is set to the
	// ClientHelloInner.
	if echConfig := config.echSelectConfig(); echConfig != nil &&
		config.maxSupportedVersion() >= VersionTLS13 {

		// Construct the ClientHelloInner.
		//
		// Make a copy of helloBase, add an empty ECH extension, and generate a
		// fresh random value.
		helloInner = new(clientHelloMsg)
		*helloInner = *helloBase

		// Set "encrypted_client_hello" with an empty payload.
		helloInner.encryptedClientHelloOffered = true

		// Ensure that only TLS 1.3 and above are offered.
		if v := helloInner.supportedVersions; v[len(v)-1] < VersionTLS13 {
			return nil, nil, errors.New("tls: ech: TLS 1.3 required")
		}

		// Set "random".
		if len(c.ech.hrrInnerRandom) == 0 {
			// Generate a fresh "random".
			helloInner.random = make([]byte, 32)
			_, err := io.ReadFull(config.rand(), helloInner.random)
			if err != nil {
				return nil, nil, errors.New("tls: short read from Rand: " + err.Error())
			}
		} else {
			// After HRR, use the "random" sent in the first ClientHelloInner.
			helloInner.random = c.ech.hrrInnerRandom
		}

		// Construct the EncodedClientHelloInner.
		//
		// NOTE(cjpatton): It would be nice to incorporate more extensions, but
		// "key_share" is the last extension to appear in the ClientHello before
		// "pre_shared_key". As a result, the only contiguous sequence of outer
		// extensions that contains "key_share" is "key_share" itself. Note that
		// we cannot change the order of extensions in the ClientHello, as the
		// unit tests expect "key_share" to be second to last extension.
		outerExtensions := []uint16{extensionKeyShare}
		if testingECHOuterExtMany {
			// NOTE(cjpatton): Incorporating this particular sequence does not
			// yield significant savings. However, it's useful to test that our
			// server correctly handles a sequence of compressed extensions and
			// not just one.
			outerExtensions = []uint16{
				extensionStatusRequest,
				extensionSupportedCurves,
				extensionSupportedPoints,
			}
		} else if testingECHOuterExtNone {
			outerExtensions = nil
		}
		encodedHelloInner, ok := echEncodeClientHelloInner(helloInner.marshal(), outerExtensions)
		if !ok {
			return nil, nil, errors.New("tls: ech: encoding of EncodedClientHelloInner failed")
		}

		// Construct the ClientHelloOuter.
		//
		// Generate a fresh ClientHello, but replace "key_share" and "random",
		// and "session_id" with the values generated for helloBase and set
		// "server_name" to be the client-facing server.
		hello, _, err = c.makeClientHello(config.MinVersion)
		if err != nil {
			return nil, nil, fmt.Errorf("tls: ech: %s", err)
		}

		// Set "random".
		hello.random = helloBase.random

		// Set "session_id" to be the same as ClientHelloInner.
		hello.sessionId = helloBase.sessionId

		// Set "key_share" to the same as ClientHelloInner.
		hello.keyShares = helloBase.keyShares

		// Set "server_name" to be the client-facing server.
		hello.serverName = hostnameInSNI(string(echConfig.rawPublicName))

		// Encrypt EncodedClientHelloInner.
		//
		// AEAD encryption authenticates the ClientHelloOuter sans the
		// "encrypted_client_hello" extension.
		helloOuterAad := hello.marshal()

		// Prepare the encryption context. Note that c.ech.hrrPsk is initially
		// nil, meaning no PSK is used for encrypting the first ClientHelloInner
		// in case of HRR.
		ctx, enc, err := echConfig.setupClientContext(c.ech.hrrPsk, config.rand())
		if err != nil {
			return nil, nil, fmt.Errorf("tls: ech: %s", err)
		}

		// Finish ClientHelloOuter.
		var ech echClient
		ech.handle.suite = ctx.cipherSuite()
		ech.handle.configId = ctx.configId(echConfig.raw)
		ech.handle.enc = enc
		ech.payload = ctx.seal(helloOuterAad, encodedHelloInner)
		if testingECHTriggerPayloadDecryptError {
			// Send inauthentic payload.
			ech.payload[0] ^= 0xff
		}
		hello.encryptedClientHelloOffered = true
		hello.encryptedClientHello = ech.marshal()

		// Update the HRR pre-shared-key. This is used to encrypt the second
		// ClientHelloInner in case the server sends an HRR.
		c.ech.hrrPsk = ctx.hrrPsk()

		// Record the "random" sent in the ClientHelloInner. This value will be
		// used for the second ClientHelloInner in case the server sends an HRR.
		c.ech.hrrInnerRandom = helloInner.random

		// Offer ECH.
		c.ech.offered = true
		helloInner.raw = nil
		hello.raw = nil
		return hello, helloInner, nil
	}

	hello = new(clientHelloMsg)
	*hello = *helloBase

	// Produce covertext for the ECH extension.
	//
	// Using a hard-coded KEM public key, generate a fresh encapsulated key
	// "enc". Generate a random "config_id" and "payload" of appropriate length.
	hpkeSuite, err := hpkeAssembleCipherSuite(dummyKemId, dummyKdfId, dummyAeadId)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: ech covertext: %s", err)
	}
	pk, err := hpkeSuite.KEM.Deserialize(echDummyX25519PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: ech covertext: %s", err)
	}

	// Compute the dummy context handle ("cipher_suite", "config_id", and
	// "enc").
	var dummyEch echClient
	dummyEch.handle.suite.kdfId = dummyKdfId
	dummyEch.handle.suite.aeadId = dummyAeadId
	if !c.hrrTriggered {
		dummyEch.handle.configId = make([]byte, dummyKdfOutputLen)
		if _, err = io.ReadFull(config.rand(), dummyEch.handle.configId); err != nil {
			return nil, nil, fmt.Errorf("tls: ech covertext: %s", err)
		}
		c.ech.hrrConfigId = dummyEch.handle.configId
	} else {
		// After HRR, the server checks these fields match.
		dummyEch.handle.configId = c.ech.hrrConfigId
	}
	dummyEch.handle.enc, _, err = hpke.SetupBaseS(hpkeSuite, config.rand(), pk, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: ech covertext: %s", err)
	}

	// Compute the dummy "payload".
	dummyEncodedHelloInnerLen := 100 // TODO(cjpatton): Compute this correctly.
	dummyEch.payload = make([]byte, dummyEncodedHelloInnerLen+dummyAeadOverheadLen)
	if _, err = io.ReadFull(config.rand(), dummyEch.payload); err != nil {
		return nil, nil, fmt.Errorf("tls: ech covertext: %s", err)
	}

	// Add the dummy ECH extension to the ClientHello.
	hello.encryptedClientHelloOffered = true
	hello.encryptedClientHello = dummyEch.marshal()

	// Bypass ECH and provide covertext.
	c.ech.offered = false
	c.ech.greased = true
	hello.raw = nil
	return hello, nil, nil
}

func (c *Conn) echAcceptOrBypass(hello *clientHelloMsg) (*clientHelloMsg, error) {
	config := c.config
	echProvider := config.ServerECHProvider

	// Decide whether to bypass ECH.
	echSentBeforeHrr := c.ech.offered || c.ech.greased
	if !config.echCanAccept() ||
		!hello.encryptedClientHelloOffered ||
		len(hello.encryptedClientHello) == 0 {
		if c.hrrTriggered && echSentBeforeHrr {
			// Detect illegal second ClientHello.
			c.sendAlert(alertIllegalParameter)
			return nil, errors.New("ech: hrr: bypass after offer")
		}

		// Bypass ECH.
		return hello, nil
	}

	if c.hrrTriggered && !echSentBeforeHrr {
		// Detect illegal second ClientHello.
		c.sendAlert(alertIllegalParameter)
		return nil, errors.New("ech: hrr: offer after bypass")
	}

	// Parse the payload of the ECH extension.
	ech, err := echUnmarshalClient(hello.encryptedClientHello)
	if err != nil {
		c.sendAlert(alertIllegalParameter)
		return nil, fmt.Errorf("ech: %s", err)
	}

	if c.hrrTriggered && !bytes.Equal(ech.handle.configId, c.ech.hrrConfigId) {
		// Detect illegal second ClientHello
		c.sendAlert(alertIllegalParameter)
		return nil, errors.New("ech: hrr: illegal handle in second ClientHello")
	}
	c.ech.hrrConfigId = ech.handle.configId

	// Ask the ECH provider for the decryption context. Note that c.ech.hrrPsk
	// is initially nil, meaning no PSK is used for encrypting the first
	// ClientHelloInner.
	res := echProvider.GetContext(ech.handle.marshal(), c.ech.hrrPsk, extensionECH)
	reject := func() (*clientHelloMsg, error) {
		if c.hrrTriggered && c.ech.accepted {
			// ECH was accepted prior to HRR then rejected after. Because the
			// configuration identifier is the same in the first ClientHello as
			// it is in the second, this indicates a server failure, likely due
			// to the ECH key being rotated.
			c.sendAlert(alertInternalError)
			return nil, errors.New("ech: hrr: reject after accept")
		}

		// Presume the client sent a dummy extension until we have information
		// to the contrary. We won't know whether the client intended to offer
		// ECH unless it sends an "ech_required" alert.
		c.ech.greased = true

		// Send retry configs just in case our presumption is wrong and the
		// client intended to offer ECH.
		c.ech.retryConfigs = res.RetryConfigs

		// Proceed with ClientHelloOuter.
		return hello, nil
	}

	if res.Status == ECHProviderAbort {
		// This condition indicates the connection must be aborted.
		c.sendAlert(alert(res.Alert))
		return nil, fmt.Errorf("ech: %s", res.Error)
	}

	if res.Status == ECHProviderReject {
		// Reject ECH.
		return reject()
	}

	if res.Status != ECHProviderSuccess {
		// This shouldn't happen.
		c.sendAlert(alertInternalError)
		return nil, errors.New("ech: expected success")
	}

	ctx, err := echUnmarshalServerContext(res.Context)
	if err != nil {
		c.sendAlert(alertInternalError)
		return nil, fmt.Errorf("ech: %s", err)
	}

	helloOuterAad, ok := encodeClientHelloOuterAAD(hello.raw, extensionECH)
	if !ok {
		// This occurs if the ClientHelloOuter is malformed. This values was
		// already parsed into `hello`, so this should not happen.
		c.sendAlert(alertInternalError)
		return nil, fmt.Errorf("ech: failed to compute ClientHelloOuterAAD")
	}

	rawEncodedHelloInner, err := ctx.open(helloOuterAad, ech.payload)
	if err != nil {
		if c.hrrTriggered && c.ech.accepted {
			// Don't reject after accept, as this would result in processing the
			// ClientHelloOuter after processing the ClientHelloInner.
			c.sendAlert(alertDecryptError)
			return nil, fmt.Errorf("ech: hrr: decryption failure after acceptance: %s", err)
		}

		// Reject ECH.
		return reject()
	}

	rawHelloInner, ok := echDecodeClientHelloInner(rawEncodedHelloInner, hello.marshal(), hello.sessionId)
	if !ok {
		c.sendAlert(alertIllegalParameter)
		return nil, fmt.Errorf("ech: %s", err)
	}

	helloInner := new(clientHelloMsg)
	if !helloInner.unmarshal(rawHelloInner) {
		c.sendAlert(alertIllegalParameter)
		return nil, fmt.Errorf("ech: %s", err)
	}

	// Update the HRR pre-shared-key. This is used to decrypt the second
	// ClientHelloInner in case an HRR is sent.
	c.ech.hrrPsk = ctx.hrrPsk()

	if c.hrrTriggered && !c.ech.accepted {
		// ECH was not accepted prior to HRR then accepted after. Because the
		// configuration identifier is the same in the first ClientHello as it
		// is in the second, this indicates a server failure, likely due to the
		// ECH key being rotated.
		c.sendAlert(alertInternalError)
		return nil, errors.New("ech: hrr: accept after reject")
	}

	// Accept ECH.
	c.ech.offered = true
	c.ech.accepted = true
	return helloInner, nil
}

// echCipherSuite represents an ECH ciphersuite, a KDF/AEAD algorithm pair. This
// is different from an HPKE ciphersuite, which represents a KEM, KDF, and an
// AEAD algorithm.
type echCipherSuite struct {
	kdfId, aeadId uint16
}

// echUnmarshalHpkePublicKey parses a serialized public key for the KEM algorithm
// identified by `kemId`.
func echUnmarshalHpkePublicKey(raw []byte, kemId uint16) (hpke.KEMPublicKey, error) {
	// NOTE: Stand-in values for KDF/AEAD algorithms are ignored.
	hpkeSuite, err := hpkeAssembleCipherSuite(kemId, dummyKdfId, dummyAeadId)
	if err != nil {
		return nil, err
	}
	return hpkeSuite.KEM.Deserialize(raw)
}

// echUnmarshalHpkeSecretKey parses a serialized secret key for the KEM algorithm
// identified by `kemId`.
func echUnmarshalHpkeSecretKey(raw []byte, kemId uint16) (hpke.KEMPrivateKey, error) {
	// NOTE: Stand-in values for KDF/AEAD algorithms are ignored.
	hpkeSuite, err := hpkeAssembleCipherSuite(kemId, dummyKdfId, dummyAeadId)
	if err != nil {
		return nil, err
	}
	return hpkeSuite.KEM.DeserializePrivate(raw)
}

// echCreateHpkeKdf returns an HPKE KDF scheme.
func echCreateHpkeKdf(kdfId uint16) (hpke.KDFScheme, error) {
	// NOTE: Stand-in values for KEM/AEAD algorithms are ignored.
	hpkeSuite, err := hpkeAssembleCipherSuite(dummyKemId, kdfId, dummyAeadId)
	if err != nil {
		return nil, err
	}
	return hpkeSuite.KDF, nil
}

func echIsCipherSuiteSupported(suite echCipherSuite) bool {
	// NOTE: Stand-in values for KEM algorithm is ignored.
	_, err := hpkeAssembleCipherSuite(dummyKemId, suite.kdfId, suite.aeadId)
	return err == nil
}

func echIsKemSupported(kemId uint16) bool {
	// NOTE: Stand-in values for KDF/AEAD algorithms are ignored.
	_, err := hpkeAssembleCipherSuite(kemId, dummyKdfId, dummyAeadId)
	return err == nil
}

// echContent represents an HPKE context (irtf-cfrg-hpke-05).
type echContext struct {
	enc       *hpke.EncryptContext
	dec       *hpke.DecryptContext
	isClient  bool
	hpkeSuite hpke.CipherSuite
}

// cipherSuite returns the ECH ciphersuite for this HPKE context.
func (ctx *echContext) cipherSuite() echCipherSuite {
	return echCipherSuite{
		kdfId:  uint16(ctx.hpkeSuite.KDF.ID()),
		aeadId: uint16(ctx.hpkeSuite.AEAD.ID()),
	}
}

// echUnmarshalServerContext parses the server's HPKE context.
func echUnmarshalServerContext(raw []byte) (*echContext, error) {
	decryptechContext, err := hpke.UnmarshalDecryptContext(raw)
	if err != nil {
		return nil, err
	}

	hpkeSuite, err := hpkeAssembleCipherSuite(uint16(decryptechContext.KEMID), uint16(decryptechContext.KDFID), uint16(decryptechContext.AEADID))
	if err != nil {
		return nil, err
	}

	return &echContext{
		enc:       nil,
		dec:       decryptechContext,
		isClient:  false,
		hpkeSuite: hpkeSuite,
	}, nil
}

// marshalServer returns the server's serialized HPKE context.
func (ctx *echContext) marshalServer() ([]byte, error) {
	return ctx.dec.Marshal()
}

// encrypt seals the ClientHelloInner in the client's HPKE context.
func (ctx *echContext) seal(aad, inner []byte) (payload []byte) {
	if !ctx.isClient {
		panic("seal() is not defined for server")
	}
	return ctx.enc.Seal(aad, inner)
}

// decrypt opens the encrypted ClientHelloInner in the server's HPKE context.
func (ctx *echContext) open(aad, payload []byte) (inner []byte, err error) {
	if ctx.isClient {
		panic("open() is not defined for client")
	}
	return ctx.dec.Open(aad, payload)
}

// hrrPsk returns the PSK used to bind the first ClientHelloOuter to the second
// in case the backend server sends a HelloRetryRequest.
func (ctx *echContext) hrrPsk() []byte {
	if ctx.isClient {
		return ctx.enc.Export([]byte(echHpkeHrrKeyExporter), echHpkeHrrKeyLen)
	}
	return ctx.dec.Export([]byte(echHpkeHrrKeyExporter), echHpkeHrrKeyLen)
}

// configId computes the configuration identifier for a serialized ECHConfig.
func (ctx *echContext) configId(config []byte) []byte {
	kdf := ctx.hpkeSuite.KDF
	return kdf.Expand(kdf.Extract(nil, config), []byte(echHpkeInfoConfigId), kdf.OutputSize())
}

// echClient represents a ClientECH structure, the payload of the client's
// "encrypted_client_hello" extension.
type echClient struct {
	raw []byte

	// Parsed from raw
	handle  echContextHandle
	payload []byte
}

// echUnmarshalClient parses a ClientECH structure. The caller provides the ECH
// version indicated by the client.
func echUnmarshalClient(raw []byte) (*echClient, error) {
	// Parse the payload as a ClientECH structure.
	ech := new(echClient)
	ech.raw = raw

	// Parse the context handle.
	s := cryptobyte.String(raw)
	if !echReadContextHandle(&s, &ech.handle) {
		return nil, fmt.Errorf("error parsing context handle")
	}
	ech.handle.raw = raw[:len(raw)-len(s)]

	// Parse the payload.
	var t cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&t) ||
		!t.ReadBytes(&ech.payload, len(t)) || !s.Empty() {
		return nil, fmt.Errorf("error parsing payload")
	}

	return ech, nil
}

func (ech *echClient) marshal() []byte {
	if ech.raw != nil {
		return ech.raw
	}
	var b cryptobyte.Builder
	b.AddBytes(ech.handle.marshal())
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(ech.payload)
	})
	return b.BytesOrPanic()
}

// echContexttHandle represents the prefix of a ClientECH structure used by
// the server to compute the HPKE context.
type echContextHandle struct {
	raw []byte

	// Parsed from raw
	suite    echCipherSuite
	configId []byte
	enc      []byte
}

func (handle *echContextHandle) marshal() []byte {
	if handle.raw != nil {
		return handle.raw
	}
	var b cryptobyte.Builder
	b.AddUint16(handle.suite.kdfId)
	b.AddUint16(handle.suite.aeadId)
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(handle.configId)
	})
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(handle.enc)
	})
	return b.BytesOrPanic()
}

func echReadContextHandle(s *cryptobyte.String, handle *echContextHandle) bool {
	var t cryptobyte.String
	if !s.ReadUint16(&handle.suite.kdfId) || // cipher_suite.kdf_id
		!s.ReadUint16(&handle.suite.aeadId) || // cipher_suite.aead_id
		!s.ReadUint8LengthPrefixed(&t) || // config_id
		!t.ReadBytes(&handle.configId, len(t)) ||
		!s.ReadUint16LengthPrefixed(&t) || // enc
		!t.ReadBytes(&handle.enc, len(t)) {
		return false
	}
	return true
}

// echEncodeClientHelloInner interprets data as a ClientHelloInner message and
// transforms into an EncodedClinetHelloInner. It also returns a bool indicating
// if parsing the ClientHelloInner succeeded.
//
// outerExtensions specifies the contiguous sequence of extensions that will be
// incorporated.
func echEncodeClientHelloInner(data []byte, outerExtensions []uint16) ([]byte, bool) {
	var (
		errReadFailure           = errors.New("read failure")
		msgType                  uint8
		legacyVersion            uint16
		random                   []byte
		legacySessionId          cryptobyte.String
		cipherSuites             cryptobyte.String
		legacyCompressionMethods cryptobyte.String
		extensions               cryptobyte.String
		s                        cryptobyte.String
		b                        cryptobyte.Builder
	)

	u := cryptobyte.String(data)
	if !u.ReadUint8(&msgType) ||
		!u.ReadUint24LengthPrefixed(&s) || !u.Empty() {
		return nil, false
	}

	if !s.ReadUint16(&legacyVersion) ||
		!s.ReadBytes(&random, 32) ||
		!s.ReadUint8LengthPrefixed(&legacySessionId) ||
		!s.ReadUint16LengthPrefixed(&cipherSuites) ||
		!s.ReadUint8LengthPrefixed(&legacyCompressionMethods) {
		return nil, false
	}

	if s.Empty() {
		// Extensions field must be present in TLS 1.3.
		return nil, false
	}

	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return nil, false
	}

	b.AddUint16(legacyVersion)
	b.AddBytes(random)
	b.AddUint8(0) // 0-length legacy_session_id
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(cipherSuites)
	})
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(legacyCompressionMethods)
	})
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		if testingECHOuterExtIncorrectOrder {
			// Replace outer extensions with "outer_extension" extension, but in
			// the incorrect order.
			echAddOuterExtensions(b, outerExtensions)
		}

		for !extensions.Empty() {
			var ext uint16
			var extData cryptobyte.String
			if !extensions.ReadUint16(&ext) ||
				!extensions.ReadUint16LengthPrefixed(&extData) {
				panic(cryptobyte.BuildError{Err: errReadFailure})
			}

			if len(outerExtensions) > 0 && ext == outerExtensions[0] {
				if !testingECHOuterExtIncorrectOrder {
					// Replace outer extensions with "outer_extension" extension.
					echAddOuterExtensions(b, outerExtensions)
				}

				// Consume the remaining outer extensions.
				for _, outerExt := range outerExtensions[1:] {
					if !extensions.ReadUint16(&ext) ||
						!extensions.ReadUint16LengthPrefixed(&extData) {
						panic(cryptobyte.BuildError{Err: errReadFailure})
					}
					if ext != outerExt {
						panic("internal error: malformed ClientHelloInner")
					}
				}

			} else {
				b.AddUint16(ext)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(extData)
				})
			}
		}
	})

	encodedData, err := b.Bytes()
	if err == errReadFailure {
		return nil, false // Reading failed
	} else if err != nil {
		panic(err) // Writing failed
	}

	return encodedData, true
}

func echAddOuterExtensions(b *cryptobyte.Builder, outerExtensions []uint16) {
	b.AddUint16(extensionECHOuterExtensions)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, outerExt := range outerExtensions {
				b.AddUint16(outerExt)
			}
		})
	})
}

// echDecodeClientHelloInner interprets data as an EncodedClientHelloInner
// message and substitutes the "outer_extension" extension with extensions from
// outerData, interpreted as the ClientHelloOuter message. Returns the decoded
// ClientHelloInner and a bool indicating whether parsing
// EncodedClientHelloInner succeeded.
func echDecodeClientHelloInner(data []byte, outerData, outerSessionId []byte) ([]byte, bool) {
	var (
		errReadFailure           = errors.New("read failure")
		legacyVersion            uint16
		random                   []byte
		legacySessionId          cryptobyte.String
		cipherSuites             cryptobyte.String
		legacyCompressionMethods cryptobyte.String
		extensions               cryptobyte.String
		b                        cryptobyte.Builder
	)

	s := cryptobyte.String(data)
	if !s.ReadUint16(&legacyVersion) ||
		!s.ReadBytes(&random, 32) ||
		!s.ReadUint8LengthPrefixed(&legacySessionId) ||
		!s.ReadUint16LengthPrefixed(&cipherSuites) ||
		!s.ReadUint8LengthPrefixed(&legacyCompressionMethods) {
		return nil, false
	}

	if len(legacySessionId) > 0 {
		return nil, false
	}

	if s.Empty() {
		// Extensions field must be present in TLS 1.3.
		return nil, false
	}

	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return nil, false
	}

	b.AddUint8(typeClientHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(legacyVersion)
		b.AddBytes(random)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(outerSessionId) // ClientHelloOuter.legacy_session_id
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(cipherSuites)
		})
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(legacyCompressionMethods)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			var handledOuterExtensions bool
			for !extensions.Empty() {
				var ext uint16
				var extData cryptobyte.String
				if !extensions.ReadUint16(&ext) ||
					!extensions.ReadUint16LengthPrefixed(&extData) {
					panic(cryptobyte.BuildError{Err: errReadFailure})
				}

				if ext == extensionECHOuterExtensions {
					if handledOuterExtensions {
						// It is an error to send any extension more than once in a
						// single message.
						panic(cryptobyte.BuildError{Err: errReadFailure})
					}
					handledOuterExtensions = true

					// Read the set of outer extension code points.
					outer := make(map[uint16]bool)
					var outerExtData cryptobyte.String
					if !extData.ReadUint8LengthPrefixed(&outerExtData) ||
						len(outerExtData)%2 != 0 ||
						!extData.Empty() {
						panic(cryptobyte.BuildError{Err: errReadFailure})
					}
					for !outerExtData.Empty() {
						if !outerExtData.ReadUint16(&ext) ||
							!echIsValidOuterExtension(ext) {
							panic(cryptobyte.BuildError{Err: errReadFailure})
						}
						// Mark outer extension as not yet incorporated.
						outer[ext] = false
					}

					// Add the outer extensions from the ClientHelloOuter into the
					// ClientHelloInner.
					if !processClientHelloExtensions(outerData, func(ext uint16, extData cryptobyte.String) bool {
						if _, ok := outer[ext]; ok {
							b.AddUint16(ext)
							b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
								b.AddBytes(extData)
							})
							// Mark outer extension as incorporated.
							outer[ext] = true
						}
						return true
					}) {
						panic(cryptobyte.BuildError{Err: errReadFailure})
					}

					// Ensure that all outer extensions have been incorporated.
					for _, incorporated := range outer {
						if !incorporated {
							panic(cryptobyte.BuildError{Err: errReadFailure})
						}
					}
				} else {
					b.AddUint16(ext)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes(extData)
					})
				}
			}
		})
	})

	decodedData, err := b.Bytes()
	if err == errReadFailure {
		return nil, false // Reading failed
	} else if err != nil {
		panic(err) // Writing failed
	}

	return decodedData, true
}

// Returns true if the code point is a valid outer extension.
func echIsValidOuterExtension(ext uint16) bool {
	// The client MUST NOT attempt to compress the ECH extension.
	return !echIsValidVersion(ext)
}

// Returns true if the code point is for a version of ECH that this package
// implements.
func echIsValidVersion(ext uint16) bool {
	return ext == extensionECH
}

// encodeClientHelloOuterAAD interprets data as ClientHelloOuter and maps it to
// ClientHelloOuterAAD. Returns a bool indicated whether parsing
// ClientHelloOuter succeeded.
func encodeClientHelloOuterAAD(data []byte, ext uint16) ([]byte, bool) {
	var (
		errReadFailure           = errors.New("read failure")
		msgType                  uint8
		legacyVersion            uint16
		random                   []byte
		legacySessionId          cryptobyte.String
		cipherSuites             cryptobyte.String
		legacyCompressionMethods cryptobyte.String
		extensions               cryptobyte.String
		s                        cryptobyte.String
		b                        cryptobyte.Builder
	)

	u := cryptobyte.String(data)
	if !u.ReadUint8(&msgType) ||
		!u.ReadUint24LengthPrefixed(&s) || !u.Empty() {
		return nil, false
	}

	if !s.ReadUint16(&legacyVersion) ||
		!s.ReadBytes(&random, 32) ||
		!s.ReadUint8LengthPrefixed(&legacySessionId) ||
		!s.ReadUint16LengthPrefixed(&cipherSuites) ||
		!s.ReadUint8LengthPrefixed(&legacyCompressionMethods) {
		return nil, false
	}

	if s.Empty() {
		// Extensions field must be present in TLS 1.3.
		return nil, false
	}

	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return nil, false
	}

	b.AddUint8(msgType)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(legacyVersion)
		b.AddBytes(random)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(legacySessionId)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(cipherSuites)
		})
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(legacyCompressionMethods)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for !extensions.Empty() {
				var ext uint16
				var extData cryptobyte.String
				if !extensions.ReadUint16(&ext) ||
					!extensions.ReadUint16LengthPrefixed(&extData) {
					panic(cryptobyte.BuildError{Err: errReadFailure})
				}

				// Copy all extensions except for ECH.
				if ext != extensionECH {
					b.AddUint16(ext)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes(extData)
					})
				}
			}
		})
	})

	encodedData, err := b.Bytes()
	if err == errReadFailure {
		return nil, false // Reading failed
	} else if err != nil {
		panic(err) // Writing failed
	}

	return encodedData, true
}

// processClientHelloExtensions interprets data as a ClientHello and applies a
// function proc to each extension. Returns a bool indicating whether parsing
// succeeded.
func processClientHelloExtensions(data []byte, proc func(ext uint16, extData cryptobyte.String) bool) bool {
	_, extensionsData, ok := splitClientHelloExtensions(data)
	if !ok {
		return false
	}

	s := cryptobyte.String(extensionsData)
	if s.Empty() {
		// Extensions field not present.
		return true
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	for !extensions.Empty() {
		var ext uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&ext) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}
		if ok := proc(ext, extData); !ok {
			return false
		}
	}
	return true
}

// splitClientHelloExtensions interprets data as a ClientHello message and
// returns two strings: the first contains the start of the ClientHello up to
// the start of the extensions; and the second is the length-prefixed
// extensions. It also returns a bool indicating whether parsing succeeded.
func splitClientHelloExtensions(data []byte) ([]byte, []byte, bool) {
	s := cryptobyte.String(data)

	var ignored uint16
	var t cryptobyte.String
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&ignored) || !s.Skip(32) || // vers, random
		!s.ReadUint8LengthPrefixed(&t) { // session_id
		return nil, nil, false
	}

	if !s.ReadUint16LengthPrefixed(&t) { // cipher_suites
		return nil, nil, false
	}

	if !s.ReadUint8LengthPrefixed(&t) { // compression_methods
		return nil, nil, false
	}

	return data[:len(data)-len(s)], s, true
}

func (c *Config) echSelectConfig() *ECHConfig {
	for _, echConfig := range c.ClientECHConfigs {
		// A suitable configuration is one that offers an HPKE ciphersuite that
		// is supported by the client and indicates the version of ECH
		// implemented by this TLS client.
		if echConfig.isSupported() && echIsValidVersion(echConfig.version) {
			return &echConfig
		}
	}
	return nil
}

func (c *Config) echCanOffer() bool {
	if c == nil {
		return false
	}
	return c.ECHEnabled && c.echSelectConfig() != nil && c.maxSupportedVersion() >= VersionTLS13
}

func (c *Config) echCanAccept() bool {
	if c == nil {
		return false
	}
	return c.ECHEnabled && c.ServerECHProvider != nil && c.maxSupportedVersion() >= VersionTLS13
}
