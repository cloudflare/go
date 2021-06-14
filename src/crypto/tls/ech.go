// Copyright 2020 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package tls

import (
	"circl/hpke"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

const (
	// Constants for TLS operations
	echAcceptConfLabel    = "ech accept confirmation"
	echAcceptConfHRRLabel = "hrr ech accept confirmation"

	// Constants for HPKE operations
	echHpkeInfoSetup = "tls ech"

	// When sent in the ClientHello, the first byte of the payload of the ECH
	// extension indicates whether the message is the ClientHelloOuter or
	// ClientHelloInner.
	echClientHelloOuterVariant uint8 = 0
	echClientHelloInnerVariant uint8 = 1
)

var (
	zeros = [8]byte{}
)

// TODO(cjpatton): "[When offering ECH, the client] MUST NOT offer to resume any
// session for TLS 1.2 and below [in ClientHelloInner]."
func (c *Conn) echOfferOrGrease(helloBase *clientHelloMsg) (hello, helloInner *clientHelloMsg, err error) {
	config := c.config

	if !config.ECHEnabled ||
		(c.hrrTriggered && testingECHTriggerBypassAfterHRR) ||
		(!c.hrrTriggered && testingECHTriggerBypassBeforeHRR) {
		// Bypass ECH.
		return helloBase, nil, nil
	}

	echConfig := config.echSelectConfig()
	if echConfig == nil || config.maxSupportedVersion() < VersionTLS13 {
		// Compute artifacts that are reused across HRR.
		if c.ech.dummy == nil {
			// Serialized ClientECH.
			c.ech.dummy, err = echGenerateDummyExt(config.rand())
			if err != nil {
				return nil, nil, fmt.Errorf("tls: ech: failed to generate grease ECH: %s", err)
			}
		}

		// Grease ECH.
		helloBase.ech = c.ech.dummy
		c.ech.offered = false
		c.ech.greased = true
		helloBase.raw = nil
		return helloBase, nil, nil
	}

	// Compute artifacts that are reused across HRR.
	var enc []byte
	if c.ech.sealer == nil {
		// HPKE context.
		enc, c.ech.sealer, err = echConfig.setupSealer(config.rand())
		if err != nil {
			return nil, nil, fmt.Errorf("tls: ech: %s", err)
		}

		// ECHConfig.contents.public_name.
		c.ech.publicName = string(echConfig.rawPublicName)

		// ECHConfig.contents.key_config.config_id.
		c.ech.configId = echConfig.configId

		// ClientHelloInner.random.
		c.ech.innerRandom = make([]byte, 32)
		if _, err = io.ReadFull(config.rand(), c.ech.innerRandom); err != nil {
			return nil, nil, fmt.Errorf("tls: short read from Rand: %s", err)
		}
	}

	// ClientHelloInner is constructed from helloBase, but uses a fresh "random"
	// (helloBase.random is used for ClientHelloOuter) and an empty
	// "ech_is_inner" extension indicating that this is the ClientHelloInner.
	helloInner = new(clientHelloMsg)
	*helloInner = *helloBase
	helloInner.random = c.ech.innerRandom
	helloInner.ech = []byte{echClientHelloInnerVariant}

	// Ensure that only TLS 1.3 and above are offered.
	if v := helloInner.supportedVersions; len(v) == 0 || v[len(v)-1] < VersionTLS13 {
		return nil, nil, errors.New("tls: ech: only TLS 1.3 is allowed in ClientHelloInner")
	}

	// EncodedClientHelloInner is constructed from ClientHelloInner by removing
	// extensions that are also used in the ClientHelloOuter.
	//
	// NOTE(cjpatton): It would be nice to incorporate more extensions, but
	// "key_share" is the last extension to appear in the ClientHello before
	// "pre_shared_key". As a result, the only contiguous sequence of outer
	// extensions that contains "key_share" is "key_share" itself. Note that
	// we cannot change the order of extensions in the ClientHello, as the
	// unit tests expect "key_share" to be the second to last extension.
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
	encodedHelloInner := echEncodeClientHelloInner(helloInner.marshal(), outerExtensions)
	if encodedHelloInner == nil {
		return nil, nil, errors.New("tls: ech: encoding of EncodedClientHelloInner failed")
	}

	// ClientHelloOuter is constructed by generating a fresh ClientHello and
	// copying "key_share", "random", and "sesion_id" from helloBase, setting
	// "server_name" to be the client-facing server, and adding the
	// "encrypted_client_hello" extension.
	hello, _, err = c.makeClientHello(config.MinVersion)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: ech: %s", err)
	}
	hello.keyShares = helloBase.keyShares
	hello.random = helloBase.random
	hello.sessionId = helloBase.sessionId
	hello.serverName = hostnameInSNI(c.ech.publicName)

	// ClientECH, the payload of the "encrypted_client_hello" extension.
	var ech echClientOuter
	_, kdf, aead := c.ech.sealer.Suite().Params()
	ech.handle.suite.kdfId = uint16(kdf)
	ech.handle.suite.aeadId = uint16(aead)
	ech.handle.configId = echConfig.configId
	ech.handle.enc = enc // Empty after HRR

	// ClientHelloOuterAAD
	hello.ech = ech.marshal()
	helloOuterAad := echEncodeClientHelloOuterAAD(hello.marshal(),
		aead.CipherLen(uint(len(encodedHelloInner))))
	if helloOuterAad == nil {
		return nil, nil, errors.New("tls: ech: encoding of ClientHelloOuterAAD failed")
	}

	ech.payload, err = c.ech.sealer.Seal(encodedHelloInner, helloOuterAad)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: ech: seal failed: %s", err)
	}
	if testingECHTriggerPayloadDecryptError {
		ech.payload[0] ^= 0xff // Inauthentic ciphertext
	}
	ech.raw = nil
	hello.ech = ech.marshal()

	// Offer ECH.
	c.ech.offered = true
	helloInner.raw = nil
	hello.raw = nil
	return hello, helloInner, nil
}

func (c *Conn) echAcceptOrReject(hello *clientHelloMsg) (*clientHelloMsg, error) {
	config := c.config
	p := config.ServerECHProvider

	if !config.echCanAccept() {
		// Bypass ECH.
		return hello, nil
	}

	if len(hello.ech) > 0 { // The ECH extension is present
		switch hello.ech[0] {
		case echClientHelloInnerVariant: // inner handshake
			if len(hello.ech) > 1 {
				c.sendAlert(alertIllegalParameter)
				return nil, errors.New("ech: inner handshake has non-empty payload")
			}

			// Bypass ECH and continue as backend server.
			return hello, nil
		case echClientHelloOuterVariant: // outer handshake
		default:
			c.sendAlert(alertIllegalParameter)
			return nil, errors.New("ech: inner handshake has non-empty payload")
		}
	} else {
		if c.ech.offered {
			// This occurs if the server accepted prior to HRR, but the client
			// failed to send the ECH extension in the second ClientHelloOuter. This
			// would cause ClientHelloOuter to be used after ClientHelloInner, which
			// is illegal.
			c.sendAlert(alertMissingExtension)
			return nil, errors.New("ech: hrr: bypass after offer")
		}

		// Bypass ECH.
		return hello, nil
	}

	if c.hrrTriggered && !c.ech.offered && !c.ech.greased {
		// The client bypassed ECH prior to HRR, but not after. This could
		// cause ClientHelloInner to be used after ClientHelloOuter, which is
		// illegal.
		c.sendAlert(alertIllegalParameter)
		return nil, errors.New("ech: hrr: offer or grease after bypass")
	}

	// Parse ClientECH.
	ech, err := echUnmarshalClientOuter(hello.ech)
	if err != nil {
		c.sendAlert(alertIllegalParameter)
		return nil, fmt.Errorf("ech: failed to parse extension: %s", err)
	}
	if c.hrrTriggered && c.ech.offered &&
		(ech.handle.suite != c.ech.suite ||
			ech.handle.configId != c.ech.configId ||
			len(ech.handle.enc) > 0) {
		// The cipher suite and config id don't change across HRR. The
		// encapsulated key field must be empty after HRR.
		c.sendAlert(alertIllegalParameter)
		return nil, errors.New("ech: hrr: illegal handle in second hello")
	}
	c.ech.configId = ech.handle.configId
	c.ech.suite = ech.handle.suite

	// Ask the ECH provider for the HPKE context.
	if c.ech.opener == nil {
		res := p.GetDecryptionContext(ech.handle.marshal(), extensionECH)

		// Compute retry configurations, skipping those indicating an
		// unsupported version.
		if len(res.RetryConfigs) > 0 {
			configs, err := UnmarshalECHConfigs(res.RetryConfigs)
			if err != nil {
				c.sendAlert(alertInternalError)
				return nil, fmt.Errorf("ech: %s", err)
			}

			if len(configs) > 0 {
				c.ech.retryConfigs, err = echMarshalConfigs(configs)
				if err != nil {
					c.sendAlert(alertInternalError)
					return nil, fmt.Errorf("ech: %s", err)
				}
			}

			// Check if the outer SNI matches the public name of any ECH config
			// advertised by the client-facing server. As of
			// draft-ietf-tls-esni-10, the client is required to use the ECH
			// config's public name as the outer SNI. Although there's no real
			// reason for the server to enforce this, it worth noting it when it
			// happens.
			pubNameMatches := false
			for _, config := range configs {
				if hello.serverName == string(config.rawPublicName) {
					pubNameMatches = true
				}
			}
			if !pubNameMatches {
				c.handleCFEvent(CFEventECHPublicNameMismatch{})
			}
		}

		switch res.Status {
		case ECHProviderSuccess:
			c.ech.opener, err = hpke.UnmarshalOpener(res.Context)
			if err != nil {
				c.sendAlert(alertInternalError)
				return nil, fmt.Errorf("ech: %s", err)
			}
		case ECHProviderReject:
			// Reject ECH. We do not know at this point whether the client
			// intended to offer or grease ECH, so we presume grease until the
			// client indicates rejection by sending an "ech_required" alert.
			c.ech.greased = true
			return hello, nil
		case ECHProviderAbort:
			c.sendAlert(alert(res.Alert))
			return nil, fmt.Errorf("ech: %s", err)
		default:
			c.sendAlert(alertInternalError)
			return nil, errors.New("ech: unexpected provider status")
		}
	}

	// EncodedClientHelloInner, the plaintext corresponding to
	// ClientECH.payload.
	rawHelloOuterAad := echEncodeClientHelloOuterAAD(hello.marshal(), uint(len(ech.payload)))
	if rawHelloOuterAad == nil {
		// This occurs if the ClientHelloOuter is malformed. This values was
		// already parsed into `hello`, so this should not happen.
		c.sendAlert(alertInternalError)
		return nil, fmt.Errorf("ech: failed to encode ClientHelloOuterAAD")
	}
	rawEncodedHelloInner, err := c.ech.opener.Open(ech.payload, rawHelloOuterAad)
	if err != nil {
		if c.hrrTriggered && c.ech.accepted {
			// Don't reject after accept, as this would result in processing the
			// ClientHelloOuter after processing the ClientHelloInner.
			c.sendAlert(alertDecryptError)
			return nil, fmt.Errorf("ech: hrr: reject after accept: %s", err)
		}
		// Reject ECH. We do not know at this point whether the client
		// intended to offer or grease ECH, so we presume grease until the
		// client indicates rejection by sending an "ech_required" alert.
		c.ech.greased = true
		return hello, nil
	}

	// ClientHelloInner, obtained by decoding EncodedClientHelloInner.
	rawHelloInner := echDecodeClientHelloInner(rawEncodedHelloInner, hello.marshal(), hello.sessionId)
	if rawHelloInner == nil {
		c.sendAlert(alertIllegalParameter)
		return nil, fmt.Errorf("ech: failed to decode EncodedClientHelloInner")
	}
	helloInner := new(clientHelloMsg)
	if !helloInner.unmarshal(rawHelloInner) {
		c.sendAlert(alertIllegalParameter)
		return nil, fmt.Errorf("ech: failed to parse ClientHelloInner")
	}

	// Check for a well-formed ECH extension.
	if len(helloInner.ech) != 1 ||
		helloInner.ech[0] != echClientHelloInnerVariant {
		c.sendAlert(alertIllegalParameter)
		return nil, fmt.Errorf("ech: ClientHelloInner does not have a well-formed ECH extension")
	}

	// Check that the client did not offer TLS 1.2 or below in the inner
	// handshake.
	helloInnerSupportsTLS12OrBelow := len(helloInner.supportedVersions) == 0
	for _, v := range helloInner.supportedVersions {
		if v < VersionTLS13 {
			helloInnerSupportsTLS12OrBelow = true
		}
	}
	if helloInnerSupportsTLS12OrBelow {
		c.sendAlert(alertIllegalParameter)
		return nil, errors.New("ech: ClientHelloInner offers TLS 1.2 or below")
	}

	// Accept ECH.
	c.ech.offered = true
	c.ech.accepted = true
	return helloInner, nil
}

// echClientOuter represents a ClientECH structure, the payload of the client's
// "encrypted_client_hello" extension that appears in the outer handshake.
type echClientOuter struct {
	raw []byte

	// Parsed from raw
	handle  echContextHandle
	payload []byte
}

// echUnmarshalClientOuter parses a ClientECH structure. The caller provides the
// ECH version indicated by the client.
func echUnmarshalClientOuter(raw []byte) (*echClientOuter, error) {
	s := cryptobyte.String(raw)
	ech := new(echClientOuter)
	ech.raw = raw

	// Make sure this is the outer handshake.
	var variant uint8
	if !s.ReadUint8(&variant) {
		return nil, fmt.Errorf("error parsing ClientECH.type")
	}
	if variant != echClientHelloOuterVariant {
		return nil, fmt.Errorf("unexpected ClientECH.type (want outer (0))")
	}

	// Parse the context handle.
	if !echReadContextHandle(&s, &ech.handle) {
		return nil, fmt.Errorf("error parsing context handle")
	}
	endOfContextHandle := len(raw) - len(s)
	ech.handle.raw = raw[1:endOfContextHandle]

	// Parse the payload.
	var t cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&t) ||
		!t.ReadBytes(&ech.payload, len(t)) || !s.Empty() {
		return nil, fmt.Errorf("error parsing payload")
	}

	return ech, nil
}

func (ech *echClientOuter) marshal() []byte {
	if ech.raw != nil {
		return ech.raw
	}
	var b cryptobyte.Builder
	b.AddUint8(echClientHelloOuterVariant)
	b.AddBytes(ech.handle.marshal())
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(ech.payload)
	})
	return b.BytesOrPanic()
}

// echContextHandle represents the prefix of a ClientECH structure used by
// the server to compute the HPKE context.
type echContextHandle struct {
	raw []byte

	// Parsed from raw
	suite    hpkeSymmetricCipherSuite
	configId uint8
	enc      []byte
}

func (handle *echContextHandle) marshal() []byte {
	if handle.raw != nil {
		return handle.raw
	}
	var b cryptobyte.Builder
	b.AddUint16(handle.suite.kdfId)
	b.AddUint16(handle.suite.aeadId)
	b.AddUint8(handle.configId)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(handle.enc)
	})
	return b.BytesOrPanic()
}

func echReadContextHandle(s *cryptobyte.String, handle *echContextHandle) bool {
	var t cryptobyte.String
	if !s.ReadUint16(&handle.suite.kdfId) || // cipher_suite.kdf_id
		!s.ReadUint16(&handle.suite.aeadId) || // cipher_suite.aead_id
		!s.ReadUint8(&handle.configId) || // config_id
		!s.ReadUint16LengthPrefixed(&t) || // enc
		!t.ReadBytes(&handle.enc, len(t)) {
		return false
	}
	return true
}

// hpkeSymmetricCipherSuite represents an ECH ciphersuite, a KDF/AEAD algorithm pair. This
// is different from an HPKE ciphersuite, which represents a KEM/KDF/AEAD
// triple.
type hpkeSymmetricCipherSuite struct {
	kdfId, aeadId uint16
}

// Generates a grease ECH extension using a hard-coded KEM public key.
func echGenerateDummyExt(rand io.Reader) ([]byte, error) {
	var err error
	var dummyX25519PublicKey = []byte{
		143, 38, 37, 36, 12, 6, 229, 30, 140, 27, 167, 73, 26, 100, 203, 107, 216,
		81, 163, 222, 52, 211, 54, 210, 46, 37, 78, 216, 157, 97, 241, 244,
	}
	dummyEncodedHelloInnerLen := 100 // TODO(cjpatton): Compute this correctly.
	kem, kdf, aead := defaultHPKESuite.Params()

	pk, err := kem.Scheme().UnmarshalBinaryPublicKey(dummyX25519PublicKey)
	if err != nil {
		return nil, fmt.Errorf("tls: grease ech: failed to parse dummy public key: %s", err)
	}
	sender, err := defaultHPKESuite.NewSender(pk, nil)
	if err != nil {
		return nil, fmt.Errorf("tls: grease ech: failed to create sender: %s", err)
	}

	var ech echClientOuter
	ech.handle.suite.kdfId = uint16(kdf)
	ech.handle.suite.aeadId = uint16(aead)
	randomByte := make([]byte, 1)
	_, err = io.ReadFull(rand, randomByte)
	if err != nil {
		return nil, fmt.Errorf("tls: grease ech:: %s", err)
	}
	ech.handle.configId = randomByte[0]
	ech.handle.enc, _, err = sender.Setup(rand)
	if err != nil {
		return nil, fmt.Errorf("tls: grease ech:: %s", err)
	}
	ech.payload = make([]byte, dummyEncodedHelloInnerLen+defaultHPKESuiteTagLen)
	if _, err = io.ReadFull(rand, ech.payload); err != nil {
		return nil, fmt.Errorf("tls: grease ech:: %s", err)
	}
	return ech.marshal(), nil
}

// echEncodeClientHelloInner interprets innerData as a ClientHelloInner message
// and transforms it into an EncodedClientHelloInner. Returns nil if parsing
// innerData fails.
//
// outerExtensions specifies the contiguous sequence of extensions that will be
// incorporated using the "ech_outer_extensions" mechanism.
func echEncodeClientHelloInner(innerData []byte, outerExtensions []uint16) []byte {
	var (
		errIllegalParameter      = errors.New("illegal parameter")
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

	u := cryptobyte.String(innerData)
	if !u.ReadUint8(&msgType) ||
		!u.ReadUint24LengthPrefixed(&s) || !u.Empty() {
		return nil
	}

	if !s.ReadUint16(&legacyVersion) ||
		!s.ReadBytes(&random, 32) ||
		!s.ReadUint8LengthPrefixed(&legacySessionId) ||
		!s.ReadUint16LengthPrefixed(&cipherSuites) ||
		!s.ReadUint8LengthPrefixed(&legacyCompressionMethods) {
		return nil
	}

	if s.Empty() {
		// Extensions field must be present in TLS 1.3.
		return nil
	}

	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return nil
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
				panic(cryptobyte.BuildError{Err: errIllegalParameter})
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
						panic(cryptobyte.BuildError{Err: errIllegalParameter})
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
	if err == errIllegalParameter {
		return nil // Input malformed
	} else if err != nil {
		panic(err) // Host encountered internal error
	}

	return encodedData
}

func echAddOuterExtensions(b *cryptobyte.Builder, outerExtensions []uint16) {
	b.AddUint16(extensionECHOuterExtensions)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, outerExt := range outerExtensions {
				b.AddUint16(outerExt)
			}
			if testingECHOuterExtIllegal {
				// This is not allowed.
				b.AddUint16(extensionECH)
			}
		})
	})
}

// echDecodeClientHelloInner interprets encodedData as an EncodedClientHelloInner
// message and substitutes the "outer_extension" extension with extensions from
// outerData, interpreted as the ClientHelloOuter message. Returns nil if
// parsing encodedData fails.
func echDecodeClientHelloInner(encodedData, outerData, outerSessionId []byte) []byte {
	var (
		errIllegalParameter      = errors.New("illegal parameter")
		legacyVersion            uint16
		random                   []byte
		legacySessionId          cryptobyte.String
		cipherSuites             cryptobyte.String
		legacyCompressionMethods cryptobyte.String
		extensions               cryptobyte.String
		b                        cryptobyte.Builder
	)

	s := cryptobyte.String(encodedData)
	if !s.ReadUint16(&legacyVersion) ||
		!s.ReadBytes(&random, 32) ||
		!s.ReadUint8LengthPrefixed(&legacySessionId) ||
		!s.ReadUint16LengthPrefixed(&cipherSuites) ||
		!s.ReadUint8LengthPrefixed(&legacyCompressionMethods) {
		return nil
	}

	if len(legacySessionId) > 0 {
		return nil
	}

	if s.Empty() {
		// Extensions field must be present in TLS 1.3.
		return nil
	}

	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return nil
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
					panic(cryptobyte.BuildError{Err: errIllegalParameter})
				}

				if ext == extensionECHOuterExtensions {
					if handledOuterExtensions {
						// It is an error to send any extension more than once in a
						// single message.
						panic(cryptobyte.BuildError{Err: errIllegalParameter})
					}
					handledOuterExtensions = true

					// Read the referenced outer extensions.
					referencedExts := make([]uint16, 0, 10)
					var outerExtData cryptobyte.String
					if !extData.ReadUint8LengthPrefixed(&outerExtData) ||
						len(outerExtData)%2 != 0 ||
						!extData.Empty() {
						panic(cryptobyte.BuildError{Err: errIllegalParameter})
					}
					for !outerExtData.Empty() {
						if !outerExtData.ReadUint16(&ext) ||
							ext == extensionECH {
							panic(cryptobyte.BuildError{Err: errIllegalParameter})
						}
						referencedExts = append(referencedExts, ext)
					}

					// Add the outer extensions from the ClientHelloOuter into the
					// ClientHelloInner.
					outerCt := 0
					r := processClientHelloExtensions(outerData, func(ext uint16, extData cryptobyte.String) bool {
						if outerCt < len(referencedExts) && ext == referencedExts[outerCt] {
							outerCt++
							b.AddUint16(ext)
							b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
								b.AddBytes(extData)
							})
						}
						return true
					})

					// Ensure that all outer extensions have been incorporated
					// exactly once, and in the correct order.
					if !r || outerCt != len(referencedExts) {
						panic(cryptobyte.BuildError{Err: errIllegalParameter})
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

	innerData, err := b.Bytes()
	if err == errIllegalParameter {
		return nil // Input malformed
	} else if err != nil {
		panic(err) // Host encountered internal error
	}

	return innerData
}

// echEncodeClientHelloOuterAAD interprets outerData as ClientHelloOuter and
// constructs a ClientHelloOuterAAD. The output doesn't have the 4-byte prefix
// that indicates the handshake message type and its length.
func echEncodeClientHelloOuterAAD(outerData []byte, payloadLen uint) []byte {
	var (
		errIllegalParameter      = errors.New("illegal parameter")
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

	u := cryptobyte.String(outerData)
	if !u.ReadUint8(&msgType) ||
		!u.ReadUint24LengthPrefixed(&s) || !u.Empty() {
		return nil
	}

	if !s.ReadUint16(&legacyVersion) ||
		!s.ReadBytes(&random, 32) ||
		!s.ReadUint8LengthPrefixed(&legacySessionId) ||
		!s.ReadUint16LengthPrefixed(&cipherSuites) ||
		!s.ReadUint8LengthPrefixed(&legacyCompressionMethods) {
		return nil
	}

	if s.Empty() {
		// Extensions field must be present in TLS 1.3.
		return nil
	}

	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return nil
	}

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
				panic(cryptobyte.BuildError{Err: errIllegalParameter})
			}

			// If this is the ECH extension and the payload is the outer variant
			// of ClientECH, then replace the payloadLen 0 bytes.
			if ext == extensionECH {
				ech, err := echUnmarshalClientOuter(extData)
				if err != nil {
					panic(cryptobyte.BuildError{Err: errIllegalParameter})
				}
				ech.payload = make([]byte, payloadLen)
				ech.raw = nil
				extData = ech.marshal()
			}

			b.AddUint16(ext)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(extData)
			})
		}
	})

	outerAadData, err := b.Bytes()
	if err == errIllegalParameter {
		return nil // Input malformed
	} else if err != nil {
		panic(err) // Host encountered internal error
	}

	return outerAadData
}

// echEncodeAcceptConfHelloRetryRequest interprets data as a ServerHello message
// and replaces the payload of the ECH extension with 8 zero bytes. The output
// includes the 4-byte prefix that indicates the message type and its length.
func echEncodeAcceptConfHelloRetryRequest(data []byte) []byte {
	var (
		errIllegalParameter = errors.New("illegal parameter")
		vers                uint16
		random              []byte
		sessionId           []byte
		cipherSuite         uint16
		compressionMethod   uint8
		s                   cryptobyte.String
		b                   cryptobyte.Builder
	)

	s = cryptobyte.String(data)
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&vers) || !s.ReadBytes(&random, 32) ||
		!readUint8LengthPrefixed(&s, &sessionId) ||
		!s.ReadUint16(&cipherSuite) ||
		!s.ReadUint8(&compressionMethod) {
		return nil
	}

	if s.Empty() {
		// ServerHello is optionally followed by extension data
		return nil
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return nil
	}

	b.AddUint8(typeServerHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(vers)
		b.AddBytes(random)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(sessionId)
		})
		b.AddUint16(cipherSuite)
		b.AddUint8(compressionMethod)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for !extensions.Empty() {
				var extension uint16
				var extData cryptobyte.String
				if !extensions.ReadUint16(&extension) ||
					!extensions.ReadUint16LengthPrefixed(&extData) {
					panic(cryptobyte.BuildError{Err: errIllegalParameter})
				}

				b.AddUint16(extension)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					if extension == extensionECH {
						b.AddBytes(zeros[:8])
					} else {
						b.AddBytes(extData)
					}
				})
			}
		})
	})

	encodedData, err := b.Bytes()
	if err == errIllegalParameter {
		return nil // Input malformed
	} else if err != nil {
		panic(err) // Host encountered internal error
	}

	return encodedData
}

// processClientHelloExtensions interprets data as a ClientHello and applies a
// function proc to each extension. Returns a bool indicating whether parsing
// succeeded.
func processClientHelloExtensions(data []byte, proc func(ext uint16, extData cryptobyte.String) bool) bool {
	_, extensionsData := splitClientHelloExtensions(data)
	if extensionsData == nil {
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
// extensions. Returns (nil, nil) if parsing of data fails.
func splitClientHelloExtensions(data []byte) ([]byte, []byte) {
	s := cryptobyte.String(data)

	var ignored uint16
	var t cryptobyte.String
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&ignored) || !s.Skip(32) || // vers, random
		!s.ReadUint8LengthPrefixed(&t) { // session_id
		return nil, nil
	}

	if !s.ReadUint16LengthPrefixed(&t) { // cipher_suites
		return nil, nil
	}

	if !s.ReadUint8LengthPrefixed(&t) { // compression_methods
		return nil, nil
	}

	return data[:len(data)-len(s)], s
}

// TODO(cjpatton): draft-ietf-tls-esni-11, Section 4 mandates:
//
//   Clients MUST ignore any "ECHConfig" structure whose public_name is
//   not parsable as a dot-separated sequence of LDH labels, as defined
//   in [RFC5890], Section 2.3.1 or which begins or end with an ASCII
//   dot.
//
//   Clients SHOULD ignore the "ECHConfig" if it contains an encoded
//   IPv4 address.  To determine if a public_name value is an IPv4
//   address, clients can invoke the IPv4 parser algorithm in
//   [WHATWG-IPV4].  It returns a value when the input is an IPv4
//   address.
//
//   See Section 6.1.4.3 for how the client interprets and validates
//   the public_name.
//
// TODO(cjpatton): draft-ietf-tls-esni-11, Section 4.1 mandates:
//
//   ECH configuration extensions are used to provide room for additional
//   functionality as needed.  See Section 12 for guidance on which types
//   of extensions are appropriate for this structure.
//
//   The format is as defined in [RFC8446], Section 4.2.  The same
//   interpretation rules apply: extensions MAY appear in any order, but
//   there MUST NOT be more than one extension of the same type in the
//   extensions block.  An extension can be tagged as mandatory by using
//   an extension type codepoint with the high order bit set to 1.  A
//   client that receives a mandatory extension they do not understand
//   MUST reject the "ECHConfig" content.
//
//   Clients MUST parse the extension list and check for unsupported
//   mandatory extensions.  If an unsupported mandatory extension is
//   present, clients MUST ignore the "ECHConfig".
func (c *Config) echSelectConfig() *ECHConfig {
	for _, echConfig := range c.ClientECHConfigs {
		if _, err := echConfig.selectSuite(); err == nil &&
			echConfig.version == extensionECH {
			return &echConfig
		}
	}
	return nil
}

func (c *Config) echCanOffer() bool {
	if c == nil {
		return false
	}
	return c.ECHEnabled &&
		c.echSelectConfig() != nil &&
		c.maxSupportedVersion() >= VersionTLS13
}

func (c *Config) echCanAccept() bool {
	if c == nil {
		return false
	}
	return c.ECHEnabled &&
		c.ServerECHProvider != nil &&
		c.maxSupportedVersion() >= VersionTLS13
}
