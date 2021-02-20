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
	echAcceptConfirmationLabel = "ech accept confirmation"

	// Constants for HPKE operations
	echHpkeInfoConfigId = "tls ech config id"
	echHpkeInfoSetup    = "tls ech"
)

// TODO(cjpatton): "[When offering ECH, the client] MUST NOT offer to resume any
// session for TLS 1.2 and below [in ClientHelloInner]."
//
// TODO(cjpatton): "[When offering ECH, the client] MUST NOT include the
// "pre_shared_key" extension [in ClientHelloOuter]." (This is a "don't stick
// out" issue.)
//
// TODO(cjpatton): Implement client-side padding.
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
		helloBase.echIsOuter = true
		c.ech.offered = false
		c.ech.greased = true
		helloBase.raw = nil
		return helloBase, nil, nil
	}

	// Compute artifacts that are reused across HRR.
	var enc, configId []byte
	if c.ech.sealer == nil {
		// HPKE context.
		enc, c.ech.sealer, err = echConfig.setupSealer(config.rand())
		if err != nil {
			return nil, nil, fmt.Errorf("tls: ech: %s", err)
		}

		// ClientECH.config_id.
		_, kdfId, _ := c.ech.sealer.Suite().Params()
		configId, err = echConfig.id(kdfId)
		if err != nil {
			return nil, nil, fmt.Errorf("tls: ech: %s", err)
		}

		// ECHConfig.contents.public_name.
		c.ech.publicName = string(echConfig.rawPublicName)

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
	helloInner.echIsInner = true

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
	hello.echIsOuter = true
	if testingECHOuterIsInner {
		hello.echIsInner = true
	}

	// ClientECH, the payload of the "encrypted_client_hello" extension.
	var ech echClient
	_, kdfId, aeadId := c.ech.sealer.Suite().Params()
	ech.handle.suite.kdfId = uint16(kdfId)
	ech.handle.suite.aeadId = uint16(aeadId)
	ech.handle.configId = configId // Empty after HRR
	ech.handle.enc = enc           // Empty after HRR
	helloOuterAad := echEncodeClientHelloOuterAAD(hello.marshal(), ech.handle.marshal())
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

	if hello.echIsInner {
		if hello.echIsOuter {
			c.sendAlert(alertIllegalParameter)
			return hello, errors.New("ech: hello marked as inner and outer")
		}
		if len(hello.ech) > 0 {
			c.sendAlert(alertIllegalParameter)
			return hello, errors.New("ech_is_inner: got non-empty payload")
		}
		// Bypass ECH and continue as backend server.
		return hello, nil
	}

	if !hello.echIsOuter {
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
	ech, err := echUnmarshalClient(hello.ech)
	if err != nil {
		c.sendAlert(alertIllegalParameter)
		return nil, fmt.Errorf("ech: failed to parse extension: %s", err)
	}
	if c.hrrTriggered && c.ech.offered &&
		(ech.handle.suite != c.ech.suite ||
			len(ech.handle.configId) > 0 ||
			len(ech.handle.enc) > 0) {
		// The context handle shouldn't change across HRR.
		c.sendAlert(alertIllegalParameter)
		return nil, errors.New("ech: hrr: illegal handle in second hello")
	}
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
			// draft-ietf-tls-esni-09, the client is required to use the ECH
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
	helloOuterAad := echEncodeClientHelloOuterAAD(hello.marshal(), ech.handle.marshal())
	if helloOuterAad == nil {
		// This occurs if the ClientHelloOuter is malformed. This values was
		// already parsed into `hello`, so this should not happen.
		c.sendAlert(alertInternalError)
		return nil, fmt.Errorf("ech: failed to encode ClientHelloOuterAAD")
	}
	rawEncodedHelloInner, err := c.ech.opener.Open(ech.payload, helloOuterAad)
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

	// Accept ECH.
	c.ech.offered = true
	c.ech.accepted = true
	return helloInner, nil
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

// echCipherSuite represents an ECH ciphersuite, a KDF/AEAD algorithm pair. This
// is different from an HPKE ciphersuite, which represents a KEM/KDF/AEAD
// triple.
type echCipherSuite struct {
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

	var ech echClient
	ech.handle.suite.kdfId = uint16(kdf)
	ech.handle.suite.aeadId = uint16(aead)
	ech.handle.configId = make([]byte, 8)
	_, err = io.ReadFull(rand, ech.handle.configId)
	if err != nil {
		return nil, fmt.Errorf("tls: grease ech:: %s", err)
	}
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

					// Read the set of outer extension code points.
					outer := make(map[uint16]bool)
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
						panic(cryptobyte.BuildError{Err: errIllegalParameter})
					}

					// Ensure that all outer extensions have been incorporated.
					for _, incorporated := range outer {
						if !incorporated {
							panic(cryptobyte.BuildError{Err: errIllegalParameter})
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

	innerData, err := b.Bytes()
	if err == errIllegalParameter {
		return nil // Input malformed
	} else if err != nil {
		panic(err) // Host encountered internal error
	}

	return innerData
}

// echEncodeClientHelloOuterAAD interprets outerData as ClientHelloOuter and
// handleData as an ECH context handle and maps these to a ClientHelloOuterAAD.
// Returns nil if parsing outerData fails.
func echEncodeClientHelloOuterAAD(outerData, handleData []byte) []byte {
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

	b.AddBytes(handleData)
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
					panic(cryptobyte.BuildError{Err: errIllegalParameter})
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

	outerAadData, err := b.Bytes()
	if err == errIllegalParameter {
		return nil // Input malformed
	} else if err != nil {
		panic(err) // Host encountered internal error
	}

	return outerAadData
}

// echEncodeServerHelloConf interprets data as a ServerHello message and encodes
// it as a ServerHelloConf. Returns nil if parsing data fails.
func echEncodeServerHelloConf(data []byte) []byte {
	var (
		msgType                 uint8
		legacyVersion           uint16
		random                  []byte
		legacySessionId         cryptobyte.String
		cipherSuite             uint16
		legacyCompressionMethod uint8
		extensions              cryptobyte.String
		s                       cryptobyte.String
		b                       cryptobyte.Builder
	)

	u := cryptobyte.String(data)
	if !u.ReadUint8(&msgType) ||
		!u.ReadUint24LengthPrefixed(&s) || !u.Empty() {
		return nil
	}

	if !s.ReadUint16(&legacyVersion) ||
		!s.ReadBytes(&random, 32) ||
		!s.ReadUint8LengthPrefixed(&legacySessionId) ||
		!s.ReadUint16(&cipherSuite) ||
		!s.ReadUint8(&legacyCompressionMethod) {
		return nil
	}

	if s.Empty() {
		// Extensions field must be present in TLS 1.3.
		return nil
	}

	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return nil
	}

	b.AddUint8(msgType)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(legacyVersion)
		b.AddBytes(random[:24])
		b.AddBytes([]byte{0, 0, 0, 0, 0, 0, 0, 0})
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(legacySessionId)
		})
		b.AddUint16(cipherSuite)
		b.AddUint8(legacyCompressionMethod)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(extensions)
		})
	})

	return b.BytesOrPanic()
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
