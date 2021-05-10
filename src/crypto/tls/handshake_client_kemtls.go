// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/hmac"
	"crypto/kem"
	"errors"
	"sync/atomic"
)

func (hs *clientHandshakeStateTLS13) handshakeKEMTLS() error {
	c := hs.c

	if err := hs.sendClientKEMCiphertext(); err != nil {
		return err
	}

	// Send the KEMTLS client certificate if asked for
	if err := hs.sendKEMClientCertificate(); err != nil {
		return err
	}

	if _, err := c.flush(); err != nil {
		return err
	}

	if err := hs.readServerKEMCiphertext(); err != nil {
		return err
	}

	if err := hs.sendKEMTLSClientFinished(); err != nil {
		return err
	}

	if _, err := c.flush(); err != nil {
		return err
	}

	if err := hs.processKEMTLSServerFinished(); err != nil {
		return err
	}

	c.handleCFEvent(hs.handshakeTimings)
	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

func (hs *clientHandshakeStateTLS13) sendClientKEMCiphertext() error {
	c := hs.c
	var pk *kem.PublicKey
	var ok bool
	var ahs []byte

	if !(hs.pdkKEMTLS && hs.keyKEMShare) {
		if c.verifiedDC != nil && c.verifiedDC.cred.expCertVerfAlgo.isKEMTLS() {
			pk, ok = c.verifiedDC.cred.publicKey.(*kem.PublicKey)
			if !ok {
				c.sendAlert(alertInternalError)
				return errors.New("tls: invalid key")
			}
		} else {
			pk, ok = c.peerCertificates[0].PublicKey.(*kem.PublicKey)
			if !ok {
				c.sendAlert(alertInternalError)
				return errors.New("tls: invalid key")
			}
		}

		ss, ct, err := kem.Encapsulate(hs.c.config.rand(), pk)
		if err != nil {
			return err
		}

		msg := clientKeyExchangeMsg{
			ciphertext: ct,
		}

		_, err = c.writeRecord(recordTypeHandshake, msg.marshal())
		if err != nil {
			return err
		}

		_, err = hs.transcript.Write(msg.marshal())
		if err != nil {
			return err
		}

		hs.handshakeTimings.WriteKEMCiphertext = hs.handshakeTimings.elapsedTime()

		// AHS <- HKDF.Extract(dHS, ss_s)
		ahs = hs.suite.extract(ss, hs.suite.deriveSecret(hs.handshakeSecret, "derived", nil))
	} else {
		ahs = hs.suite.extract(hs.ssKEMTLS, hs.suite.deriveSecret(hs.handshakeSecret, "derived", nil))
	}

	// CAHTS <- HKDF.Expand(AHS, "c ahs traffic", CH..CKC)
	clientSecret := hs.suite.deriveSecret(ahs,
		clientAuthenticatedHandshakeTrafficLabel, hs.transcript)
	c.out.setTrafficSecret(hs.suite, clientSecret)
	// SAHTS <- HKDF.Expand(AHS, "s ahs traffic", CH..CKC)
	serverSecret := hs.suite.deriveSecret(ahs,
		serverAuthenticatedHandshakeTrafficLabel, hs.transcript)
	c.in.setTrafficSecret(hs.suite, serverSecret)

	// dAHS  <- HKDF.Expand(AHS, "derived", nil)
	hs.handshakeSecret = hs.suite.deriveSecret(ahs, "derived", nil)

	err := c.config.writeKeyLog(keyLogLabelClientKEMAuthenticatedHandshake, hs.hello.random, clientSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	err = c.config.writeKeyLog(keyLogLabelServerKEMAuthenticatedHandshake, hs.hello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) sendKEMClientCertificate() error {
	c := hs.c

	if hs.certReq == nil {
		return nil
	}

	cri := certificateRequestInfo(hs.certReq, c.vers)

	cert, err := c.getClientCertificate(cri)
	if err != nil {
		return err
	}

	if hs.certReq.supportDelegatedCredential && len(hs.certReq.supportedSignatureAlgorithmsDC) > 0 {
		var dcPair *DelegatedCredentialPair
		if delegatedCredentialPair, err := getClientDelegatedCredential(cri, cert); err == nil {
			if delegatedCredentialPair.DC != nil && delegatedCredentialPair.PrivateKey != nil {
				var err error
				// Even if the Delegated Credential has already been marshalled, be sure it is the correct one.
				if delegatedCredentialPair.DC.raw, err = delegatedCredentialPair.DC.marshal(); err == nil {
					dcPair = delegatedCredentialPair
					cert.DelegatedCredential = dcPair.DC.raw
					cert.DelegatedCredentialPrivateKey = dcPair.PrivateKey
				}
			}
		}
	}

	if len(cert.DelegatedCredential) > 0 {
		_, ok := cert.DelegatedCredentialPrivateKey.(*kem.PrivateKey)
		if !ok {
			// it has to be a KEM key
			c.sendAlert(alertInternalError)
			return errors.New("tls: incorrect delegated credential found")
		}
	} else if len(cert.Certificate) != 0 {
		_, ok := cert.PrivateKey.(*kem.PrivateKey)
		if !ok {
			// it has to be a KEM key
			c.sendAlert(alertInternalError)
			return errors.New("tls: incorrect certificate found")
		}
	}

	certMsg := new(certificateMsgTLS13)
	certMsg.certificate = *cert
	hs.certKEMTLS = cert

	certMsg.scts = hs.certReq.scts && len(cert.SignedCertificateTimestamps) > 0
	certMsg.ocspStapling = hs.certReq.ocspStapling && len(cert.OCSPStaple) > 0
	certMsg.delegatedCredential = hs.certReq.supportDelegatedCredential && len(cert.DelegatedCredential) > 0

	hs.transcript.Write(certMsg.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
		return err
	}

	hs.handshakeTimings.WriteCertificate = hs.handshakeTimings.elapsedTime()

	return nil
}

func (hs *clientHandshakeStateTLS13) readServerKEMCiphertext() error {
	c := hs.c

	if hs.certReq == nil {
		return nil
	}

	if len(hs.certKEMTLS.Certificate) == 0 {
		return nil
	}

	var sk *kem.PrivateKey
	var ok, ok1 bool
	sk, ok = hs.certKEMTLS.PrivateKey.(*kem.PrivateKey)
	if !ok {
		sk, ok1 = hs.certKEMTLS.DelegatedCredentialPrivateKey.(*kem.PrivateKey)
		if !ok1 {
			c.sendAlert(alertInternalError)
			return errors.New("crypto/tls: private key unexpectedly of wrong type")
		}
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	kexMsg, ok := msg.(*serverKeyExchangeMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(kexMsg, msg)
	}
	hs.transcript.Write(kexMsg.marshal())

	hs.handshakeTimings.ReadKEMCiphertext = hs.handshakeTimings.elapsedTime()

	ss, err := kem.Decapsulate(sk, kexMsg.key)
	if err != nil {
		return err
	}

	// compute MS
	// MS <- HKDF.Extract(dAHS, ssC)
	hs.masterSecret = hs.suite.extract(ss, hs.handshakeSecret)
	hs.isClientAuthKEMTLS = true
	c.didClientAuthentication = true

	return nil
}

func (hs *clientHandshakeStateTLS13) sendKEMTLSClientFinished() error {
	c := hs.c

	if !hs.isClientAuthKEMTLS {
		hs.masterSecret = hs.suite.extract(nil, hs.handshakeSecret)
	}
	// fk_c <- HKDF.Expand(MS, "c finished", nil)
	// CF <- HMAC(fk_c, CH..CKC)
	finished := &finishedMsg{
		verifyData: hs.suite.finishedHashKEMTLS(hs.masterSecret, "c", hs.transcript),
	}

	if _, err := hs.transcript.Write(finished.marshal()); err != nil {
		return err
	}
	if _, err := c.writeRecord(recordTypeHandshake, finished.marshal()); err != nil {
		return err
	}
	hs.handshakeTimings.WriteClientFinished = hs.handshakeTimings.elapsedTime()

	// CATS <- HKDF.Expand(MS, "c ap traffic", CH..CF)
	hs.trafficSecret = hs.suite.deriveSecret(hs.masterSecret,
		clientApplicationTrafficLabel, hs.transcript)

	c.out.setTrafficSecret(hs.suite, hs.trafficSecret)

	err := c.config.writeKeyLog(keyLogLabelClientTraffic, hs.hello.random, hs.trafficSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) processKEMTLSServerFinished() error {
	c := hs.c
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	finished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(finished, msg)
	}

	hs.handshakeTimings.ReadServerFinished = hs.handshakeTimings.elapsedTime()

	// HMAC(fk_s , CH..CF)
	expectedMAC := hs.suite.finishedHashKEMTLS(hs.masterSecret, "s", hs.transcript)
	if !hmac.Equal(expectedMAC, finished.verifyData) {
		c.sendAlert(alertDecryptError)
		return errors.New("tls: invalid server finished hash")
	}

	if _, err := hs.transcript.Write(finished.marshal()); err != nil {
		return err
	}

	// SATS <- HKDF.Expand(MS, "s ap traffic", CH..SF)
	serverSecret := hs.suite.deriveSecret(hs.masterSecret,
		serverApplicationTrafficLabel, hs.transcript)
	c.in.setTrafficSecret(hs.suite, serverSecret)

	err = c.config.writeKeyLog(keyLogLabelServerTraffic, hs.hello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	if !c.config.SessionTicketsDisabled && c.config.ClientSessionCache != nil {
		c.resumptionSecret = hs.suite.deriveSecret(hs.masterSecret,
			resumptionLabel, hs.transcript)
	}

	c.ekm = hs.suite.exportKeyingMaterial(hs.masterSecret, hs.transcript)
	c.didKEMTLS = true

	return nil
}
