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

	// Send the KEM client certificate if asked for
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

	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

func (hs *clientHandshakeStateTLS13) sendClientKEMCiphertext() error {
	c := hs.c
	var pk *kem.PublicKey
	var ok bool

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

	ss, ct, err := kem.Encapsulate(hs.c.config.Rand, pk)
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

	// AHS <- HKDF.Extract(dHS, ss_s)
	ahs := hs.suite.extract(ss, hs.suite.deriveSecret(hs.handshakeSecret, "derived", nil))

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

	err = c.config.writeKeyLog(keyLogLabelClientAuthenticatedHandshake, hs.hello.random, clientSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	err = c.config.writeKeyLog(keyLogLabelServerAuthenticatedHandshake, hs.hello.random, serverSecret)
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

	cert, err := c.getClientCertificate(&CertificateRequestInfo{
		AcceptableCAs:               hs.certReq.certificateAuthorities,
		SignatureSchemes:            hs.certReq.supportedSignatureAlgorithms,
		SupportsDelegatedCredential: hs.certReq.supportDelegatedCredential,
		SignatureSchemesDC:          hs.certReq.supportedSignatureAlgorithmsDC,
		Version:                     c.vers,
	})
	if err != nil {
		return err
	}

	if hs.certReq.supportDelegatedCredential && c.config.GetDelegatedCredential != nil {
		dCred, priv, err := c.config.GetDelegatedCredential(nil, certificateRequestInfo(hs.certReq))
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		if dCred != nil && priv != nil {
			cert.PrivateKey = priv
			if dCred.raw == nil {
				dCred.raw, err = dCred.marshal()
				if err != nil {
					c.sendAlert(alertInternalError)
					return err
				}
			}
			cert.DelegatedCredential = dCred.raw
		}
	}

	_, ok := cert.PrivateKey.(*kem.PrivateKey)
	if !ok {
		// it has to be a KEM key
		c.sendAlert(alertInternalError)
		return nil
	}

	certMsg := new(certificateMsgTLS13)

	certMsg.certificate = *cert
	hs.cert = cert
	certMsg.scts = hs.certReq.scts && len(cert.SignedCertificateTimestamps) > 0
	certMsg.ocspStapling = hs.certReq.ocspStapling && len(cert.OCSPStaple) > 0
	certMsg.delegatedCredential = hs.certReq.supportDelegatedCredential && len(cert.DelegatedCredential) > 0

	hs.transcript.Write(certMsg.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
		return err
	}

	hs.handshakeTimings.WriteCertificate = hs.handshakeTimings.elapsedTime()

	// If we sent an empty certificate message, skip the CertificateVerify.
	if len(cert.Certificate) == 0 {
		return nil
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) readServerKEMCiphertext() error {
	c := hs.c

	if hs.certReq == nil {
		return nil
	}

	sk, ok := hs.cert.PrivateKey.(*kem.PrivateKey)
	if !ok {
		c.sendAlert(alertInternalError)
		return errors.New("crypto/tls: private key unexpectedly wrong type")
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

	ss, err := kem.Decapsulate(sk, kexMsg.key)
	if err != nil {
		return err
	}

	// compute MS
	// MS <- HKDF.Extract(dAHS, ssC)
	hs.masterSecret = hs.suite.extract(ss, hs.handshakeSecret)
	hs.isClientAuthKEMTLS = true

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

	return nil
}
