package tls

import (
	"crypto/hmac"
	"crypto/kem"
	"errors"
	"sync/atomic"
)

func (hs *serverHandshakeStateTLS13) handshakeKEMTLS() error {
	c := hs.c

	if err := hs.readClientKEMCiphertext(); err != nil {
		return err
	}
	if err := hs.readClientKEMCertificate(); err != nil {
		return err
	}
	if err := hs.sendServerKEMCiphertext(); err != nil {
		return err
	}
	if _, err := c.flush(); err != nil {
		return err
	}
	if err := hs.readKEMTLSClientFinished(); err != nil {
		return err
	}

	if err := hs.writeKEMTLSServerFinished(); err != nil {
		return err
	}
	if _, err := c.flush(); err != nil {
		return err
	}

	c.handleCFEvent(hs.handshakeTimings)
	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

func (hs *serverHandshakeStateTLS13) readClientKEMCiphertext() error {
	c := hs.c

	sk, ok := hs.cert.PrivateKey.(*kem.PrivateKey)
	if !ok {
		c.sendAlert(alertInternalError)
		return errors.New("crypto/tls: private key unexpectedly of wrong type")
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	kexMsg, ok := msg.(*clientKeyExchangeMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(kexMsg, msg)
	}

	hs.transcript.Write(kexMsg.marshal())
	hs.handshakeTimings.ReadKEMCiphertext = hs.handshakeTimings.elapsedTime()

	ss, err := kem.Decapsulate(sk, kexMsg.ciphertext)
	if err != nil {
		return err
	}

	// derive AHS
	// AHS <- HKDF.Extract(dHS, ss_s)
	ahs := hs.suite.extract(ss, hs.suite.deriveSecret(hs.handshakeSecret, "derived", nil))
	// CAHTS <- HKDF.Expand(AHS, "c ahs traffic", CH..CKC)
	clientSecret := hs.suite.deriveSecret(ahs,
		clientAuthenticatedHandshakeTrafficLabel, hs.transcript)
	c.in.setTrafficSecret(hs.suite, clientSecret)
	// SAHTS <- HKDF.Expand(AHS, "s ahs traffic", CH..CKC)
	serverSecret := hs.suite.deriveSecret(ahs,
		serverAuthenticatedHandshakeTrafficLabel, hs.transcript)
	c.out.setTrafficSecret(hs.suite, serverSecret)

	// dAHS  <- HKDF.Expand(AHS, "derived", nil)
	hs.handshakeSecret = hs.suite.deriveSecret(ahs, "derived", nil)

	return nil
}

func (hs *serverHandshakeStateTLS13) requestClientKEMCert() bool {
	return hs.c.config.ClientAuth >= RequestClientCert && !hs.usingPSK
}

func (hs *serverHandshakeStateTLS13) readClientKEMCertificate() error {
	c := hs.c

	if !hs.requestClientKEMCert() {
		// Make sure the connection is still being verified whether or not
		// the server requested a client certificate.
		if c.config.VerifyConnection != nil {
			if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		}
		return nil
	}

	// If we requested a client kem certificate, then the client must send a
	// kem certificate message.
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	certMsg, ok := msg.(*certificateMsgTLS13)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}
	hs.transcript.Write(certMsg.marshal())

	hs.handshakeTimings.ReadCertificate = hs.handshakeTimings.elapsedTime()

	if err := c.processCertsFromClient(certMsg.certificate); err != nil {
		return err
	}

	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	if len(certMsg.certificate.Certificate) != 0 {
		if certMsg.delegatedCredential {
			if err := hs.processDelegatedCredentialFromClient(certMsg.certificate.DelegatedCredential, nil); err != nil {
				return err
			}
		}

		pk := c.peerCertificates[0].PublicKey
		if c.verifiedDC != nil {
			pk = c.verifiedDC.cred.publicKey
		}

		_, ok = pk.(*kem.PublicKey)
		if !ok {
			// it has to be a KEM key
			c.sendAlert(alertInternalError)
			return nil
		}
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) sendServerKEMCiphertext() error {
	c := hs.c

	if !hs.requestClientKEMCert() {
		return nil
	}

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

	ss, ct, err := kem.Encapsulate(hs.c.config.rand(), pk)
	if err != nil {
		return err
	}

	msg := serverKeyExchangeMsg{
		raw: nil,
		key: ct,
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

	// MS <- HKDF.Extract(dAHS, ssC)
	hs.masterSecret = hs.suite.extract(ss, hs.handshakeSecret)
	hs.isClientAuthKEMTLS = true

	return nil
}

func (hs *serverHandshakeStateTLS13) readKEMTLSClientFinished() error {
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

	hs.handshakeTimings.ReadClientFinished = hs.handshakeTimings.elapsedTime()

	if !hs.isClientAuthKEMTLS {
		// compute MS
		// MS <- HKDF.Extract(dAHS, 0)
		hs.masterSecret = hs.suite.extract(nil, hs.handshakeSecret)
	}

	// fk_s <- HKDF.Expand(MS, "s finished", nil)
	expectedMAC := hs.suite.finishedHashKEMTLS(hs.masterSecret, "c", hs.transcript)
	if !hmac.Equal(expectedMAC, finished.verifyData) {
		c.sendAlert(alertDecryptError)
		return errors.New("tls: invalid server finished hash")
	}

	if _, err := hs.transcript.Write(finished.marshal()); err != nil {
		return err
	}

	// CATS <- HKDF.Expand(MS, "c ap traffic", CH..CF)
	clientSecret := hs.suite.deriveSecret(hs.masterSecret, clientApplicationTrafficLabel, hs.transcript)
	c.in.setTrafficSecret(hs.suite, clientSecret)

	err = c.config.writeKeyLog(keyLogLabelClientTraffic, hs.hello.random, clientSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) writeKEMTLSServerFinished() error {
	c := hs.c

	finished := &finishedMsg{
		verifyData: hs.suite.finishedHashKEMTLS(hs.masterSecret, "s", hs.transcript),
	}

	if _, err := hs.transcript.Write(finished.marshal()); err != nil {
		return err
	}
	if _, err := c.writeRecord(recordTypeHandshake, finished.marshal()); err != nil {
		return err
	}

	hs.handshakeTimings.WriteServerFinished = hs.handshakeTimings.elapsedTime()

	// TS <- HKDF.Expand(MS, "s ap traffic", CH..SF)
	hs.trafficSecret = hs.suite.deriveSecret(hs.masterSecret,
		serverApplicationTrafficLabel, hs.transcript)

	c.out.setTrafficSecret(hs.suite, hs.trafficSecret)

	err := c.config.writeKeyLog(keyLogLabelServerTraffic, hs.hello.random, hs.trafficSecret)
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
