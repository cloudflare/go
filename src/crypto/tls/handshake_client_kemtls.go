// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/hmac"
	kem "crypto/kem"
	"errors"
	"sync/atomic"
)

func (hs *clientHandshakeStateTLS13) handshakeKEMTLS() error {
	c := hs.c
	// Send over KEM CT and derive AHS
	if err := hs.sendClientKemCiphertext(); err != nil {
		return err
	}
	if hs.certReq != nil {
		return errors.New("crypto/tls: KEMTLS does not support certificate requests yet")
	}

	// send ClientFinished
	if err := hs.sendKEMTLSClientFinished(); err != nil {
		return err
	}

	// We are now ready to start writing data on the wire
	atomic.StoreUint32(&c.handshakeStatus, 1)

	// read ServerFinished
	if err := hs.processKEMTLSServerFinished(); err != nil {
		return err
	}

	// done
	if _, err := c.flush(); err != nil {
		return err
	}
	return nil
}

func (hs *clientHandshakeStateTLS13) sendClientKemCiphertext() error {
	c := hs.c

	pk := c.verifiedDC.Cred.PublicKey.(kem.PublicKey)

	ct, ss, err := kem.Encapsulate(hs.c.config.Rand, &pk)
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

	ahs := hs.suite.extract(ss, hs.suite.deriveSecret(hs.handshakeSecret, "derived", nil))
	clientSecret := hs.suite.deriveSecret(ahs,
		clientAuthenticatedHandshakeTrafficLabel, hs.transcript)
	c.out.setTrafficSecret(hs.suite, clientSecret)
	serverSecret := hs.suite.deriveSecret(ahs,
		serverAuthenticatedHandshakeTrafficLabel, hs.transcript)
	c.in.setTrafficSecret(hs.suite, serverSecret)

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

func (hs *clientHandshakeStateTLS13) sendKEMTLSClientFinished() error {
	c := hs.c

	hs.masterSecret = hs.suite.extract(nil,
		hs.suite.deriveSecret(hs.handshakeSecret, "derived", nil))

	finished := &finishedMsg{
		verifyData: hs.suite.finishedHash(c.out.trafficSecret, hs.transcript),
	}

	if _, err := hs.transcript.Write(finished.marshal()); err != nil {
		return err
	}
	if _, err := c.writeRecord(recordTypeHandshake, finished.marshal()); err != nil {
		return err
	}

	hs.trafficSecret = hs.suite.deriveSecret(hs.masterSecret,
		clientApplicationTrafficLabel, hs.transcript)

	c.out.setTrafficSecret(hs.suite, hs.trafficSecret)

	err := c.config.writeKeyLog(keyLogLabelClientTraffic, hs.hello.random, hs.trafficSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	if !c.config.SessionTicketsDisabled && c.config.ClientSessionCache != nil {
		c.resumptionSecret = hs.suite.deriveSecret(hs.masterSecret,
			resumptionLabel, hs.transcript)
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

	expectedMAC := hs.suite.finishedHash(c.in.trafficSecret, hs.transcript)
	if !hmac.Equal(expectedMAC, finished.verifyData) {
		c.sendAlert(alertDecryptError)
		return errors.New("tls: invalid server finished hash")
	}

	if _, err := hs.transcript.Write(finished.marshal()); err != nil {
		return err
	}

	serverSecret := hs.suite.deriveSecret(hs.masterSecret,
		serverApplicationTrafficLabel, hs.transcript)
	c.in.setTrafficSecret(hs.suite, serverSecret)

	err = c.config.writeKeyLog(keyLogLabelServerTraffic, hs.hello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	c.ekm = hs.suite.exportKeyingMaterial(hs.masterSecret, hs.transcript)

	return nil
}
