// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

// Delegated credentials for TLS
// (https://tools.ietf.org/html/draft-ietf-tls-subcerts) is an IETF Internet
// draft and proposed TLS extension. If the client supports this extension, then
// the server may use a "delegated credential" as the signing key in the
// handshake. A delegated credential is a short lived public/secret key pair
// delegated to the server by an entity trusted by the client. This allows a
// middlebox to terminate a TLS connection on behalf of the entity; for example,
// this can be used to delegate TLS termination to a reverse proxy. Credentials
// can't be revoked; in order to mitigate risk in case the middlebox is
// compromised, the credential is only valid for a short time (days, hours, or
// even minutes).

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	dcMaxTTLSeconds   = 60 * 60 * 24 * 7 // The maxium validity period is 7 days
	dcMaxTTL          = time.Duration(dcMaxTTLSeconds * time.Second)
	dcMaxPubLen       = 1 << 24 // Bytes
	dcMaxSignatureLen = 1 << 16 // Bytes
)

var errNoDelegationUsage = errors.New("tls: certificate not authorized for delegation")

// delegationUsageID is the DelegationUsage X.509 extension OID
var delegationUsageID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 44}

// CreateDelegationUsagePKIXExtension returns a pkix.Extension that every delegation
// certificate must have.
// TODO: we might not need this if we go for modifying x509
func CreateDelegationUsagePKIXExtension() *pkix.Extension {
	return &pkix.Extension{
		Id:       delegationUsageID,
		Critical: false,
		Value:    nil,
	}
}

// isValidForDelegation returns true if a certificate can be used for delegated
// credentials.
func isValidForDelegation(cert *x509.Certificate) bool {
	// Check that the digitalSignature key usage is set.
	// The certificate must contains the digitalSignature KeyUsage.
	if (cert.KeyUsage & x509.KeyUsageDigitalSignature) == 0 {
		return false
	}

	// Check that the certificate has the DelegationUsage extension and that
	// it's non-critical (See Section 4.2 of RFC5280).
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(delegationUsageID) {
			return true
		}
	}
	return false
}

// IsExpired returns true if the credential has expired. The end of the validity
// interval is defined as the delegator certificate's notBefore field ('start')
// plus ValidTime seconds. This function simply checks that the current time
// ('now') is before the end of the validity interval.
func (dc *DelegatedCredential) IsExpired(start, now time.Time) bool {
	end := start.Add(dc.Cred.ValidTime)
	return !now.Before(end)
}

// InvalidTTL returns true if the credential's validity period is longer than the
// maximum permitted. This is defined by the certificate's notBefore field
// ('start') plus the ValidTime, minus the current time ('now').
func (dc *DelegatedCredential) InvalidTTL(start, now time.Time) bool {
	return dc.Cred.ValidTime > (now.Sub(start) + dcMaxTTL).Round(time.Second)
}

// Credential stores the public components of a Delegated Credential.
type Credential struct {
	// The amount of time for which the credential is valid. Specifically, the
	// the credential expires 'ValidTime' seconds after the 'notBefore' of the
	// delegation certificate. The delegator shall not issue delegated
	// credentials that are valid for more than 7 days from their current time.
	//
	// When this data structure is serialized, this value is converted to a
	// uint32 representing the duration in seconds.
	ValidTime time.Duration
	// The signature scheme associated with the credential public key.
	// This is expected to be the same as the CertificateVerify.algorithm
	// sent by the server.
	expCertVerfAlgo SignatureScheme
	// The credential's public key.
	PublicKey crypto.PublicKey
}

// DelegatedCredential stores the credential and its signature.
type DelegatedCredential struct {
	// The serialized form of the Credential
	Raw []byte

	// Credential stores the public components of a Delegated Credential
	Cred *Credential

	// The signature scheme used to sign the credential
	Algorithm SignatureScheme

	// The Credential's delegation: a signature that binds the credential to
	// the end-entity certificate's public key
	Signature []byte
}

// marshalSubjectPublicKeyInfo returns a DER encoded SubjectPublicKeyInfo structure
// (as defined in the X.509 standard) for the credential.
// TODO: maybe we can move this as well to x509
// TODO: add the other signatures flavors, as defined in common.go
func (cred *Credential) marshalPublicKeyInfo() ([]byte, error) {
	switch cred.expCertVerfAlgo {
	case ECDSAWithP256AndSHA256,
		ECDSAWithP384AndSHA384,
		ECDSAWithP521AndSHA512:
		serPub, err := x509.MarshalPKIXPublicKey(cred.PublicKey)
		if err != nil {
			return nil, err
		}

		return serPub, nil

	default:
		return nil, fmt.Errorf("unsupported signature scheme: 0x%04x", cred.expCertVerfAlgo)
	}
}

// unmarshalPublicKeyInfo parses a DER encoded PublicKeyInfo
// structure into a public key and its corresponding algorithm.
// TODO: add the other signatures flavors, as defined in common.go
func unmarshalPublicKeyInfo(serialized []byte) (crypto.PublicKey, SignatureScheme, error) {
	pubKey, err := x509.ParsePKIXPublicKey(serialized)
	if err != nil {
		return nil, 0, err
	}

	switch pk := pubKey.(type) {
	case *ecdsa.PublicKey:
		curveName := pk.Curve.Params().Name
		if curveName == "P-256" {
			return pk, ECDSAWithP256AndSHA256, nil
		} else if curveName == "P-384" {
			return pk, ECDSAWithP384AndSHA384, nil
		} else if curveName == "P-521" {
			return pk, ECDSAWithP521AndSHA512, nil
		} else {
			return nil, 0, fmt.Errorf("curve %s s not supported", curveName)
		}

	default:
		return nil, 0, fmt.Errorf("unsupported delgation key type: %T", pk)
	}
}

// marshal encodes the credential struct of the Delegated Credential.
func (cred *Credential) marshal() ([]byte, error) {
	ser := make([]byte, 4)
	binary.BigEndian.PutUint32(ser, uint32(cred.ValidTime/time.Second))

	var serAlgo [2]byte
	binary.BigEndian.PutUint16(serAlgo[:], uint16(cred.expCertVerfAlgo))
	ser = append(ser, serAlgo[:]...)

	// Encode the public key
	serPub, err := cred.marshalPublicKeyInfo()
	if err != nil {
		return nil, err
	}
	// Assert that the public key encoding is no longer than 2^24  bytes.
	if len(serPub) > dcMaxPubLen {
		return nil, errors.New("tls: public key is not valid")
	}

	var serLen [2]byte
	binary.BigEndian.PutUint16(serLen[:], uint16(len(serPub)))
	ser = append(ser, serLen[:]...)
	ser = append(ser, serPub...)

	return ser, nil
}

// unmarshalCredential decodes serialized bytes and returns a credential, if possible.
func unmarshalCredential(ser []byte) (*Credential, error) {
	if len(ser) < 8 {
		return nil, errors.New("tls: delegated credential is not valid")
	}

	validTime := time.Duration(binary.BigEndian.Uint32(ser)) * time.Second
	pubAlgo := SignatureScheme(binary.BigEndian.Uint16(ser[4:6]))
	pubLen := binary.BigEndian.Uint16(ser[6:8])

	pubKey, err := x509.ParsePKIXPublicKey(ser[8:])
	if err != nil {
		return nil, err
	}

	if len(ser[8:]) != int(pubLen) {
		return nil, errors.New("tls: delegated credential is not valid")
	}

	return &Credential{validTime, pubAlgo, pubKey}, nil
}

// getCredentialLen returns the number of bytes comprising the serialized
// credential struct inside the Delegated Credential.
func getCredentialLen(ser []byte) (int, error) {
	if len(ser) < 8 {
		return 0, errors.New("tls: delegated credential is not valid")
	}

	// The validity time.
	ser = ser[4:]

	// The expCertVerfAlgo.
	ser = ser[2:]

	// The lenght of the Public Key.
	pubLen := int(binary.BigEndian.Uint16(ser))
	ser = ser[2:]

	if len(ser) < pubLen {
		return 0, errors.New("tls: delegated credential is not valid")
	}

	return 8 + pubLen, nil
}

// getHash maps the SignatureScheme to its corresponding hash function.
// TODO: replace this with typeAndHashFromSignatureScheme
func getHash(scheme SignatureScheme) crypto.Hash {
	switch scheme {
	case ECDSAWithP256AndSHA256:
		return crypto.SHA256
	case ECDSAWithP384AndSHA384:
		return crypto.SHA384
	case ECDSAWithP521AndSHA512:
		return crypto.SHA512
	default:
		return 0 // Unknown hash function
	}
}

// getCurve maps the SignatureScheme to its corresponding elliptic.Curve.
// TODO: replace this with typeAndHashFromSignatureScheme
func getCurve(scheme SignatureScheme) elliptic.Curve {
	switch scheme {
	case ECDSAWithP256AndSHA256:
		return elliptic.P256()
	case ECDSAWithP384AndSHA384:
		return elliptic.P384()
	case ECDSAWithP521AndSHA512:
		return elliptic.P521()
	default:
		return nil
	}
}

// prepareDelegation returns the message that the delegator is going to sign.
// The inputs are the credential ('cred'), the DER-encoded end-entity
// certificate ('dCert'), the signature scheme of the delegator
// ('algo').
func prepareDelegation(cred *Credential, dCert []byte, algo SignatureScheme, peer string) ([]byte, error) {
	values := make([]byte, 64, 128)
	for i := range values {
		values[i] = 0x20
	}

	if peer == "server" {
		values = append(values, []byte("TLS, server delegated credentials\x00")...)
	} else if peer == "client" {
		values = append(values, []byte("TLS, client delegated credentials\x00")...)
	}

	values = append(values, dCert...)

	serCred, err := cred.marshal()
	if err != nil {
		return nil, err
	}
	values = append(values, serCred...)

	var serAlgo [2]byte
	binary.BigEndian.PutUint16(serAlgo[:], uint16(algo))
	values = append(values, serAlgo[:]...)

	return values, nil
}

// NewDelegatedCredential creates a new delegated credential using 'cert' for
// delegation. It generates a public/private key pair for the provided signature
// algorithm ('scheme'), validity interval (defined by 'cert.Leaf.notBefore' and
// 'validTime'), and TLS version ('vers'), and signs it using 'cert.PrivateKey'.
// TODO: add the other signature schemes
func NewDelegatedCredential(cert *Certificate, pubAlgo SignatureScheme, validTime time.Duration, peer string) (*DelegatedCredential, crypto.PrivateKey, error) {
	// The granularity of DC validity is seconds.
	validTime = validTime.Round(time.Second)

	// Parse the leaf certificate if needed.
	var err error
	if cert.Leaf == nil {
		if len(cert.Certificate[0]) == 0 {
			return nil, nil, errors.New("tls: missing leaf certificate for delegated credential")
		}
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, nil, err
		}

	}

	// Check that the leaf certificate can be used for delegation.
	if !isValidForDelegation(cert.Leaf) {
		return nil, nil, errNoDelegationUsage
	}

	// Extract the algorithm used to sign the DelegatedCredential from the end-entity (leaf) certificate
	var sigAlgo SignatureScheme
	switch sk := cert.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		pk := sk.Public().(*ecdsa.PublicKey)
		curveName := pk.Curve.Params().Name
		certAlg := cert.Leaf.SignatureAlgorithm
		if certAlg == x509.ECDSAWithSHA256 && curveName == "P-256" {
			sigAlgo = ECDSAWithP256AndSHA256
		} else if certAlg == x509.ECDSAWithSHA384 && curveName == "P-384" {
			sigAlgo = ECDSAWithP384AndSHA384
		} else if certAlg == x509.ECDSAWithSHA512 && curveName == "P-521" {
			sigAlgo = ECDSAWithP521AndSHA512
		} else {
			return nil, nil, fmt.Errorf("using curve %s for %s is not supported", curveName, cert.Leaf.SignatureAlgorithm)
		}
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm for delegated credential: %T", sk)
	}

	// Generate the Delegated Credential Key Pair based on the provided scheme
	var sk crypto.PrivateKey
	var pk crypto.PublicKey
	switch pubAlgo {
	case ECDSAWithP256AndSHA256,
		ECDSAWithP384AndSHA384,
		ECDSAWithP521AndSHA512:
		sk, err = ecdsa.GenerateKey(getCurve(pubAlgo), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pk = sk.(*ecdsa.PrivateKey).Public()
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm for delegated credential: 0x%04x", pubAlgo)
	}

	// Prepare the credential for digital signing.
	credential := &Credential{validTime, pubAlgo, pk}
	values, err := prepareDelegation(credential, cert.Leaf.Raw, sigAlgo, peer)
	if err != nil {
		return nil, nil, err
	}

	hash := getHash(sigAlgo)
	var sig []byte
	switch sk := cert.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		opts := crypto.SignerOpts(hash)
		sig, err = sk.Sign(rand.Reader, values, opts)
		if err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("unsupported key type for delegated credential: %T", sk)
	}

	return &DelegatedCredential{
		Cred:      credential,
		Algorithm: sigAlgo,
		Signature: sig,
	}, sk, nil
}

// Validate checks that the delegated credential is valid by checking that the
// signature is valid, that the credential hasn't expired, and that the TTL is
// valid. It also checks that certificate can be used for delegation.
func (dc *DelegatedCredential) Validate(cert *x509.Certificate, peer string, now time.Time) (bool, error) {
	if dc.IsExpired(cert.NotBefore, now) {
		return false, errors.New("tls: delegated credential is not valid")
	}

	if dc.InvalidTTL(cert.NotBefore, now) {
		return false, errors.New("tls: delegated credential is not valid")
	}

	in, err := prepareDelegation(dc.Cred, cert.Raw, dc.Algorithm, peer)
	if err != nil {
		return false, err
	}

	// TODO: for the moment
	if !(dc.Cred.expCertVerfAlgo == ECDSAWithP256AndSHA256 && cert.SignatureAlgorithm == x509.ECDSAWithSHA256) {
		return false, errors.New("tls: delegated credential is not valid")
	}

	if !isValidForDelegation(cert) {
		return false, errors.New("tls: delegated credential is not valid")
	}

	// TODO(any) This code overlaps signficantly with verifyHandshakeSignature()
	// in ../auth.go. This should be refactored.
	switch dc.Algorithm {
	case ECDSAWithP256AndSHA256,
		ECDSAWithP384AndSHA384,
		ECDSAWithP521AndSHA512:
		pk, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return false, errors.New("expected ECDSA public key")
		}

		//case *ecdsa.PublicKey:
		//	if pubKeyAlgo != ECDSA {
		//		return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		//	}
		//	if !ecdsa.VerifyASN1(pub, signed, signature) {
		//		return errors.New("x509: ECDSA verification failure")
		//	}
		//	return

		//sig := new(ecdsaSignature)
		//if _, err = asn1.Unmarshal(dc.Signature, sig); err != nil {
		//	return false, err
		//}
		return ecdsa.VerifyASN1(pk, in, dc.Signature), nil
	default:
		return false, fmt.Errorf(
			"unsupported signature scheme: 0x%04x", dc.Algorithm)
	}
}

// Marshal encodes a DelegatedCredential structure. It also sets dc.Raw to the encoding.
func (dc *DelegatedCredential) Marshal() ([]byte, error) {
	ser, err := dc.Cred.marshal()
	if err != nil {
		return nil, err
	}

	serAlgo := make([]byte, 2)
	binary.BigEndian.PutUint16(serAlgo, uint16(dc.Algorithm))
	ser = append(ser, serAlgo...)

	if len(dc.Signature) > dcMaxSignatureLen {
		return nil, errors.New("tls: delegated credential is not valid")
	}
	serLenSig := make([]byte, 2)
	binary.BigEndian.PutUint16(serLenSig, uint16(len(dc.Signature)))

	ser = append(ser, serLenSig...)
	ser = append(ser, dc.Signature...)

	dc.Raw = ser

	return ser, nil
}

// UnmarshalDelegatedCredential decodes a DelegatedCredential structure.
func UnmarshalDelegatedCredential(ser []byte) (*DelegatedCredential, error) {
	serCredentialLen, err := getCredentialLen(ser)
	if err != nil {
		return nil, err
	}

	credential, err := unmarshalCredential(ser[:serCredentialLen])
	if err != nil {
		return nil, err
	}

	ser = ser[serCredentialLen:]
	if len(ser) < 4 {
		return nil, errors.New("tls: delegated credential is not valid")
	}
	algo := SignatureScheme(binary.BigEndian.Uint16(ser))

	ser = ser[2:]
	serSignatureLen := binary.BigEndian.Uint16(ser)

	ser = ser[2:]
	if len(ser) < int(serSignatureLen) {
		return nil, errors.New("tls: delegated credential is not valid")
	}
	sig := ser[:serSignatureLen]

	return &DelegatedCredential{
		Cred:      credential,
		Algorithm: algo,
		Signature: sig,
	}, nil
}
