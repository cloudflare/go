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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

const (
	dcMaxTTLSeconds   = 60 * 60 * 24 * 7 // The maxium validity period is 7 days
	dcMaxTTL          = time.Duration(dcMaxTTLSeconds * time.Second)
	dcMaxPubLen       = 1 << 24 // Bytes
	dcMaxSignatureLen = 1 << 16 // Bytes
)

var errNoDelegationUsage = errors.New("tls: certificate not authorized for delegation")
var extensionDelegatedCredential = []int{1, 3, 6, 1, 4, 1, 44363, 44}

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
		if extension.Id.Equal(extensionDelegatedCredential) {
			if extension.Critical {
				return false
			}
			return true
		}
	}

	return false
}

func isValidInCertVerify(expCertVerfAlgo SignatureScheme, certVerifyMsgAlgo SignatureScheme) bool {
	if expCertVerfAlgo == certVerifyMsgAlgo {
		return true
	}

	return false
}

// IsExpired returns true if the credential has expired. The end of the validity
// interval is defined as the delegator certificate's notBefore field ('start')
// plus ValidTime seconds. This function simply checks that the current time
// ('now') is before the end of the validity interval.
func (dc *DelegatedCredential) IsExpired(start, now time.Time) bool {
	end := start.Add(dc.Cred.validTime)
	return !now.Before(end)
}

// InvalidTTL returns true if the credential's validity period is longer than the
// maximum permitted. This is defined by the certificate's notBefore field
// ('start') plus the ValidTime, minus the current time ('now').
func (dc *DelegatedCredential) InvalidTTL(start, now time.Time) bool {
	return dc.Cred.validTime > (now.Sub(start) + dcMaxTTL).Round(time.Second)
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
	validTime time.Duration
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

// marshalPublicKeyInfo returns a DER encoded PublicKeyInfo
// from a Delegated Credential (as defined in the X.509 standard).
// The following key types are currently supported: *ecdsa.PublicKey
// and ed25519.PublicKey. Unsupported key types result in an error.
// rsa.PublicKey is not supported a defined by the draft.
func (cred *Credential) marshalPublicKeyInfo() ([]byte, error) {
	switch cred.expCertVerfAlgo {
	case ECDSAWithP256AndSHA256,
		ECDSAWithP384AndSHA384,
		ECDSAWithP521AndSHA512,
		Ed25519:
		serPub, err := x509.MarshalPKIXPublicKey(cred.PublicKey)
		if err != nil {
			return nil, err
		}

		return serPub, nil
	default:
		return nil, fmt.Errorf("tls: unsupported signature scheme: 0x%04x", cred.expCertVerfAlgo)
	}
}

// unmarshalPublicKeyInfo parses a DER encoded PublicKeyInfo from a Delegated
// Credential to a public key and its corresponding algorithm.
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
			return nil, 0, fmt.Errorf("tls: unsupported delgation key type: %s", curveName)
		}
	case ed25519.PublicKey:
		return pk, Ed25519, nil
	default:
		return nil, 0, fmt.Errorf("tls: unsupported delgation key type: %T", pk)
	}
}

// marshal encodes the credential struct of the Delegated Credential.
func (cred *Credential) marshal() ([]byte, error) {
	ser := make([]byte, 4)
	binary.BigEndian.PutUint32(ser, uint32(cred.validTime/time.Second))

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
		return nil, errors.New("tls: public key length exceeds 2^24-1 limit")
	}

	var b cryptobyte.Builder
	b.AddUint24(uint32(len(serPub)))
	serLen := b.BytesOrPanic()
	ser = append(ser, serLen[:]...)
	ser = append(ser, serPub...)

	return ser, nil
}

// unmarshalCredential decodes serialized bytes and returns a credential, if possible.
func unmarshalCredential(ser []byte) (*Credential, error) {
	if len(ser) < 9 {
		return nil, errors.New("tls: delegated credential is not valid")
	}

	validTime := time.Duration(binary.BigEndian.Uint32(ser)) * time.Second
	pubAlgo := SignatureScheme(binary.BigEndian.Uint16(ser[4:6]))

	s := cryptobyte.String(ser[6:9])
	var pubLen uint32
	s.ReadUint24(&pubLen)

	pubKey, err := x509.ParsePKIXPublicKey(ser[9:])
	if err != nil {
		return nil, err
	}

	if len(ser[9:]) != int(pubLen) {
		return nil, errors.New("tls: delegated credential is not valid")
	}

	return &Credential{validTime, pubAlgo, pubKey}, nil
}

// getCredentialLen returns the number of bytes comprising the serialized
// credential struct inside the Delegated Credential.
func getCredentialLen(ser []byte) (int, error) {
	if len(ser) < 9 {
		return 0, errors.New("tls: delegated credential is not valid")
	}

	// The validity time.
	ser = ser[4:]
	// The expCertVerfAlgo.
	ser = ser[2:]

	// The length of the Public Key.
	s := cryptobyte.String(ser[:3])
	var pubLen uint32
	s.ReadUint24(&pubLen)
	ser = ser[3:]
	if len(ser) < int(pubLen) {
		return 0, errors.New("tls: delegated credential is not valid")
	}

	return 9 + int(pubLen), nil
}

// getHash maps the SignatureScheme to its corresponding hash function.
func getHash(scheme SignatureScheme) crypto.Hash {
	switch scheme {
	case ECDSAWithP256AndSHA256:
		return crypto.SHA256
	case ECDSAWithP384AndSHA384:
		return crypto.SHA384
	case ECDSAWithP521AndSHA512:
		return crypto.SHA512
	case Ed25519:
		return crypto.SHA512
	default:
		return 0 //Unknown hash function
	}
}

// getCurve maps the SignatureScheme to its corresponding elliptic.Curve.
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

// prepareDelegationSignatureInput returns the message that the delegator is going to sign.
func prepareDelegationSignatureInput(hash crypto.Hash, cred *Credential, dCert []byte, algo SignatureScheme, peer string) ([]byte, error) {
	h := hash.New()

	header := make([]byte, 64, 128)
	for i := range header {
		header[i] = 0x20
	}
	h.Write(header)

	if peer == "server" {
		h.Write([]byte("TLS, server delegated credentials\x00"))
	} else if peer == "client" {
		h.Write([]byte("TLS, client delegated credentials\x00"))
	} else {
		return nil, errors.New("tls: invalid params for delegated credential")
	}

	h.Write(dCert)

	serCred, err := cred.marshal()
	if err != nil {
		return nil, err
	}
	h.Write(serCred)

	var serAlgo [2]byte
	binary.BigEndian.PutUint16(serAlgo[:], uint16(algo))
	h.Write(serAlgo[:])

	return h.Sum(nil), nil
}

// Extract the algorithm used to sign the DelegatedCredential from the end-entity (leaf) certificate
func getSigAlgo(cert *Certificate) (SignatureScheme, error) {
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
			return SignatureScheme(0x00), fmt.Errorf("using curve %s for %s is not supported", curveName, cert.Leaf.SignatureAlgorithm)
		}
	case ed25519.PublicKey:
		sigAlgo = Ed25519
	default:
		return SignatureScheme(0x00), fmt.Errorf("tls: unsupported algorithm for delegated credential")
	}

	return sigAlgo, nil
}

// NewDelegatedCredential creates a new delegated credential using 'cert' for
// delegation. It generates a public/private key pair for the provided signature
// algorithm ('scheme'), validity interval (defined by 'cert.Leaf.notBefore' and
// 'validTime'), and TLS version ('vers'), and signs it using 'cert.PrivateKey'.
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

	sigAlgo, err := getSigAlgo(cert)
	if err != nil {
		return nil, nil, err
	}

	// Generate the Delegated Credential Key Pair based on the provided scheme
	var privK crypto.PrivateKey
	var pubK crypto.PublicKey
	switch pubAlgo {
	case ECDSAWithP256AndSHA256,
		ECDSAWithP384AndSHA384,
		ECDSAWithP521AndSHA512:
		privK, err = ecdsa.GenerateKey(getCurve(pubAlgo), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pubK = privK.(*ecdsa.PrivateKey).Public()
	case Ed25519:
		pubK, privK, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("tls: unsupported algorithm for delegated credential: %T", pubAlgo)
	}

	// Prepare the credential for signing
	hash := getHash(sigAlgo)
	credential := &Credential{validTime, pubAlgo, pubK}
	values, err := prepareDelegationSignatureInput(hash, credential, cert.Leaf.Raw, sigAlgo, peer)
	if err != nil {
		return nil, nil, err
	}

	var sig []byte
	switch sk := cert.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		opts := crypto.SignerOpts(hash)
		sig, err = sk.Sign(rand.Reader, values, opts)
		if err != nil {
			return nil, nil, err
		}
	case ed25519.PrivateKey:
		opts := crypto.SignerOpts(hash)
		sig, err = sk.Sign(rand.Reader, values, opts)
		if err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("tls: unsupported key type for delegated credential")
	}

	return &DelegatedCredential{
		Cred:      credential,
		Algorithm: sigAlgo,
		Signature: sig,
	}, privK, nil
}

// Validate checks that the delegated credential is valid by checking that the
// signature is valid, that the credential hasn't expired, and that the TTL is
// valid. It also checks that certificate can be used for delegation.
func (dc *DelegatedCredential) Validate(cert *x509.Certificate, peer string, now time.Time, certVerifyMsg *certificateVerifyMsg) bool {
	if dc.IsExpired(cert.NotBefore, now) {
		return false
	}

	if dc.InvalidTTL(cert.NotBefore, now) {
		return false
	}

	if !isValidInCertVerify(dc.Cred.expCertVerfAlgo, certVerifyMsg.signatureAlgorithm) {
		return false
	}

	if !isValidForDelegation(cert) {
		return false
	}

	hash := getHash(dc.Algorithm)
	in, err := prepareDelegationSignatureInput(hash, dc.Cred, cert.Raw, dc.Algorithm, peer)
	if err != nil {
		return false
	}

	switch dc.Algorithm {
	case ECDSAWithP256AndSHA256,
		ECDSAWithP384AndSHA384,
		ECDSAWithP521AndSHA512:
		pk, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return false
		}

		return ecdsa.VerifyASN1(pk, in, dc.Signature)
	case Ed25519:
		pk, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return false
		}

		return ed25519.Verify(pk, in, dc.Signature)
	default:
		return false
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
	sig := make([]byte, serSignatureLen)
	copy(sig, ser[:serSignatureLen])

	return &DelegatedCredential{
		Cred:      credential,
		Algorithm: algo,
		Signature: sig,
	}, nil
}
