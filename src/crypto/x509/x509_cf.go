package x509

import (
	circlPki "circl/pki"
	circlSign "circl/sign"

	"circl/sign/ed448"
	"circl/sign/eddilithium3"
	"circl/sign/eddilithium4"

	"crypto"
	"encoding/asn1"
)

// To add a signature scheme from Circl
//
//   1. make sure it implements CertificateScheme,
//	 2. add SignatureAlgorithm and PublicKeyAlgorithm constants in x509.go
//   3. add row in circlSchemes below
//   4. update publicKeyAlgoName in x509.go

var circlSchemes = [...]struct {
	sga    SignatureAlgorithm
	alg    PublicKeyAlgorithm
	scheme circlSign.Scheme
}{
	{PureEd448, Ed448, ed448.Scheme()},
	{PureEdDilithium3, EdDilithium3, eddilithium3.Scheme()},
	{PureEdDilithium4, EdDilithium4, eddilithium4.Scheme()},
}

func CirclSchemeByPublicKeyAlgorithm(alg PublicKeyAlgorithm) circlSign.Scheme {
	for _, cs := range circlSchemes {
		if cs.alg == alg {
			return cs.scheme
		}
	}
	return nil
}

func SignatureAlgorithmByCirclScheme(scheme circlSign.Scheme) SignatureAlgorithm {
	for _, cs := range circlSchemes {
		if cs.scheme == scheme {
			return cs.sga
		}
	}
	return UnknownSignatureAlgorithm
}

func PublicKeyAlgorithmByCirclScheme(scheme circlSign.Scheme) PublicKeyAlgorithm {
	for _, cs := range circlSchemes {
		if cs.scheme == scheme {
			return cs.alg
		}
	}
	return UnknownPublicKeyAlgorithm
}

func init() {
	for _, cs := range circlSchemes {
		signatureAlgorithmDetails = append(signatureAlgorithmDetails,
			struct {
				algo       SignatureAlgorithm
				name       string
				oid        asn1.ObjectIdentifier
				pubKeyAlgo PublicKeyAlgorithm
				hash       crypto.Hash
			}{
				cs.sga,
				cs.scheme.Name(),
				cs.scheme.(circlPki.CertificateScheme).Oid(),
				cs.alg,
				crypto.Hash(0),
			},
		)
	}
}
