// Copyright 2021 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package tls

import (
	circlPki "circl/pki"
	circlSign "circl/sign"

	"circl/sign/eddilithium3"
)

// To add a signature scheme from Circl
//
//   1. make sure it implements TLSScheme and CertificateScheme,
//   2. follow the instructions in crypto/x509/x509_cf.go
//   3. add a signature<NameOfAlg> to the iota in common.go
//   4. add row in the circlSchemes lists below

var circlSchemes = [...]struct {
	sigType uint8
	scheme  circlSign.Scheme
}{
	{signatureEdDilithium3, eddilithium3.Scheme()},
}

func circlSchemeBySigType(sigType uint8) circlSign.Scheme {
	for _, cs := range circlSchemes {
		if cs.sigType == sigType {
			return cs.scheme
		}
	}
	return nil
}

func sigTypeByCirclScheme(scheme circlSign.Scheme) uint8 {
	for _, cs := range circlSchemes {
		if cs.scheme == scheme {
			return cs.sigType
		}
	}
	return 0
}

func init() {
	if true {
		// FIXME(pwu): decide how to enable these signature algorithms
		// without changing the ClientHello testdata files. Perhaps we
		// could expose a new tls.Config parameter for clients?
		return
	}
	// Note: this will extend the signature_algorithms TLS extension in the
	// Client Hello which requires changes to various testdata files.
	for _, cs := range circlSchemes {
		supportedSignatureAlgorithms = append(supportedSignatureAlgorithms,
			SignatureScheme(cs.scheme.(circlPki.TLSScheme).TLSIdentifier()))
	}
}
