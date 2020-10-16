// Code generated from params.templ.go. DO NOT EDIT.

package internal

import (
	"circl/pke/kyber/internal/common"
)

const (
	K             = 4
	DU            = 11
	DV            = 5
	PublicKeySize = 32 + K*common.PolySize

	PrivateKeySize = K * common.PolySize

	PlaintextSize  = common.PlaintextSize
	SeedSize       = 32
	CiphertextSize = 1568
)
