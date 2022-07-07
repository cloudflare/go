// Code generated by go generate; DO NOT EDIT.
// This file was generated by robots.

package p434

import (
	. "circl/dh/sidh/internal/common"
	crand "crypto/rand"
)

// -----------------------------------------------------------------------------
// Functions for traversing isogeny trees acoording to strategy. Key type 'A' is
//

// Traverses isogeny tree in order to compute xR, xP, xQ and xQmP needed
// for public key generation.
func traverseTreePublicKeyA(curve *ProjectiveCurveParameters, xR, phiP, phiQ, phiR *ProjectivePoint) {
	points := make([]ProjectivePoint, 0, 8)
	indices := make([]int, 0, 8)
	var i, sIdx int
	var phi isogeny4

	cparam := CalcCurveParamsEquiv4(curve)
	strat := params.A.IsogenyStrategy
	stratSz := len(strat)

	for j := 1; j <= stratSz; j++ {
		for i <= stratSz-j {
			points = append(points, *xR)
			indices = append(indices, i)

			k := strat[sIdx]
			sIdx++
			Pow2k(xR, &cparam, 2*k)
			i += int(k)
		}
		cparam = phi.GenerateCurve(xR)

		for k := 0; k < len(points); k++ {
			phi.EvaluatePoint(&points[k])
		}
		phi.EvaluatePoint(phiP)
		phi.EvaluatePoint(phiQ)
		phi.EvaluatePoint(phiR)

		// pop xR from points
		*xR, points = points[len(points)-1], points[:len(points)-1]
		i, indices = int(indices[len(indices)-1]), indices[:len(indices)-1]
	}
}

// Traverses isogeny tree in order to compute xR needed
// for public key generation.
func traverseTreeSharedKeyA(curve *ProjectiveCurveParameters, xR *ProjectivePoint) {
	points := make([]ProjectivePoint, 0, 8)
	indices := make([]int, 0, 8)
	var i, sIdx int
	var phi isogeny4

	cparam := CalcCurveParamsEquiv4(curve)
	strat := params.A.IsogenyStrategy
	stratSz := len(strat)

	for j := 1; j <= stratSz; j++ {
		for i <= stratSz-j {
			points = append(points, *xR)
			indices = append(indices, i)

			k := strat[sIdx]
			sIdx++
			Pow2k(xR, &cparam, 2*k)
			i += int(k)
		}
		cparam = phi.GenerateCurve(xR)

		for k := 0; k < len(points); k++ {
			phi.EvaluatePoint(&points[k])
		}

		// pop xR from points
		*xR, points = points[len(points)-1], points[:len(points)-1]
		i, indices = int(indices[len(indices)-1]), indices[:len(indices)-1]
	}
}

// Traverses isogeny tree in order to compute xR, xP, xQ and xQmP needed
// for public key generation.
func traverseTreePublicKeyB(curve *ProjectiveCurveParameters, xR, phiP, phiQ, phiR *ProjectivePoint) {
	points := make([]ProjectivePoint, 0, 8)
	indices := make([]int, 0, 8)
	var i, sIdx int
	var phi isogeny3

	cparam := CalcCurveParamsEquiv3(curve)
	strat := params.B.IsogenyStrategy
	stratSz := len(strat)

	for j := 1; j <= stratSz; j++ {
		for i <= stratSz-j {
			points = append(points, *xR)
			indices = append(indices, i)

			k := strat[sIdx]
			sIdx++
			Pow3k(xR, &cparam, k)
			i += int(k)
		}

		cparam = phi.GenerateCurve(xR)
		for k := 0; k < len(points); k++ {
			phi.EvaluatePoint(&points[k])
		}

		phi.EvaluatePoint(phiP)
		phi.EvaluatePoint(phiQ)
		phi.EvaluatePoint(phiR)

		// pop xR from points
		*xR, points = points[len(points)-1], points[:len(points)-1]
		i, indices = int(indices[len(indices)-1]), indices[:len(indices)-1]
	}
}

// Traverses isogeny tree in order to compute xR, xP, xQ and xQmP needed
// for public key generation.
func traverseTreeSharedKeyB(curve *ProjectiveCurveParameters, xR *ProjectivePoint) {
	points := make([]ProjectivePoint, 0, 8)
	indices := make([]int, 0, 8)
	var i, sIdx int
	var phi isogeny3

	cparam := CalcCurveParamsEquiv3(curve)
	strat := params.B.IsogenyStrategy
	stratSz := len(strat)

	for j := 1; j <= stratSz; j++ {
		for i <= stratSz-j {
			points = append(points, *xR)
			indices = append(indices, i)

			k := strat[sIdx]
			sIdx++
			Pow3k(xR, &cparam, k)
			i += int(k)
		}

		cparam = phi.GenerateCurve(xR)
		for k := 0; k < len(points); k++ {
			phi.EvaluatePoint(&points[k])
		}

		// pop xR from points
		*xR, points = points[len(points)-1], points[:len(points)-1]
		i, indices = int(indices[len(indices)-1]), indices[:len(indices)-1]
	}
}

// Generate a public key in the 2-torsion group. Public key is a set
// of three x-coordinates: xP,xQ,x(P-Q), where P,Q are points on E_a(Fp2)
func PublicKeyGenA(pub3Pt *[3]Fp2, prvBytes []byte) {
	var xPA, xQA, xRA ProjectivePoint
	var xPB, xQB, xRB, xR ProjectivePoint
	var invZP, invZQ, invZR Fp2
	var phi isogeny4

	// Load points for A
	xPA = ProjectivePoint{X: params.A.AffineP, Z: params.OneFp2}
	xQA = ProjectivePoint{X: params.A.AffineQ, Z: params.OneFp2}
	xRA = ProjectivePoint{X: params.A.AffineR, Z: params.OneFp2}

	// Load points for B
	xRB = ProjectivePoint{X: params.B.AffineR, Z: params.OneFp2}
	xQB = ProjectivePoint{X: params.B.AffineQ, Z: params.OneFp2}
	xPB = ProjectivePoint{X: params.B.AffineP, Z: params.OneFp2}

	// Find isogeny kernel
	xR = ScalarMul3Pt(&params.InitCurve, &xPA, &xQA, &xRA, params.A.SecretBitLen, prvBytes)
	traverseTreePublicKeyA(&params.InitCurve, &xR, &xPB, &xQB, &xRB)

	// Secret isogeny
	phi.GenerateCurve(&xR)
	xPA = xPB
	xQA = xQB
	xRA = xRB
	phi.EvaluatePoint(&xPA)
	phi.EvaluatePoint(&xQA)
	phi.EvaluatePoint(&xRA)
	Fp2Batch3Inv(&xPA.Z, &xQA.Z, &xRA.Z, &invZP, &invZQ, &invZR)

	mul(&pub3Pt[0], &xPA.X, &invZP)
	mul(&pub3Pt[1], &xQA.X, &invZQ)
	mul(&pub3Pt[2], &xRA.X, &invZR)
}

// Generate a public key in the 2-torsion group. Public key is a set
// of three x-coordinates: xP,xQ,x(P-Q), where P,Q are points on E_a(Fp2)
func PublicKeyGenB(pub3Pt *[3]Fp2, prvBytes []byte) {
	var xPB, xQB, xRB, xR ProjectivePoint
	var xPA, xQA, xRA ProjectivePoint
	var invZP, invZQ, invZR Fp2
	var phi isogeny3

	// Load points for B
	xRB = ProjectivePoint{X: params.B.AffineR, Z: params.OneFp2}
	xQB = ProjectivePoint{X: params.B.AffineQ, Z: params.OneFp2}
	xPB = ProjectivePoint{X: params.B.AffineP, Z: params.OneFp2}

	// Load points for A
	xPA = ProjectivePoint{X: params.A.AffineP, Z: params.OneFp2}
	xQA = ProjectivePoint{X: params.A.AffineQ, Z: params.OneFp2}
	xRA = ProjectivePoint{X: params.A.AffineR, Z: params.OneFp2}

	// Find isogeny kernel
	xR = ScalarMul3Pt(&params.InitCurve, &xPB, &xQB, &xRB, params.B.SecretBitLen, prvBytes)
	traverseTreePublicKeyB(&params.InitCurve, &xR, &xPA, &xQA, &xRA)

	phi.GenerateCurve(&xR)
	xPB = xPA
	xQB = xQA
	xRB = xRA
	phi.EvaluatePoint(&xPB)
	phi.EvaluatePoint(&xQB)
	phi.EvaluatePoint(&xRB)
	Fp2Batch3Inv(&xPB.Z, &xQB.Z, &xRB.Z, &invZP, &invZQ, &invZR)

	mul(&pub3Pt[0], &xPB.X, &invZP)
	mul(&pub3Pt[1], &xQB.X, &invZQ)
	mul(&pub3Pt[2], &xRB.X, &invZR)
}

// -----------------------------------------------------------------------------
// Key agreement functions
//

// Establishing shared keys in in 2-torsion group
func DeriveSecretA(ss, prv []byte, pub3Pt *[3]Fp2) {
	var xP, xQ, xQmP ProjectivePoint
	var xR ProjectivePoint
	var phi isogeny4
	var jInv Fp2

	// Recover curve coefficients
	cparam := params.InitCurve
	RecoverCoordinateA(&cparam, &pub3Pt[0], &pub3Pt[1], &pub3Pt[2])

	// Find kernel of the morphism
	xP = ProjectivePoint{X: pub3Pt[0], Z: params.OneFp2}
	xQ = ProjectivePoint{X: pub3Pt[1], Z: params.OneFp2}
	xQmP = ProjectivePoint{X: pub3Pt[2], Z: params.OneFp2}
	xR = ScalarMul3Pt(&cparam, &xP, &xQ, &xQmP, params.A.SecretBitLen, prv)

	// Traverse isogeny tree
	traverseTreeSharedKeyA(&cparam, &xR)

	// Calculate j-invariant on isogeneus curve
	c := phi.GenerateCurve(&xR)
	RecoverCurveCoefficients4(&cparam, &c)
	Jinvariant(&cparam, &jInv)
	FromMontgomery(&jInv, &jInv)
	Fp2ToBytes(ss, &jInv, params.Bytelen)
}

// Establishing shared keys in in 3-torsion group
func DeriveSecretB(ss, prv []byte, pub3Pt *[3]Fp2) {
	var xP, xQ, xQmP ProjectivePoint
	var xR ProjectivePoint
	var phi isogeny3
	var jInv Fp2

	// Recover curve coefficients
	cparam := params.InitCurve
	RecoverCoordinateA(&cparam, &pub3Pt[0], &pub3Pt[1], &pub3Pt[2])

	// Find kernel of the morphism
	xP = ProjectivePoint{X: pub3Pt[0], Z: params.OneFp2}
	xQ = ProjectivePoint{X: pub3Pt[1], Z: params.OneFp2}
	xQmP = ProjectivePoint{X: pub3Pt[2], Z: params.OneFp2}

	//PUBLIC KEY VALIDATION
	if err := PublicKeyValidation(&cparam, &xP, &xQ, &xQmP, params.B.SecretBitLen); err != nil {
		_, err_read := crand.Read(ss)
		if err_read != nil {
			panic("core: failed to generate random ss when public key verification fails")
		}
		return
	}

	xR = ScalarMul3Pt(&cparam, &xP, &xQ, &xQmP, params.B.SecretBitLen, prv)

	// Traverse isogeny tree
	traverseTreeSharedKeyB(&cparam, &xR)

	// Calculate j-invariant on isogeneus curve
	c := phi.GenerateCurve(&xR)
	RecoverCurveCoefficients3(&cparam, &c)
	Jinvariant(&cparam, &jInv)
	FromMontgomery(&jInv, &jInv)
	Fp2ToBytes(ss, &jInv, params.Bytelen)

}
