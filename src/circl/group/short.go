package group

import (
	"crypto"
	"crypto/elliptic"
	_ "crypto/sha256" // to link libraries
	_ "crypto/sha512" // to link libraries
	"crypto/subtle"
	"fmt"
	"io"
	"math/big"
)

type wG struct {
	elliptic.Curve
}

func (g wG) String() string      { return g.Params().Name }
func (g wG) NewElement() Element { return g.Identity() }
func (g wG) NewScalar() Scalar   { return &wScl{g, nil} }
func (g wG) Identity() Element   { return &wElt{g, new(big.Int), new(big.Int)} }
func (g wG) Generator() Element  { return &wElt{g, g.Params().Gx, g.Params().Gy} }
func (g wG) Order() Scalar       { s := &wScl{g, nil}; s.fromBig(g.Params().N); return s }
func (g wG) RandomElement(rd io.Reader) Element {
	b := make([]byte, (g.Params().BitSize+7)/8)
	_, _ = io.ReadFull(rd, b)
	return g.HashToElement(b, nil)
}
func (g wG) RandomScalar(rd io.Reader) Scalar {
	b := make([]byte, (g.Params().BitSize+7)/8)
	_, _ = io.ReadFull(rd, b)
	return g.HashToScalar(b, nil)
}
func (g wG) getHasher(dst []byte) wHash {
	var Z, C2 big.Int
	var h crypto.Hash
	var L uint
	switch g.Params().BitSize {
	case 256:
		Z.SetInt64(-10)
		C2.SetString("0x78bc71a02d89ec07214623f6d0f955072c7cc05604a5a6e23ffbf67115fa5301", 0)
		h = crypto.SHA256
		L = 48
	case 384:
		Z.SetInt64(-12)
		C2.SetString("0x19877cc1041b7555743c0ae2e3a3e61fb2aaa2e0e87ea557a563d8b598a0940d0a697a9e0b9e92cfaa314f583c9d066", 0)
		h = crypto.SHA512
		L = 72
	case 521:
		Z.SetInt64(-4)
		C2.SetInt64(8)
		h = crypto.SHA512
		L = 98
	default:
		panic("curve not supported")
	}
	return wHash{
		sswu3mod4{g, &Z, &C2},
		NewExpanderMD(h, g.Params().P, L, dst),
		NewExpanderMD(h, g.Params().N, L, dst),
	}
}
func (g wG) cvtElt(e Element) *wElt {
	ee, ok := e.(*wElt)
	if !ok || g.Params().BitSize != ee.Params().BitSize {
		panic(ErrType)
	}
	return ee
}
func (g wG) cvtScl(s Scalar) *wScl {
	ss, ok := s.(*wScl)
	if !ok || g.Params().BitSize != ss.Params().BitSize {
		panic(ErrType)
	}
	return ss
}

type wElt struct {
	wG
	x, y *big.Int
}

func (e *wElt) String() string   { return fmt.Sprintf("x: 0x%v\ny: 0x%v", e.x.Text(16), e.y.Text(16)) }
func (e *wElt) IsIdentity() bool { return e.x.Sign() == 0 && e.y.Sign() == 0 }
func (e *wElt) IsEqual(o Element) bool {
	oo := e.cvtElt(o)
	return e.x.Cmp(oo.x) == 0 && e.y.Cmp(oo.y) == 0
}
func (e *wElt) Add(a, b Element) Element {
	aa, bb := e.cvtElt(a), e.cvtElt(b)
	e.x, e.y = e.Curve.Add(aa.x, aa.y, bb.x, bb.y)
	return e
}
func (e *wElt) Dbl(a Element) Element {
	aa := e.cvtElt(a)
	e.x, e.y = e.Curve.Double(aa.x, aa.y)
	return e
}
func (e *wElt) Neg(a Element) Element {
	aa := e.cvtElt(a)
	e.x.Set(aa.x)
	e.y.Neg(aa.y)
	return e
}
func (e *wElt) Mul(a Element, s Scalar) Element {
	aa, ss := e.cvtElt(a), e.cvtScl(s)
	e.x, e.y = e.ScalarMult(aa.x, aa.y, ss.k)
	return e
}
func (e *wElt) MulGen(s Scalar) Element {
	ss := e.cvtScl(s)
	e.x, e.y = e.ScalarBaseMult(ss.k)
	return e
}
func (e *wElt) MarshalBinary() ([]byte, error) {
	if e.IsIdentity() {
		return []byte{0x0}, nil
	}
	return elliptic.Marshal(e.wG, e.x, e.y), nil
}
func (e *wElt) MarshalBinaryCompress() ([]byte, error) {
	if e.IsIdentity() {
		return []byte{0x0}, nil
	}
	l := (e.Params().BitSize + 7) / 8
	data := make([]byte, 1+l)
	bytes := e.x.Bytes()
	copy(data[1+l-len(bytes):], bytes)
	data[0] = 0x02 | byte(e.y.Bit(0))
	return data, nil
}
func (e *wElt) UnmarshalBinary(b []byte) error {
	byteLen := (e.Params().BitSize + 7) / 8
	l := len(b)
	switch {
	case l == 1 && b[0] == 0x00: // point at infinity
		e.x.SetInt64(0)
		e.y.SetInt64(0)
	case l == 1+byteLen && (b[0] == 0x02 || b[0] == 0x03): // compressed
		p := e.wG.Params().P
		x := new(big.Int).SetBytes(b[1:])
		y := new(big.Int)
		y.Mul(x, x)               // x^2
		y.Mul(y, x)               // x^3
		y.Sub(y, x)               // x^3-x
		y.Sub(y, x)               // x^3-2x
		y.Sub(y, x)               // x^3-3x
		y.Add(y, e.wG.Params().B) // x^3-3x+b
		y.Mod(y, p)               //
		qr := y.ModSqrt(y, p)     // sqrt(x^3-3x+b)
		if qr == nil {
			return ErrUnmarshal
		}
		if byte(y.Bit(0)) != (b[0] & 1) {
			y.Neg(y).Mod(y, p)
		}
		e.x, e.y = x, y
	case l == 1+2*byteLen && b[0] == 0x04: // uncompressed
		x, y := elliptic.Unmarshal(e.wG, b)
		if x == nil {
			return ErrUnmarshal
		}
		e.x, e.y = x, y
	default:
		return ErrUnmarshal
	}
	return nil
}

type wScl struct {
	wG
	k []byte
}

func (s *wScl) String() string { return fmt.Sprintf("0x%x", s.k) }
func (s *wScl) IsEqual(a Scalar) bool {
	aa := s.cvtScl(a)
	return subtle.ConstantTimeCompare(s.k, aa.k) == 1
}
func (s *wScl) fromBig(b *big.Int) {
	_ = s.UnmarshalBinary(b.Bytes())
}
func (s *wScl) Add(a, b Scalar) Scalar {
	aa, bb := s.cvtScl(a), s.cvtScl(b)
	r := new(big.Int)
	r.SetBytes(aa.k).Add(r, new(big.Int).SetBytes(bb.k)).Mod(r, s.Params().N)
	s.fromBig(r)
	return s
}
func (s *wScl) Sub(a, b Scalar) Scalar {
	aa, bb := s.cvtScl(a), s.cvtScl(b)
	r := new(big.Int)
	r.SetBytes(aa.k).Sub(r, new(big.Int).SetBytes(bb.k)).Mod(r, s.Params().N)
	s.fromBig(r)
	return s
}
func (s *wScl) Mul(a, b Scalar) Scalar {
	aa, bb := s.cvtScl(a), s.cvtScl(b)
	r := new(big.Int)
	r.SetBytes(aa.k).Mul(r, new(big.Int).SetBytes(bb.k)).Mod(r, s.Params().N)
	s.fromBig(r)
	return s
}
func (s *wScl) Neg(a Scalar) Scalar {
	aa := s.cvtScl(a)
	r := new(big.Int)
	r.SetBytes(aa.k).Neg(r).Mod(r, s.Params().N)
	s.fromBig(r)
	return s
}
func (s *wScl) Inv(a Scalar) Scalar {
	aa := s.cvtScl(a)
	r := new(big.Int)
	r.SetBytes(aa.k).ModInverse(r, s.Params().N)
	s.fromBig(r)
	return s
}
func (s *wScl) MarshalBinary() (data []byte, err error) {
	data = make([]byte, (s.Params().BitSize+7)/8)
	copy(data, s.k)
	return data, nil
}
func (s *wScl) UnmarshalBinary(b []byte) error {
	l := (s.Params().BitSize + 7) / 8
	s.k = make([]byte, l)
	copy(s.k[l-len(b):l], b)
	return nil
}

type wHash struct {
	sswu3mod4
	elt FieldHasher
	scl FieldHasher
}

func (g wG) HashToElement(b, dst []byte) Element {
	var u [2]big.Int
	h := g.getHasher(dst)
	h.elt.HashToField(u[:], b)
	Q0 := h.Map(&u[0])
	Q1 := h.Map(&u[1])
	return Q0.Add(Q0, Q1)
}

func (g wG) HashToScalar(b, dst []byte) Scalar {
	var u [1]big.Int
	h := g.getHasher(dst)
	h.scl.HashToField(u[:], b)
	s := g.NewScalar().(*wScl)
	s.fromBig(&u[0])
	return s
}

type sswu3mod4 struct {
	wG
	Z  *big.Int
	C2 *big.Int // c2 = sqrt(-Z^3)
}

func (s sswu3mod4) Map(u *big.Int) Element {
	tv1 := new(big.Int)
	tv2 := new(big.Int)
	tv3 := new(big.Int)
	tv4 := new(big.Int)
	xn := new(big.Int)
	xd := new(big.Int)
	x1n := new(big.Int)
	x2n := new(big.Int)
	gx1 := new(big.Int)
	gxd := new(big.Int)
	y1 := new(big.Int)
	y2 := new(big.Int)
	x := new(big.Int)
	y := new(big.Int)

	A := big.NewInt(-3)
	B := s.Params().B
	p := s.Params().P
	c1 := new(big.Int)
	c1.Sub(p, big.NewInt(3)).Rsh(c1, 2) // 1.  c1 = (q - 3) / 4

	add := func(c, a, b *big.Int) { c.Add(a, b).Mod(c, p) }
	mul := func(c, a, b *big.Int) { c.Mul(a, b).Mod(c, p) }
	sqr := func(c, a *big.Int) { c.Mul(a, a).Mod(c, p) }
	exp := func(c, a, b *big.Int) { c.Exp(a, b, p) }
	sgn := func(a *big.Int) uint { a.Mod(a, p); return a.Bit(0) }
	cmv := func(c, a, b *big.Int, k bool) {
		if k {
			c.Set(b)
		} else {
			c.Set(a)
		}
	}

	sqr(tv1, u)                 // 1.  tv1 = u^2
	mul(tv3, s.Z, tv1)          // 2.  tv3 = Z * tv1
	sqr(tv2, tv3)               // 3.  tv2 = tv3^2
	add(xd, tv2, tv3)           // 4.   xd = tv2 + tv3
	add(x1n, xd, big.NewInt(1)) // 5.  x1n = xd + 1
	mul(x1n, x1n, B)            // 6.  x1n = x1n * B
	tv4.Neg(A)                  //
	mul(xd, tv4, xd)            // 7.   xd = -A * xd
	e1 := xd.Sign() == 0        // 8.   e1 = xd == 0
	mul(tv4, s.Z, A)            //
	cmv(xd, xd, tv4, e1)        // 9.   xd = CMOV(xd, Z * A, e1)
	sqr(tv2, xd)                // 10. tv2 = xd^2
	mul(gxd, tv2, xd)           // 11. gxd = tv2 * xd
	mul(tv2, A, tv2)            // 12. tv2 = A * tv2
	sqr(gx1, x1n)               // 13. gx1 = x1n^2
	add(gx1, gx1, tv2)          // 14. gx1 = gx1 + tv2
	mul(gx1, gx1, x1n)          // 15. gx1 = gx1 * x1n
	mul(tv2, B, gxd)            // 16. tv2 = B * gxd
	add(gx1, gx1, tv2)          // 17. gx1 = gx1 + tv2
	sqr(tv4, gxd)               // 18. tv4 = gxd^2
	mul(tv2, gx1, gxd)          // 19. tv2 = gx1 * gxd
	mul(tv4, tv4, tv2)          // 20. tv4 = tv4 * tv2
	exp(y1, tv4, c1)            // 21.  y1 = tv4^c1
	mul(y1, y1, tv2)            // 22.  y1 = y1 * tv2
	mul(x2n, tv3, x1n)          // 23. x2n = tv3 * x1n
	mul(y2, y1, s.C2)           // 24.  y2 = y1 * c2
	mul(y2, y2, tv1)            // 25.  y2 = y2 * tv1
	mul(y2, y2, u)              // 26.  y2 = y2 * u
	sqr(tv2, y1)                // 27. tv2 = y1^2
	mul(tv2, tv2, gxd)          // 28. tv2 = tv2 * gxd
	e2 := tv2.Cmp(gx1) == 0     // 29.  e2 = tv2 == gx1
	cmv(xn, x2n, x1n, e2)       // 30.  xn = CMOV(x2n, x1n, e2)
	cmv(y, y2, y1, e2)          // 31.   y = CMOV(y2, y1, e2)
	e3 := sgn(u) == sgn(y)      // 32.  e3 = sgn0(u) == sgn0(y)
	tv1.Neg(y)                  //
	cmv(y, tv1, y, e3)          // 33.   y = CMOV(-y, y, e3)
	tv1.ModInverse(xd, p)       //
	mul(x, xn, tv1)             // 34. return (xn, xd, y, 1)
	y.Mod(y, p)
	return &wElt{s.wG, x, y}
}
