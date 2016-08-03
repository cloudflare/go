package chacha20poly1305

import (
	"crypto/internal/bytesop"
	"crypto/subtle"
	"encoding/binary"
	"unsafe"
)

// MACSize is the length of the result of (*MAC).Finish.
const MACSize = 16

// A MAC is a Poly1305-based message authentication code with a given key.
type MAC struct {
	a0, a1, a2, a3, a4 uint64
	r0, r1, r2, r3     uint64
	s0, s1, s2, s3     uint64
}

func writeU32(in uint64, out []byte) {
	/* Assumption : len(out) >= 8 */
	for i := 0; i < 4; i++ {
		out[i] = byte(in)
		in >>= 8
	}
}

// NewMAC returns a Poly1305 MAC with the given key, which must be 32 bytes long.
func NewMAC(key []byte) (*MAC, error) {
	k := len(key)
	if k != 32 {
		return nil, KeySizeError(k)
	}

	if bytesop.SupportsUnaligned {
		ptr := (*[8]uint32)(unsafe.Pointer(&key[0]))

		return &MAC{0, 0, 0, 0, 0,
				uint64(ptr[0]) & 0x0FFFFFFF,
				uint64(ptr[1]) & 0x0FFFFFFC,
				uint64(ptr[2]) & 0x0FFFFFFC,
				uint64(ptr[3]) & 0x0FFFFFFC,
				uint64(ptr[4]),
				uint64(ptr[5]),
				uint64(ptr[6]),
				uint64(ptr[7])},
			nil
	}

	return &MAC{0, 0, 0, 0, 0,
			uint64(binary.LittleEndian.Uint32(key[0:4])) & 0x0FFFFFFF,
			uint64(binary.LittleEndian.Uint32(key[4:8])) & 0x0FFFFFFC,
			uint64(binary.LittleEndian.Uint32(key[8:12])) & 0x0FFFFFFC,
			uint64(binary.LittleEndian.Uint32(key[12:16])) & 0x0FFFFFFC,
			uint64(binary.LittleEndian.Uint32(key[16:20])),
			uint64(binary.LittleEndian.Uint32(key[20:24])),
			uint64(binary.LittleEndian.Uint32(key[24:28])),
			uint64(binary.LittleEndian.Uint32(key[28:32]))},
		nil
}

// Update adds more data to the MAC.
//
// TODO: document the behavior of multiple calls, in particular when they are
// not 16-byte aligned.
func (p *MAC) Update(in []byte) {
	a0 := p.a0
	a1 := p.a1
	a2 := p.a2
	a3 := p.a3
	a4 := p.a4

	/* ri has at most 28 bits */
	r0 := p.r0
	r1 := p.r1
	r2 := p.r2
	r3 := p.r3

loop:
	for len(in) >= 16 {
		/* ai will have at most 33 bits */
		if bytesop.SupportsUnaligned {
			ptr := (*[4]uint32)(unsafe.Pointer(&in[0]))
			a0 += uint64(ptr[0])
			a1 += uint64(ptr[1])
			a2 += uint64(ptr[2])
			a3 += uint64(ptr[3])
			a4 += 1
		} else {
			a0 += uint64(binary.LittleEndian.Uint32(in[0:]))
			a1 += uint64(binary.LittleEndian.Uint32(in[4:]))
			a2 += uint64(binary.LittleEndian.Uint32(in[8:]))
			a3 += uint64(binary.LittleEndian.Uint32(in[12:]))
			a4 += 1
		}

		in = in[16:]

		/* any ai * rj will have at most 28 + 33 bits = 61 bits, it is safe to sum them all */
		t0 := a0 * r0
		t1 := a1*r0 + a0*r1
		t2 := a2*r0 + a1*r1 + a0*r2
		t3 := a3*r0 + a2*r1 + a1*r2 + a0*r3
		t4 := a4*r0 + a3*r1 + a2*r2 + a1*r3 + t3>>32 /* t3 might overflow on the next addition, so we fix it */
		t5 := a4*r1 + a3*r2 + a2*r3
		t6 := a4*r2 + a3*r3
		t7 := a4 * r3

		t3 &= 0xffffffff
		a4 = t4 & 0x3
		t4 &= 0xfffffffffffffffc

		a0 = t0 + t4 + t4>>2 + t5&3<<30
		a1 = t1 + t5 + t5>>2 + t6&3<<30 + a0>>32
		a2 = t2 + t6 + t6>>2 + t7&3<<30 + a1>>32
		a3 = t3 + t7 + t7>>2 + a2>>32
		a4 += a3 >> 32

		a0 &= 0xffffffff
		a1 &= 0xffffffff
		a2 &= 0xffffffff
		a3 &= 0xffffffff
	}

	if len(in) > 0 {
		var tmp [16]byte
		copy(tmp[:], in)
		tmp[len(in)] = 1
		a4 -= 1
		in = tmp[:]
		goto loop
	}

	p.a0 = a0
	p.a1 = a1
	p.a2 = a2
	p.a3 = a3
	p.a4 = a4
}

// Finish appends the MAC to b and returns the resulting slice.
//
// TODO: document how the state is modified. And if it's unnecessary, make it reusable.
func (p *MAC) Finish(b []byte) []byte {
	a0 := uint64(p.a0)
	a1 := uint64(p.a1)
	a2 := uint64(p.a2)
	a3 := uint64(p.a3)
	a4 := uint64(p.a4)

	/* Subtract p1305 */
	a0 -= 0xFFFFFFFB
	a1 -= 0xFFFFFFFF
	a2 -= 0xFFFFFFFF
	a3 -= 0xFFFFFFFF
	a4 -= 3
	/* Propagate borrow bit - we get borrow when there was borrow and the current result is 0 */
	borrow := a0 >> 32
	borrow2 := a1>>32 | (borrow & (0x100000000 - uint64(subtle.ConstantTimeEq(int32(a1), 0))))
	a1 += borrow
	borrow = a2>>32 | (borrow2 & (0x100000000 - uint64(subtle.ConstantTimeEq(int32(a2), 0))))
	a2 += borrow
	borrow2 = a3>>32 | (borrow & (0x100000000 - uint64(subtle.ConstantTimeEq(int32(a3), 0))))
	a3 += borrow
	borrow = a4>>32 | (borrow2 & (0x100000000 - uint64(subtle.ConstantTimeEq(int32(a4), 0))))

	a0 &= 0xffffffff
	a1 &= 0xffffffff
	a2 &= 0xffffffff
	a3 &= 0xffffffff

	a0 = a0 & ^borrow + p.a0&borrow
	a1 = a1 & ^borrow + p.a1&borrow
	a2 = a2 & ^borrow + p.a2&borrow
	a3 = a3 & ^borrow + p.a3&borrow

	a0 += p.s0
	a1 += p.s1 + a0>>32
	a2 += p.s2 + a1>>32
	a3 += p.s3 + a2>>32

	p.a0 = a0 & 0xffffffff
	p.a1 = a1 & 0xffffffff
	p.a2 = a2 & 0xffffffff
	p.a3 = a3 & 0xffffffff

	res, dst := bytesop.SliceForAppend(b, 16)
	writeU32(p.a0, dst[0:4])
	writeU32(p.a1, dst[4:8])
	writeU32(p.a2, dst[8:12])
	writeU32(p.a3, dst[12:16])
	return res
}
