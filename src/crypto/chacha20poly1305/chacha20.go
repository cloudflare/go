package chacha20poly1305

import (
	"crypto/cipher"
	"strconv"
	"unsafe"
)

type chacha20Cipher struct {
	state [16]uint32
	buf   [16]uint32
	avail int
}

type KeySizeError int
type IVSizeError int

const outputBufferSize = 64

func (k KeySizeError) Error() string {
	return "crypto/chacha20poly1305: invalid key size " + strconv.Itoa(int(k))
}

func (i IVSizeError) Error() string {
	return "crypto/chacha20poly1305: invalid iv size " + strconv.Itoa(int(i))
}

func u8tou32(in []byte) uint32 {
	if supportsUnaligned {
		return *(*uint32)(unsafe.Pointer(&in[0]))
	} else {
		return uint32(in[0]) ^ uint32(in[1])<<8 ^ uint32(in[2])<<16 ^ uint32(in[3])<<24
	}
}

func newChacha(key []byte) (*chacha20Cipher, error) {
	k := len(key)

	if k != 32 {
		return nil, KeySizeError(k)
	}

	c := chacha20Cipher{state: [16]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
		u8tou32(key[0:4]), u8tou32(key[4:8]), u8tou32(key[8:12]), u8tou32(key[12:16]),
		u8tou32(key[16:20]), u8tou32(key[20:24]), u8tou32(key[24:28]), u8tou32(key[28:32]),
		0, 0, 0, 0},
		avail: 0}

	return &c, nil
}

func (c *chacha20Cipher) setIV(iv []byte, ctr uint32) error {
	i := len(iv)

	if i != 12 {
		return IVSizeError(i)
	}

	c.state[12] = ctr
	c.state[13] = u8tou32(iv[0:4])
	c.state[14] = u8tou32(iv[4:8])
	c.state[15] = u8tou32(iv[8:12])
	c.avail = 0

	return nil
}

func NewCipher(key, iv []byte, ctr uint32) (cipher.Stream, error) {

	c, err := newChacha(key)
	if err != nil {
		return nil, err
	}

	if err := c.setIV(iv, ctr); err != nil {
		return nil, err
	}

	return c, nil
}

func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {

	a += b
	d ^= a
	d = d<<16 ^ d>>16

	c += d
	b ^= c
	b = b<<12 ^ b>>20

	a += b
	d ^= a
	d = d<<8 ^ d>>24

	c += d
	b ^= c
	b = b<<7 ^ b>>25

	return a, b, c, d
}

func (c *chacha20Cipher) core() {

	s0 := c.state[0x0]
	s1 := c.state[0x1]
	s2 := c.state[0x2]
	s3 := c.state[0x3]
	s4 := c.state[0x4]
	s5 := c.state[0x5]
	s6 := c.state[0x6]
	s7 := c.state[0x7]
	s8 := c.state[0x8]
	s9 := c.state[0x9]
	sa := c.state[0xa]
	sb := c.state[0xb]
	sc := c.state[0xc]
	sd := c.state[0xd]
	se := c.state[0xe]
	sf := c.state[0xf]

	for i := 0; i < 20; i += 2 {
		s0, s4, s8, sc = quarterRound(s0, s4, s8, sc)
		s1, s5, s9, sd = quarterRound(s1, s5, s9, sd)
		s2, s6, sa, se = quarterRound(s2, s6, sa, se)
		s3, s7, sb, sf = quarterRound(s3, s7, sb, sf)

		s0, s5, sa, sf = quarterRound(s0, s5, sa, sf)
		s1, s6, sb, sc = quarterRound(s1, s6, sb, sc)
		s2, s7, s8, sd = quarterRound(s2, s7, s8, sd)
		s3, s4, s9, se = quarterRound(s3, s4, s9, se)
	}

	c.buf[0x0] = s0 + c.state[0x0]
	c.buf[0x1] = s1 + c.state[0x1]
	c.buf[0x2] = s2 + c.state[0x2]
	c.buf[0x3] = s3 + c.state[0x3]
	c.buf[0x4] = s4 + c.state[0x4]
	c.buf[0x5] = s5 + c.state[0x5]
	c.buf[0x6] = s6 + c.state[0x6]
	c.buf[0x7] = s7 + c.state[0x7]
	c.buf[0x8] = s8 + c.state[0x8]
	c.buf[0x9] = s9 + c.state[0x9]
	c.buf[0xa] = sa + c.state[0xa]
	c.buf[0xb] = sb + c.state[0xb]
	c.buf[0xc] = sc + c.state[0xc]
	c.buf[0xd] = sd + c.state[0xd]
	c.buf[0xe] = se + c.state[0xe]
	c.buf[0xf] = sf + c.state[0xf]

	c.state[12]++
	c.avail = 64
}

func (c *chacha20Cipher) XORKeyStream(dst, src []byte) {

	buf := (*[64]byte)(unsafe.Pointer(&c.buf[0]))

	for len(src) > 0 {
		if c.avail == 0 {
			c.core()
		}
		n := xorBytes(dst, src, buf[64-c.avail:])

		c.avail -= n
		dst = dst[n:]
		src = src[n:]
	}
}
