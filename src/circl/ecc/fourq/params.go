package fourq

// All values in little endian
var (

	// prime is the modulus 2^127-1
	prime = [2]uint64{
		0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF,
	}

	// orderGenerator is the size of the largest subgroup.
	orderGenerator = [4]uint64{
		0x2fb2540ec7768ce7, 0xdfbd004dfe0f7999,
		0xf05397829cbc14e5, 0x0029cbc14e5e0a72,
	}

	paramD = Fq{
		Fp{
			0x42, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0xe4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		Fp{
			0x8d, 0x0c, 0xfc, 0xf1, 0x88, 0x14, 0x82, 0xb3,
			0xfc, 0xe0, 0x57, 0x66, 0x84, 0x2f, 0x47, 0x5e,
		},
	}

	genX = Fq{
		Fp{
			0xaa, 0x33, 0x38, 0x7b, 0xad, 0x92, 0x65, 0x28,
			0x05, 0xb3, 0x2f, 0x7c, 0x23, 0x72, 0x34, 0x1a,
		},
		Fp{
			0xf6, 0x77, 0xac, 0x60, 0xb3, 0x9f, 0x86, 0x96,
			0x9c, 0xaa, 0x78, 0x28, 0x3f, 0x55, 0x1f, 0x1e,
		},
	}

	genY = Fq{
		Fp{
			0x87, 0xb2, 0xcb, 0x2b, 0x46, 0xa2, 0x24, 0xb9,
			0x5a, 0x78, 0x20, 0xa1, 0x9b, 0xee, 0x3f, 0x0e,
		},
		Fp{
			0x5c, 0x8b, 0x4c, 0x84, 0x44, 0xc3, 0xa7, 0x49,
			0x42, 0x02, 0x0e, 0x63, 0xf8, 0x4a, 0x1c, 0x6e,
		},
	}
)
