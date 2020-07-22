package internal

import (
	"testing"

	"circl/sign/dilithium/internal/common"
)

// Tests specific to the current mode

func TestVectorDeriveUniformLeqEta(t *testing.T) {
	var p common.Poly
	var seed [32]byte
	p2 := common.Poly{
		3, 0, 2, 3, 8380412, 8380414, 2, 2, 8380415, 8380416,
		8380416, 1, 7, 8380411, 4, 7, 2, 8380414, 8380412, 0, 3,
		8380413, 4, 8380410, 8380414, 8380410, 8380413, 8380412,
		8380410, 8380410, 7, 3, 8380412, 3, 8380411, 8380414, 7,
		8380415, 1, 8380416, 7, 8380414, 2, 4, 7, 8380416, 4, 5,
		5, 2, 1, 8380411, 7, 3, 4, 8380416, 8380415, 2, 2, 8380410,
		7, 5, 0, 8380411, 8380416, 7, 8380412, 5, 8380411, 5, 4,
		1, 4, 2, 8380414, 8380416, 3, 4, 8380414, 8380410, 8380414,
		7, 8380415, 8380412, 8380411, 6, 8380415, 8380410, 8380413,
		0, 8380416, 8380412, 8380411, 6, 8380415, 8380410, 8380410,
		8380413, 7, 8380415, 3, 1, 0, 8380414, 4, 8380410, 8380412,
		5, 6, 0, 1, 8380410, 8380413, 8380410, 6, 8380411, 0,
		8380415, 3, 8380411, 2, 3, 6, 8380410, 8380410, 0, 0, 6,
		8380414, 0, 6, 8380411, 8380412, 8380412, 5, 7, 2, 8380413,
		8380410, 0, 0, 4, 0, 5, 8380416, 1, 5, 7, 7, 8380410, 2,
		0, 8380412, 6, 5, 4, 8380411, 0, 0, 7, 8380414, 8380416,
		8380410, 4, 0, 8380411, 8380410, 8380413, 8380414, 3,
		8380413, 8380414, 8380415, 7, 8380411, 8380414, 8380410,
		5, 6, 8380410, 6, 8380415, 4, 0, 0, 8380416, 8380415,
		8380415, 8380415, 4, 8380410, 8380411, 8380415, 8380412,
		6, 1, 4, 1, 2, 8380411, 0, 8380416, 4, 8380414, 8380416,
		6, 5, 1, 3, 8380414, 4, 8380414, 8380414, 3, 2, 2, 8380413,
		2, 8380412, 0, 8380416, 8380415, 8380414, 0, 3, 8380413,
		3, 8380410, 7, 8380410, 8380414, 8380412, 1, 4, 2, 8380415,
		2, 8380410, 8380410, 8380410, 4, 8380413, 4, 4, 0, 3,
		8380410, 5, 8380413, 8380414, 8380415, 4, 1, 8380410, 7,
		8380413,
	}
	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
	}
	PolyDeriveUniformLeqEta(&p, &seed, 30000)
	p.Normalize()
	if p != p2 {
		t.Fatalf("%v != %v", p, p2)
	}
}
