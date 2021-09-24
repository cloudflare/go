package keccakf1600

import "circl/internal/sha3"

func permuteSIMD(state []uint64) { f1600x4AVX2(&state[0], &sha3.RC) }
