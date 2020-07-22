package keccakf1600

import "circl/internal/shake"

func permuteSIMD(state []uint64) { f1600x4AVX2(&state[0], &shake.RC) }
