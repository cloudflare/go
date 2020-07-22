// +build amd64,!noasm

package p384

import "internal/cpu"

var hasBMI2 = cpu.X86.HasBMI2 //nolint
