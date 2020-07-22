// +build amd64

package p384

import "internal/cpu"

var hasBMI2 = cpu.X86.HasBMI2 //nolint
