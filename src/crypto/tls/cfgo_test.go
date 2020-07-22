//go:build !cfgo

package tls

import "testing"

func TestCfgoBuildTag(t *testing.T) {
	t.Error("Build tag cfgo is expected to be set for this toolchain")
}
