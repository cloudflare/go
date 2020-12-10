package tls

import (
	"testing"
)

type testCFControl struct {
	flags uint64
}

// Check that CFControl is correctly propagated from Config to ConnectionState.
func TestPropagateCFControl(t *testing.T) {
	want := uint64(23)
	s := Server(nil, &Config{CFControl: &testCFControl{want}})
	got := s.ConnectionState().CFControl.(*testCFControl).flags
	if got != want {
		t.Errorf("failed to propagate CFControl: got %v; want %v", got, want)
	}
}
