package tls

import (
	"bytes"
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

// cfTestClientHelloEqual checks that the client and server both set
// ConnectionState.CFClientHello and that the values match.
func cfTestClientHelloEqual(t *testing.T, clientState, serverState *ConnectionState) {
	cli := clientState.CFClientHello
	srv := serverState.CFClientHello

	if len(cli) == 0 {
		t.Fatal("client state is missing CFClientHello")
	}

	if len(srv) == 0 {
		t.Fatal("server state is missing CFClientHello")
	}

	if !bytes.Equal(cli, srv) {
		t.Error("CFClientHello mismatch")
		t.Errorf("client: %02x", cli)
		t.Errorf("server: %02x", srv)
	}
}
