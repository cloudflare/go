// Copyright (c) 2021 Cloudflare, Inc.

package cf_test

import (
	"net/cf"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// Check that, if an HTTP server has a net/http.CFNewHeaderProcessor configured,
// then the request context propagates a processor.
func TestHTTP1HeaderProcessor(t *testing.T) {
	ch := make(chan *testHeaderProcessor)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k := cf.HeaderProcessorContextKey("cf-header-processor")
		v := r.Context().Value(k)

		go func() {
			p, _ := v.(*testHeaderProcessor)
			ch <- p
		}()
	}))
	ts.Config.CFNewHeaderProcessor = newTestHeaderProcessor
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	p := <-ch
	if p == nil {
		t.Fatal("processor not propagated")
	}

	if p.isHTTP2 {
		t.Fatal("HTTP/2 was used; expected HTTP/1")
	}

	wantCallCt := 1 /* request line */ + 2*3 /* three headers, two calls per header */
	gotCallCt := len(p.callOrder)
	if gotCallCt != wantCallCt {
		t.Errorf("unexpected number of calls: got %d; want %d", gotCallCt, wantCallCt)
	}

	wantCallOrder := []callType{
		callHTTP1RequestLine,
		callHTTP1RawHeader,
		callHeader,
		callHTTP1RawHeader,
		callHeader,
		callHTTP1RawHeader,
		callHeader,
	}

	if !reflect.DeepEqual(p.callOrder, wantCallOrder) {
		t.Errorf("unexpected call order: got %v; want %v", p.callOrder, wantCallOrder)
	}
}

// Same test as above, except enable HTTP/2.
func TestHTTP2HeaderProcessor(t *testing.T) {
	ch := make(chan *testHeaderProcessor)

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k := cf.HeaderProcessorContextKey("cf-header-processor")
		v := r.Context().Value(k)

		go func() {
			p, _ := v.(*testHeaderProcessor)
			ch <- p
		}()
	}))
	ts.EnableHTTP2 = true
	ts.Config.CFNewHeaderProcessor = newTestHeaderProcessor
	ts.StartTLS()
	defer ts.Close()

	tc := ts.Client()
	resp, err := tc.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	p := <-ch
	if p == nil {
		t.Fatal("processor not propagated")
	}

	if !p.isHTTP2 {
		t.Fatal("HTTP/1 was used; expected HTTP/2")
	}

	wantCallCt := 6 /* six headers */
	gotCallCt := len(p.callOrder)
	if gotCallCt != wantCallCt {
		t.Errorf("unexpected number of calls: got %d; want %d", gotCallCt, wantCallCt)
	}

	wantCallOrder := []callType{
		callHeader,
		callHeader,
		callHeader,
		callHeader,
		callHeader,
		callHeader,
	}

	if !reflect.DeepEqual(p.callOrder, wantCallOrder) {
		t.Errorf("unexpected call order: got %v; want %v", p.callOrder, wantCallOrder)
	}
}

// Check that the request context does not propagate a request processor if no
// constructor is configured.
func TestNoHeaderProcessor(t *testing.T) {
	ch := make(chan *testHeaderProcessor)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k := cf.HeaderProcessorContextKey("cf-header-processor")
		v := r.Context().Value(k)

		go func() {
			p, _ := v.(*testHeaderProcessor)
			ch <- p
		}()
	}))
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	p := <-ch
	if p != nil {
		t.Fatal("processor propagated; expected nil")
	}
}

// This processor records the order in which the calls were made and whether
// HTTP/2 was used for the request.
type testHeaderProcessor struct {
	callOrder []callType
	isHTTP2   bool
}

type callType int

func (t callType) String() string {
	switch t {
	case callHTTP1RequestLine:
		return "HTTP1RequestLine"
	case callHTTP1RawHeader:
		return "HTTP1RawHeader"
	case callHeader:
		return "RawHeader"
	default:
		panic("unknown call type")
	}
}

const (
	callHTTP1RequestLine callType = iota
	callHTTP1RawHeader
	callHeader
)

func newTestHeaderProcessor(isHTTP2 bool) cf.HeaderProcessor {
	return &testHeaderProcessor{
		isHTTP2: isHTTP2,
	}
}

func (p *testHeaderProcessor) HTTP1RequestLine(_ string) {
	p.callOrder = append(p.callOrder, callHTTP1RequestLine)
}

func (p *testHeaderProcessor) HTTP1RawHeader(_ []byte) {
	p.callOrder = append(p.callOrder, callHTTP1RawHeader)
}

func (p *testHeaderProcessor) Header(_, _ string) {
	p.callOrder = append(p.callOrder, callHeader)
}
