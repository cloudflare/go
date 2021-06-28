// Copyright (c) 2021 Cloudflare, Inc.

// +build !nethttpomithttp2

package http_test

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"reflect"
	"strings"
	"testing"
)

func TestCF_HTTP1ReadRequest(t *testing.T) {
	rawRequest := "GET / HTTP/1.0\r\n" +
		"Host: blah\r\n" +
		"\r\n"

	r, err := http.CFReadRequest(bufio.NewReader(strings.NewReader(rawRequest)))
	if err != nil {
		t.Fatal(err)
	}

	want := []textproto.CFHeaderLine{
		{
			Name:                  "Host",
			Value:                 "blah",
			HTTP1SpacesAfterColon: 1,
		},
	}

	if !reflect.DeepEqual(r.CFHeaderLines, want) {
		t.Errorf("unexpected CFHeaderLines: want %v; got %v", r.CFHeaderLines, want)
	}
}

// Check that http.Request.CFHeaderLines gets set properly.
func TestCF_HTTP1HeaderLines(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := []textproto.CFHeaderLine{
			{
				Name:                  "Host",
				Value:                 r.Host,
				HTTP1SpacesAfterColon: 1,
			},
			{
				Name:                  "User-Agent",
				Value:                 "Go-http-client/1.1",
				HTTP1SpacesAfterColon: 1,
			},
			{
				Name:                  "Accept-Encoding",
				Value:                 "gzip",
				HTTP1SpacesAfterColon: 1,
			},
		}

		if !reflect.DeepEqual(r.CFHeaderLines, want) {
			t.Errorf("unexpected CFHeaderLines: want %v; got %v", r.CFHeaderLines, want)
		}
	}))
	ts.Config.CFRecordRequestLines = true
	defer ts.Close()

	_, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
}

// Same test as above, except enable HTTP/2.
func TestCF_HTTP2HeaderLines(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := []textproto.CFHeaderLine{
			{
				Name:                  ":authority",
				Value:                 r.Host,
				HTTP1SpacesAfterColon: -1,
			},
			{
				Name:                  ":method",
				Value:                 "GET",
				HTTP1SpacesAfterColon: -1,
			},
			{
				Name:                  ":path",
				Value:                 "/",
				HTTP1SpacesAfterColon: -1,
			},
			{
				Name:                  ":scheme",
				Value:                 "https",
				HTTP1SpacesAfterColon: -1,
			},
			{
				Name:                  "accept-encoding",
				Value:                 "gzip",
				HTTP1SpacesAfterColon: -1,
			},
			{
				Name:                  "user-agent",
				Value:                 "Go-http-client/2.0",
				HTTP1SpacesAfterColon: -1,
			},
		}

		if !reflect.DeepEqual(r.CFHeaderLines, want) {
			t.Errorf("unexpected CFHeaderLines:\nwant %v\ngot  %v", r.CFHeaderLines, want)
		}

	}))
	ts.Config.CFRecordRequestLines = true
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	tc := ts.Client()
	_, err := tc.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
}
