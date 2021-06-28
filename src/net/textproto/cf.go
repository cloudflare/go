// Copyright (c) 2021 Cloudflare, Inc.

package textproto

// CFHeaderLine represents an HTTP header line in a way that allows headers to
// be constructed (almost) as they appared on the wire. (We don't keep track of
// whitespace that interrupts the header value.)
type CFHeaderLine struct {
	// Name is the header name as it appears on the wire.
	Name string

	// Value is the header value.
	Value string

	// HTTP1SpacesAfterColon is the number of spaces between the colon and the
	// beginning of the header value. For example, for "Host:     example.com"
	// we set this to 5.
	//
	// This value is propagated by net/http.Request. If HTTP/2 was used for the
	// request, this value will be set to -1.
	HTTP1SpacesAfterColon int
}
