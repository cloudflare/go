// Copyright (c) 2021 Cloudflare, Inc.

package cf

// HeaderProcessor is called at various points while reading the client's
// request header from the wire.
type HeaderProcessor interface {
	// HTTP1RequestLine is called in HTTP/1 on the first line, e.g., "GET
	// /index.html HTTP/1.1".
	HTTP1RequestLine(line string)
	// HTTP1RawHeader is called in HTTP/1 on each header, e.g., "Host:
	// example.com".
	HTTP1RawHeader(header []byte)
	// Header is called in HTTP/1 or HTTP/2 on each header (name, value) pair.
	// The name is canonicalized.
	Header(name, value string)
}

// HeaderProcessorContextKey is the key type for the request processor
// added to the request context.
type HeaderProcessorContextKey string
