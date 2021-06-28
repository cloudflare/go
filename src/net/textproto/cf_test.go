// Copyright (c) 2021 Cloudflare, Inc.

package textproto

import (
	"reflect"
	"testing"
)

func TestCFRadMIMEHeaderr(t *testing.T) {
	r := reader("my-key: Value one  \r\nlong-kEy:    Even \n Longer Value\r\nmy-KEY:Value two\r\n\n")
	_, ordered, err := r.CFReadMIMEHeader(true /* recordRequestLines */)
	if err != nil {
		t.Fatal(err)
	}

	want := []CFHeaderLine{
		{
			Name:                  "my-key",
			Value:                 "Value one",
			HTTP1SpacesAfterColon: 1,
		},
		{
			Name:                  "long-kEy",
			Value:                 "Even Longer Value",
			HTTP1SpacesAfterColon: 4,
		},
		{
			Name:                  "my-KEY",
			Value:                 "Value two",
			HTTP1SpacesAfterColon: 0,
		},
	}

	if !reflect.DeepEqual(ordered, want) || err != nil {
		t.Fatalf("CFReadMIMEHeader: %v, %v; want %v", ordered, err, want)
	}
}
