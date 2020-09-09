// Copyright 2020 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package ech

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func TestKeySerialization(t *testing.T) {
	template := DefaultConfigTemplate()
	template.ignoredExtensions = []byte("raw ECHConfigContents.extensions")
	want, err := GenerateKey(template, rand.Reader, time.Now)
	if err != nil {
		t.Fatal(err)
	}

	rawKey, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	got, err := UnmarshalKey(rawKey)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got.sk.marshaled(), want.sk.marshaled()) {
		t.Errorf("sk: got %x; want %x", got.sk, want.sk)
	}

	if got.Created != want.Created {
		t.Errorf("Created: got %s; want %s", got.Created, want.Created)
	}

	if got.Config.Version != want.Config.Version {
		t.Errorf("Config.Version: got %x; want %x", got.Config.Version, want.Config.Version)
	}

	if !bytes.Equal(got.Config.Contents, want.Config.Contents) {
		t.Errorf("Config.Contents: got %v; want %v", got.Config.Contents, want.Config.Contents)
	}

	if got.Config.contents.KemId != want.Config.contents.KemId {
		t.Errorf("Config.contents.kemId: got %x; want %x", got.Config.contents.KemId, want.Config.contents.KemId)
	}

	bad := false
	if len(got.Config.contents.CipherSuites) != len(want.Config.contents.CipherSuites) {
		bad = true
	} else {
		for i, _ := range got.Config.contents.CipherSuites {
			if got.Config.contents.CipherSuites[i] != want.Config.contents.CipherSuites[i] {
				bad = true
			}
		}
	}
	if bad {
		t.Errorf("Config.contents.CipherSuites: got %v; want %v", got.Config.contents.CipherSuites, want.Config.contents.CipherSuites)
	}

	if got.Config.contents.MaximumNameLength != want.Config.contents.MaximumNameLength {
		t.Errorf("Config.contents.MaximumNameLength: got %d; want %d", got.Config.contents.MaximumNameLength, want.Config.contents.MaximumNameLength)
	}

	if !bytes.Equal(got.Config.contents.IgnoredExtensions, want.Config.contents.IgnoredExtensions) {
		t.Errorf("Config.contents.IgnoredExtensions: got %v; want %v", got.Config.contents.IgnoredExtensions, want.Config.contents.IgnoredExtensions)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	want := []byte("raw ClientHelloInner")
	template := DefaultConfigTemplate()
	key, err := GenerateKey(template, rand.Reader, time.Now)
	if err != nil {
		t.Fatal(err)
	}

	clientContext, enc, err := key.Config.SetupClientContext(nil, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serverContext, err := key.SetupServerContext(enc, nil, clientContext.Suite)
	if err != nil {
		t.Fatal(err)
	}

	got, err := serverContext.Decrypt(clientContext.Encrypt(want))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("encryption fails: got %v; want %v", got, want)
	}
}

func TestExportHRRKey(t *testing.T) {
	template := DefaultConfigTemplate()
	key, err := GenerateKey(template, rand.Reader, time.Now)
	if err != nil {
		t.Fatal(err)
	}

	clientContext, enc, err := key.Config.SetupClientContext(nil, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serverContext, err := key.SetupServerContext(enc, nil, clientContext.Suite)
	if err != nil {
		t.Fatal(err)
	}

	clientHrrKey := clientContext.ExportHRRKey()
	serverHrrKey := serverContext.ExportHRRKey()
	if !bytes.Equal(clientHrrKey, serverHrrKey) {
		t.Errorf("HRR keys don't match; want match (%x != %x)", clientHrrKey, serverHrrKey)
	}

	if len(clientHrrKey) != echHpkeHrrKeyLen {
		t.Errorf("HRR key length incorrect: want %d; got %d", echHpkeHrrKeyLen, len(clientHrrKey))
	}
}
