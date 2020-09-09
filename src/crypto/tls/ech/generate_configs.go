// Copyright 2020 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// +build ignore

package main

import (
	"crypto/rand"
	"crypto/tls/ech"
	"encoding/pem"
	"log"
	"os"
	"time"
)

func main() {
	version := ech.VersionDraft08

	x25519Template := ech.DefaultConfigTemplate()
	x25519Template.KemId = ech.HPKE_KEM_DHKEM_X25519_HKDF_SHA256
	x25519Template.Version = version
	x25519Key, err := ech.GenerateKey(x25519Template, rand.Reader, time.Now)
	if err != nil {
		log.Fatal(err)
	}

	p256Template := ech.DefaultConfigTemplate()
	p256Template.KemId = ech.HPKE_KEM_DHKEM_P256_HKDF_SHA256
	p256Template.Version = version
	p256Key, err := ech.GenerateKey(p256Template, rand.Reader, time.Now)
	if err != nil {
		log.Fatal(err)
	}

	rawKeys := make([]byte, 0)
	rawConfigs := make([]byte, 0)
	for _, key := range []*ech.Key{x25519Key, p256Key} {
		rawKey, err := key.Marshal()
		if err != nil {
			log.Fatal(err)
		}
		rawKeys = append(rawKeys, rawKey...)

		rawConfig, err := key.Config.Marshal()
		if err != nil {
			log.Fatal(err)
		}
		rawConfigs = append(rawConfigs, rawConfig...)
	}

	keysOut, err := os.OpenFile("keys.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer keysOut.Close()

	if err = pem.Encode(keysOut, &pem.Block{Type: "ECH KEYS", Bytes: rawKeys}); err != nil {
		log.Fatal(err)
	}

	log.Println("wrote keys.pem")

	configsOut, err := os.Create("configs.pem")
	if err != nil {
		log.Fatal(err)
	}
	defer configsOut.Close()

	if err = pem.Encode(configsOut, &pem.Block{Type: "ECH CONFIGS", Bytes: rawConfigs}); err != nil {
		log.Fatal(err)
	}

	log.Println("wrote configs.pem")
}
