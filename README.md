This is a stable Go tree with some backports from tip and some CloudFlare commits.

This branch is based on 1.4.3 and is not to be considered maintained anymore.

## Backports

Please note that the commit authors have no control or responsability over the backporting.

```
* go/build: add variable expansion to cgo lines <Carlos Castillo>
* crypto/tls: update the supported signature algorithms. <Adam Langley>
* crypto/tls: decouple handshake signatures from the handshake hash. <Adam Langley>
* crypto/tls: call GetCertificate if Certificates is empty. <Adam Langley>
* crypto/tls: make use of crypto.Signer and crypto.Decrypter <Jacob H. Haven>
* crypto/tls: return correct hash function when using client certificates in handshake <Joël Stemmer>
* crypto/rsa: implement crypto.Decrypter <Nick Sullivan>
* crypto/tls: add support for AES_256_GCM_SHA384 cipher suites specified in RFC5289 <Jacob H. Haven>
* crypto/ecdsa: make Sign safe with broken entropy sources <David Leon Gil>
* crypto/x509: Fix parsing bug in uncommon CSR Attributes. <Jacob H. Haven>
* crypto/x509: implement crypto.Signer <Paul van Brouwershaven>
```

## CloudFlare commits

```
* crypto/aes: dedicated asm version of AES-GCM <Vlad Krasnov>
* math/big: Simple Montgomery Multiplication to accelerate Mod-Exp <Vlad Krasnov>
* crypto/elliptic,crypto/ecdsa: P256 amd64 assembly <Vlad Krasnov>
```
