This is a stable Go tree with backports from tip and/or CloudFlare commits.

There is also a (not actively used anymore) 1.4.3-based branch at https://github.com/cloudflare/go/tree/1.4.3

## Backports

Please note that the commit authors have no control or responsability over the backporting.

```
crypto/elliptic,crypto/ecdsa: P256 amd64 assembly <Vlad Krasnov>
crypto/aes: dedicated asm version of AES-GCM <Vlad Krasnov>
math/big: additional Montgomery cleanup <Russ Cox>
crypto/rsa: check CRT result. <Adam Langley>
```
