🚨 This fork is offered as-is, and without guarantees. It is expected that
changes in the code, repository, and API occur in the future. We recommend to take
caution before using this library in production.

# cfgo

This is an experimental fork of Go, that patches the TLS stack, to support: 

1. [Encrypted ClientHello (ECH)](https://blog.cloudflare.com/encrypted-client-hello/)
2. [Post-quantum key agreement](https://blog.cloudflare.com/post-quantum-for-all/)
3. [Delegated Credentials](https://blog.cloudflare.com/keyless-delegation/)
4. Post-quantum certificates. 
5. Configuraton of keyshares sent in ClientHello with `tls.Config.ClientCurveGuess`.

To use upstream Go and this fork with the same codebase, this fork sets the `cfgo` build tag.

## Build

```
$ git clone https://github.com/cloudflare/go
$ cd go/src
$ ./make.bash
```

 You can now use `../bin/go` as you would regular `go`.
