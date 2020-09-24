This packages is a paired down version of [Cisco's HPKE
implementation](https://github.com/cisco/go-hpke). Its base is:

```
$ git clone https://github.com/cisco/go-hpke
$ cd go-hpke
$ git checkout a07eeccbf5d591fce2c172bf5b35c8d048b320bd
```
Changes:

* Dependency on "log" has been removed.
* Dependency on "git.schwanenlied.me/yawning/x448.git" has been removed.
* Imports from "github.com/cloudflare/circl/..." have been changed to "circl/...".
* Import from "github.com/cisco/go-tls-syntax" has been changed to
  "crypto/tls/internal/syntax".
* Commented out lines 287, 538, and 557 in crypto.go.

TODO(cjpatton): Remove this package once HPKE is implemented in CIRCL.
