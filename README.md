# crypto-go

Go library of crypto standards.

## Installation

To install crypto-go, use `go get`:

```shell
go get github.com/trumanwong/cryptogo
```

## Usage
```go
package yours

import (
	"fmt"
	"trumanwong/cryptogo"
)

func main()  {
    fmt.Println(cryptogo.MD5("message"))
}
```

## Finished encrypt functions

- md5
- sha1
- sha224
- sha256
- sha384
- sha512
- sha3-224
- sha3-256
- sha3-384
- sha3-512
---

- hmac-md5
- hmac-sha1
- hmac-sha224
- hmac-sha256
- hmac-sha512
- hmac-sha384
- hmac-ripemd160

## Staying up to date

To update crypto-go to the latest version, use `go get -u github.com/trumanwong/cryptogo`

## License
This project is licensed under the terms of the MIT license.