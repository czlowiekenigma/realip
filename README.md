# RealIP

[![GoDoc](https://godoc.org/github.com/defabricated/realip?status.svg)](http://godoc.org/github.com/defabricated/realip)

Go package that can be used to get client's real public IP, which usually useful for logging HTTP server.

### Feature

* Follows the rule of X-Real-IP
* Follows the rule of X-Forwarded-For
* Exclude local or private address
* Exclude CloudFlare or own proxy server address

## Examples

```go
package main

import "github.com/czlowiekenigma/realip"

func (h *Handler) ServeIndexPage(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	clientIP := realip.FromRequest(r)
	log.Println("GET / from", clientIP)
}
```

You can also pass multiple CIDR blocks which are blocks of your proxies.

```go
package main

import "github.com/czlowiekenigma/realip"

func (h *Handler) ServeIndexPage(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	clientIP := realip.FromRequest(r, net.ParseCIDR("169.254.0.0/16"))
	log.Println("GET / from", clientIP)
}
```

## Developing

Commited code must pass:

* [golint](https://github.com/golang/lint)
* [go vet](https://godoc.org/golang.org/x/tools/cmd/vet)
* [gofmt](https://golang.org/cmd/gofmt)
* [go test](https://golang.org/cmd/go/#hdr-Test_packages):
