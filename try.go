package main

import (
	"crypto/tls"
	"log"
	"net/http"

	cert "github.com/chie4hao/nettools/cert"
	net "github.com/chie4hao/nettools/net"
)

func main() {
	ca, err := cert.LoadCA()
	if err != nil {
		log.Fatal(err)
	}
	p := &net.Proxy{
		CA: &ca,
		TLSServerConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
		},
		Wrap: cloudToButt,
	}
	log.Fatal(http.ListenAndServe(":8080", p))
}

func cloudToButt(upstream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream.ServeHTTP(w, r)
	})
}
