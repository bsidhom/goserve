// HTTP server meant to be used for quick development. Caching is aggressively disabled so that changes propagate fast.
// Originally from https://gist.github.com/bsidhom/028f7bafc730615aee3c2b516b5001b7.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"
)

func main() {
	var dir string
	var port int
	var allInterfaces bool
	var enableCache bool
	var tlsName string
	flag.StringVar(&dir, "from", ".", "Directory to serve data from.")
	flag.IntVar(&port, "port", 8000, "Port to listen on.")
	flag.BoolVar(&allInterfaces, "public", false, "Listen on all (including non-localhost) interfaces.")
	flag.BoolVar(&enableCache, "cache", false, "Enable caching")
	flag.StringVar(&tlsName, "tls", "", "If non-empty, will generate a random TLS keypair for the given server name and serve TLS.")
	flag.Parse()

	handler := http.FileServer(http.Dir(dir))
	if !enableCache {
		handler = disableCache(handler)
	}
	mux := http.NewServeMux()
	mux.Handle("/", handler)

	var addr string
	if allInterfaces {
		addr = fmt.Sprintf(":%d", port)
	} else {
		addr = fmt.Sprintf("localhost:%d", port)
	}

	var listener net.Listener
	var err error
	if tlsName == "" {
		listener, err = net.Listen("tcp", addr)
	} else {
		cert := generateTLSCert(tlsName)
		listener, err = tls.Listen("tcp", addr, &tls.Config{
			Certificates: []tls.Certificate{cert},
		})
	}
	if err != nil {
		panic(err)
	}

	log.Printf("listening on %q", addr)
	err = http.Serve(listener, mux)
	if err != nil {
		panic(err)
	}
}

var unixEpoch = time.Unix(0, 0).Format(time.RFC1123)

func disableCache(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Delete the If-Modified-Since header. Browsers aggressively set this. The
		// static content server uses this header to determine whether to send a 302
		// response:
		// https://github.com/golang/go/blob/05c8d8d3655b92ea6608f8f9ff47d85b74b67e94/src/net/http/fs.go#L431
		r.Header.Del("If-Modified-Since")

		h.ServeHTTP(w, r)

		// Set anti-cache headers.
		w.Header().Set("Cache-Control", "no-cache, private, max-age=0")
		w.Header().Set("Expires", unixEpoch)
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Accel-Expires", "0")

		// Delete timestamps just in case.
		w.Header().Del("Last-Modified")
		w.Header().Del("Date")
	})
}

func generateTLSCert(name string) tls.Certificate {
	// Generate a one-time use TLS certificate. Adapted from https://stackoverflow.com/a/43828190.
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}
	// Generate a pem block with the private key
	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	maxSerialNumber := big.NewInt(1)
	maxSerialNumber.Lsh(maxSerialNumber, 256)
	serialNumber, err := rand.Int(rand.Reader, maxSerialNumber)
	if err != nil {
		panic(err)
	}
	tml := x509.Certificate{
		NotBefore: time.Now(),
		// NOTE: This cert will expire in 1 day.
		NotAfter:     time.Now().Add(24 * time.Hour),
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"Local Development"},
		},
		BasicConstraintsValid: true,
	}
	cert, err := x509.CreateCertificate(rand.Reader, &tml, &tml, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	tlsCert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		panic(err)
	}
	return tlsCert
}
