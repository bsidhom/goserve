package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	var dir string
	var port int
	var allInterfaces bool
	var enableCache bool
	flag.StringVar(&dir, "from", ".", "Directory to serve data from.")
	flag.IntVar(&port, "port", 8000, "Port to listen on.")
	flag.BoolVar(&allInterfaces, "public", false, "Listen on all (including non-localhost) interfaces.")
	flag.BoolVar(&enableCache, "cache", false, "Enable caching")
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

	log.Printf("listening on %q", addr)
	err := http.ListenAndServe(addr, mux)
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
