package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

func masqHandler(target string) http.Handler {
	if target == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "not found", http.StatusNotFound)
		})
	}
	// Proxy to HTTPS for realistic masquerade
	targetURL := strings.TrimPrefix(target, "http://")
	targetURL = strings.TrimPrefix(targetURL, "https://")
	targetURL = strings.TrimSuffix(targetURL, "/")
	u, err := url.Parse("https://" + targetURL)
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "bad gateway", http.StatusBadGateway)
		})
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("masq: %s %s from %s", r.Method, r.URL, r.RemoteAddr)
		r.Host = u.Host
		r.URL.Scheme = "https"
		rp.ServeHTTP(w, r)
	})
}

func (e *edge) serveMasqTCP(ctx context.Context, ln net.Listener, domain string) {
	mux := http.NewServeMux()
	mux.Handle("/", masqHandler(domain))
	tlsCfg := &tls.Config{
		GetCertificate: e.vault.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
	tlsLn := tls.NewListener(ln, tlsCfg)
	srv := &http.Server{Handler: mux}
	e.mu.Lock()
	e.tcpServer = srv
	e.mu.Unlock()
	log.Printf("data: tcp masq serving HTTPS on %s -> %s", ln.Addr(), domain)
	if err := srv.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
		log.Printf("data: tcp masq serve error: %v", err)
	}
}
