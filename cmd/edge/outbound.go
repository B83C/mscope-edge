package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	hcore "github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/outbounds/speedtest"
)

type directOutbound struct{}

func (directOutbound) TCP(reqAddr string) (net.Conn, error) {
	host := splitHost(reqAddr)
	log.Printf("outbound TCP request: reqAddr=%q host=%q", reqAddr, host)
	if strings.HasPrefix(host, "@") {
		if host == "@SpeedTest" {
			return speedtest.NewServerConn(), nil
		}
		return nil, fmt.Errorf("unknown internal address: %s", reqAddr)
	}
	return net.Dial("tcp", reqAddr)
}

func (directOutbound) UDP(reqAddr string) (hcore.UDPConn, error) {
	return newUDPConn()
}

func (directOutbound) CheckUDP(reqAddr string) error { return nil }

type udpConn struct{ c *net.UDPConn }

func newUDPConn() (*udpConn, error) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	return &udpConn{c: c}, nil
}

func (u *udpConn) ReadFrom(b []byte) (int, string, error) {
	n, a, err := u.c.ReadFromUDP(b)
	if err != nil {
		return 0, "", err
	}
	return n, a.String(), nil
}

func (u *udpConn) WriteTo(b []byte, addr string) (int, error) {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return 0, err
	}
	return u.c.WriteToUDP(b, a)
}

func (u *udpConn) Close() error { return u.c.Close() }

type atomicHandler struct {
	h atomic.Pointer[http.Handler]
}

func (a *atomicHandler) Set(h http.Handler) { a.h.Store(&h) }

func (a *atomicHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p := a.h.Load(); p != nil {
		(*p).ServeHTTP(w, r)
		return
	}
	http.Error(w, "masq not configured", http.StatusServiceUnavailable)
}

func splitHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func maybe[T uint64 | int64](v, def T) T {
	if v > 0 {
		return v
	}
	return def
}

func parseDuration(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}
