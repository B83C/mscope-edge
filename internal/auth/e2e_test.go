package auth

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/B83C/mscope-edge/pkg/control"
	hclient "github.com/apernet/hysteria/core/v2/client"
	hcore "github.com/apernet/hysteria/core/v2/server"
)

func tmpCert(t *testing.T) (_ tls.Certificate, pool *x509.CertPool) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:     []string{"test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, _ := tls.X509KeyPair(certPEM, keyPEM)
	cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	pool = x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	return cert, pool
}

func tmpPacketConn(t *testing.T) (net.PacketConn, *net.UDPAddr) {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	return udp, udp.LocalAddr().(*net.UDPAddr)
}

type directOutbound struct{}

func (d *directOutbound) TCP(addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, 5*time.Second)
}
func (d *directOutbound) UDP(addr string) (hcore.UDPConn, error) {
	return nil, fmt.Errorf("UDP not implemented")
}
func (d *directOutbound) CheckUDP(addr string) error { return nil }

func startServer(t *testing.T, store *Store) (hcore.Server, *x509.CertPool, *net.UDPAddr, func()) {
	t.Helper()
	pc, addr := tmpPacketConn(t)
	cert, pool := tmpCert(t)
	srv, err := hcore.NewServer(&hcore.Config{
		TLSConfig: hcore.TLSConfig{
			GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
		},
		Conn:          pc,
		Outbound:      &directOutbound{},
		Authenticator: store,
		EventLogger:   store,
		TrafficLogger: store,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	go func() { _ = srv.Serve() }()
	time.Sleep(100 * time.Millisecond)
	return srv, pool, addr, func() { srv.Close(); pc.Close() }
}

func dial(t *testing.T, addr *net.UDPAddr, auth string, pool *x509.CertPool) hclient.Client {
	t.Helper()
	cl, _, err := hclient.NewClient(&hclient.Config{
		ServerAddr: addr,
		Auth:       auth,
		TLSConfig:  hclient.TLSConfig{ServerName: "test", RootCAs: pool},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return cl
}

// TestE2E_Auth_Success — valid user:pass accepted.
func TestE2E_Auth_Success(t *testing.T) {
	s := NewStore()
	s.Apply(control.GrantsPayload{Grants: []control.UserGrant{{UserID: "alice", Secret: "pass", MaxClients: 3}}})
	_, pool, addr, stop := startServer(t, s)
	defer stop()

	cl := dial(t, addr, "alice:pass", pool)
	cl.Close()
}

// TestE2E_Auth_ExpiredGrant — grant with past ExpiresAt is rejected.
func TestE2E_Auth_ExpiredGrant(t *testing.T) {
	s := NewStore()
	s.Apply(control.GrantsPayload{Grants: []control.UserGrant{
		{UserID: "alice", Secret: "x", MaxClients: 3, ExpiresAt: time.Now().Add(-1 * time.Hour)},
	}})
	_, pool, addr, stop := startServer(t, s)
	defer stop()

	_, _, err := hclient.NewClient(&hclient.Config{
		ServerAddr: addr,
		Auth:       "alice:x",
		TLSConfig:  hclient.TLSConfig{ServerName: "test", RootCAs: pool},
	})
	if err == nil {
		t.Fatal("expected expired grant to be rejected")
	}
	t.Logf("expired rejected: %v", err)
}

// TestE2E_Auth_MultipleUsers — multiple users all authenticate.
func TestE2E_Auth_MultipleUsers(t *testing.T) {
	s := NewStore()
	s.Apply(control.GrantsPayload{Grants: []control.UserGrant{
		{UserID: "alice", Secret: "a", MaxClients: 3},
		{UserID: "bob", Secret: "b", MaxClients: 3},
		{UserID: "charlie", Secret: "c", MaxClients: 3},
	}})
	_, pool, addr, stop := startServer(t, s)
	defer stop()

	for _, tc := range []struct{ user, secret string }{
		{"alice", "a"},
		{"bob", "b"},
		{"charlie", "c"},
	} {
		cl := dial(t, addr, tc.user+":"+tc.secret, pool)
		cl.Close()
	}
}

// TestE2E_Auth_NonExistingUser — user not in grants rejected.
func TestE2E_Auth_NonExistingUser(t *testing.T) {
	s := NewStore()
	s.Apply(control.GrantsPayload{Grants: []control.UserGrant{
		{UserID: "alice", Secret: "x", MaxClients: 3},
	}})
	_, pool, addr, stop := startServer(t, s)
	defer stop()

	_, _, err := hclient.NewClient(&hclient.Config{
		ServerAddr: addr,
		Auth:       "nobody:x",
		TLSConfig:  hclient.TLSConfig{ServerName: "test", RootCAs: pool},
	})
	if err == nil {
		t.Fatal("expected non-existing user to be rejected")
	}
	t.Logf("non-existing rejected: %v", err)
}

// TestE2E_Auth_WrongPassword — wrong secret rejected.
func TestE2E_Auth_WrongPassword(t *testing.T) {
	s := NewStore()
	s.Apply(control.GrantsPayload{Grants: []control.UserGrant{{UserID: "alice", Secret: "pass", MaxClients: 3}}})
	_, pool, addr, stop := startServer(t, s)
	defer stop()

	_, _, err := hclient.NewClient(&hclient.Config{
		ServerAddr: addr,
		Auth:       "alice:wrong",
		TLSConfig:  hclient.TLSConfig{ServerName: "test", RootCAs: pool},
	})
	if err == nil {
		t.Fatal("expected auth failure")
	}
	t.Logf("rejected: %v", err)
}

// TestE2E_Auth_UnknownUser — unknown user rejected.
func TestE2E_Auth_UnknownUser(t *testing.T) {
	s := NewStore()
	s.Apply(control.GrantsPayload{Grants: []control.UserGrant{{UserID: "alice", Secret: "x", MaxClients: 3}}})
	_, pool, addr, stop := startServer(t, s)
	defer stop()

	_, _, err := hclient.NewClient(&hclient.Config{
		ServerAddr: addr,
		Auth:       "bob:x",
		TLSConfig:  hclient.TLSConfig{ServerName: "test", RootCAs: pool},
	})
	if err == nil {
		t.Fatal("expected auth failure")
	}
	t.Logf("rejected: %v", err)
}

// TestE2E_Auth_NoGrants — no grants at all rejected.
func TestE2E_Auth_NoGrants(t *testing.T) {
	_, pool, addr, stop := startServer(t, NewStore())
	defer stop()

	_, _, err := hclient.NewClient(&hclient.Config{
		ServerAddr: addr,
		Auth:       "any:x",
		TLSConfig:  hclient.TLSConfig{ServerName: "test", RootCAs: pool},
	})
	if err == nil {
		t.Fatal("expected auth failure")
	}
	t.Logf("rejected: %v", err)
}

// TestE2E_HTTP_ThroughTunnel — TCP forwarding + HTTP fetch through hysteria.
func TestE2E_HTTP_ThroughTunnel(t *testing.T) {
	store := NewStore()
	store.Apply(control.GrantsPayload{Grants: []control.UserGrant{{UserID: "alice", Secret: "pass", MaxClients: 3}}})
	_, pool, addr, stop := startServer(t, store)
	defer stop()

	cl := dial(t, addr, "alice:pass", pool)
	defer cl.Close()

	targetLn, _ := net.Listen("tcp", "127.0.0.1:0")
	targetSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("hello from target"))
	})}
	go targetSrv.Serve(targetLn)
	defer targetSrv.Close()

	conn, err := cl.TCP(targetLn.Addr().String())
	if err != nil {
		t.Fatalf("tcp: %v", err)
	}

	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/", targetLn.Addr()), nil)
	req.Write(conn)
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello from target" {
		t.Errorf("body: got %q, want %q", body, "hello from target")
	}
	conn.Close()

	time.Sleep(200 * time.Millisecond)
	tx, rx, _ := store.UserStats("alice")
	if tx == 0 && rx == 0 {
		t.Error("expected traffic logged")
	} else {
		t.Logf("traffic: tx=%d rx=%d", tx, rx)
	}
}

// TestE2E_MaxClients — max_clients=1, second connection rejected, reconnects after close.
func TestE2E_MaxClients(t *testing.T) {
	store := NewStore()
	store.Apply(control.GrantsPayload{Grants: []control.UserGrant{{UserID: "alice", Secret: "x", MaxClients: 1}}})
	_, pool, addr, stop := startServer(t, store)
	defer stop()

	cl1 := dial(t, addr, "alice:x", pool)

	_, _, err := hclient.NewClient(&hclient.Config{
		ServerAddr: addr,
		Auth:       "alice:x",
		TLSConfig:  hclient.TLSConfig{ServerName: "test", RootCAs: pool},
	})
	if err == nil {
		t.Fatal("expected max clients to block second connection")
	}
	t.Logf("second blocked: %v", err)

	cl1.Close()
	time.Sleep(500 * time.Millisecond)

	cl2 := dial(t, addr, "alice:x", pool)
	cl2.Close()
}

// TestE2E_UserOnline — user goes online after auth, offline after close.
func TestE2E_UserOnline(t *testing.T) {
	store := NewStore()
	store.Apply(control.GrantsPayload{Grants: []control.UserGrant{{UserID: "alice", Secret: "x", MaxClients: 3}}})
	_, pool, addr, stop := startServer(t, store)
	defer stop()

	cl := dial(t, addr, "alice:x", pool)
	time.Sleep(100 * time.Millisecond)
	_, _, online := store.UserStats("alice")
	if !online {
		t.Error("expected online after auth")
	}

	cl.Close()
	time.Sleep(500 * time.Millisecond)
	_, _, online = store.UserStats("alice")
	if online {
		t.Error("expected offline after close")
	}
}

// TestE2E_SessionCount — multiple sessions counted correctly.
func TestE2E_SessionCount(t *testing.T) {
	store := NewStore()
	store.Apply(control.GrantsPayload{Grants: []control.UserGrant{{UserID: "alice", Secret: "x", MaxClients: 5}}})
	_, pool, addr, stop := startServer(t, store)
	defer stop()

	cl1 := dial(t, addr, "alice:x", pool)
	cl2 := dial(t, addr, "alice:x", pool)

	time.Sleep(200 * time.Millisecond)
	active := store.ActiveSessions()
	if active["alice"] != 2 {
		t.Errorf("expected 2 sessions, got %d", active["alice"])
	}

	cl1.Close()
	time.Sleep(200 * time.Millisecond)
	active = store.ActiveSessions()
	if active["alice"] != 1 {
		t.Errorf("expected 1 session after close, got %d", active["alice"])
	}

	cl2.Close()
}

// TestE2E_ConcurrentDial — 3 clients dial in parallel, each makes one request.
func TestE2E_ConcurrentDial(t *testing.T) {
	store := NewStore()
	store.Apply(control.GrantsPayload{
		Grants: []control.UserGrant{
			{UserID: "alice", Secret: "x", MaxClients: 3},
			{UserID: "bob", Secret: "y", MaxClients: 3},
		},
	})
	_, pool, addr, stop := startServer(t, store)
	defer stop()

	targetLn, _ := net.Listen("tcp", "127.0.0.1:0")
	targetSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})}
	go targetSrv.Serve(targetLn)
	defer targetSrv.Close()

	var mu sync.Mutex
	errs := make([]error, 0)
	var wg sync.WaitGroup
	for i := range 3 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			auth := "alice:x"
			if n%2 == 0 {
				auth = "bob:y"
			}
			cl, _, err := hclient.NewClient(&hclient.Config{
				ServerAddr: addr,
				Auth:       auth,
				TLSConfig:  hclient.TLSConfig{ServerName: "test", RootCAs: pool},
			})
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("conn %d: %w", n, err))
				mu.Unlock()
				return
			}
			defer cl.Close()

			conn, err := cl.TCP(targetLn.Addr().String())
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("conn %d tcp: %w", n, err))
				mu.Unlock()
				return
			}
			conn.Close()
		}(i)
	}
	wg.Wait()

	for _, e := range errs {
		t.Error(e)
	}
}

// TestE2E_TrafficStats — traffic counted after data transfer.
func TestE2E_TrafficStats(t *testing.T) {
	store := NewStore()
	store.Apply(control.GrantsPayload{Grants: []control.UserGrant{{UserID: "alice", Secret: "x", MaxClients: 1}}})
	_, pool, addr, stop := startServer(t, store)
	defer stop()

	cl := dial(t, addr, "alice:x", pool)
	defer cl.Close()

	targetLn, _ := net.Listen("tcp", "127.0.0.1:0")
	targetSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("traffic test body"))
	})}
	go targetSrv.Serve(targetLn)
	defer targetSrv.Close()

	conn, err := cl.TCP(targetLn.Addr().String())
	if err != nil {
		t.Fatalf("tcp: %v", err)
	}
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/", targetLn.Addr()), nil)
	req.Write(conn)
	resp, _ := http.ReadResponse(bufio.NewReader(conn), req)
	io.ReadAll(resp.Body)
	resp.Body.Close()
	conn.Close()

	time.Sleep(300 * time.Millisecond)
	tx, rx, _ := store.UserStats("alice")
	if tx == 0 && rx == 0 {
		t.Fatal("expected traffic logged")
	}
	t.Logf("traffic: tx=%d rx=%d", tx, rx)
}
