package certvault

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func newTestCert(t testing.TB) ([]byte, []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return der, keyDER
}

func TestInstallAndGet(t *testing.T) {
	v := New()
	der, keyDER := newTestCert(t)

	if err := v.InstallFromDER(der, keyDER); err != nil {
		t.Fatalf("Install: %v", err)
	}

	if !v.HasCert() {
		t.Error("HasCert should be true after install")
	}

	cert, err := v.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("GetCertificate returned nil")
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("cert has no Certificate bytes")
	}

	// Verify the cert DER matches what we installed
	h := sha256.Sum256(cert.Certificate[0])
	expected := sha256.Sum256(der)
	if h != expected {
		t.Error("certificate bytes changed after install+retrieve")
	}
}

func TestGetCertificate_NoCert(t *testing.T) {
	v := New()
	_, err := v.GetCertificate(&tls.ClientHelloInfo{})
	if err == nil {
		t.Error("expected error when no cert installed")
	}
}

func TestReplaceCert(t *testing.T) {
	v := New()
	der1, key1 := newTestCert(t)
	der2, key2 := newTestCert(t)

	v.InstallFromDER(der1, key1)
	cert1, _ := v.GetCertificate(nil)

	v.InstallFromDER(der2, key2)
	cert2, _ := v.GetCertificate(nil)

	if sha256.Sum256(cert1.Certificate[0]) == sha256.Sum256(cert2.Certificate[0]) {
		t.Error("certs should be different after re-install")
	}
}

func TestExpiresAt(t *testing.T) {
	v := New()
	der, key := newTestCert(t)
	v.InstallFromDER(der, key)

	exp := v.ExpiresAt()
	if exp.IsZero() {
		t.Error("ExpiresAt should not be zero")
	}
	if time.Until(exp) < 20*time.Hour {
		t.Errorf("expected expiry >20h from now, got %v", time.Until(exp))
	}
}

func TestCurrentCertificate(t *testing.T) {
	v := New()
	if v.Current() != nil {
		t.Error("Current should be nil before install")
	}

	der, key := newTestCert(t)
	v.InstallFromDER(der, key)

	leaf := v.Current()
	if leaf == nil {
		t.Fatal("Current should return leaf after install")
	}
	if leaf.Subject.CommonName != "test" {
		t.Errorf("got CN=%q, want %q", leaf.Subject.CommonName, "test")
	}
}

func TestInstallFromDER_RejectsEmptyCert(t *testing.T) {
	v := New()
	err := v.InstallFromDER(nil, []byte("garbage"))
	if err == nil {
		t.Error("expected error for nil cert DER")
	}
}

func BenchmarkGetCertificate(b *testing.B) {
	v := New()
	der, key := newTestCert(b)
	v.InstallFromDER(der, key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.GetCertificate(nil)
	}
}
