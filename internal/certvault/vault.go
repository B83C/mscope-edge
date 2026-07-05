package certvault

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type Vault struct {
	mu      sync.RWMutex
	current atomic.Pointer[entry]
}

type entry struct {
	cert     tls.Certificate
	certLeaf *x509.Certificate
	expires  time.Time
}

func New() *Vault {
	return &Vault{}
}

func (v *Vault) Install(certPEM, keyPEM []byte) error {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("vault: parse keypair: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("vault: no certificate in pair")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("vault: parse leaf: %w", err)
	}
	e := &entry{cert: cert, certLeaf: leaf, expires: leaf.NotAfter}
	v.mu.Lock()
	v.current.Store(e)
	v.mu.Unlock()
	return nil
}

func (v *Vault) InstallFromDER(certDER, keyDER []byte) error {
	if len(certDER) == 0 {
		return fmt.Errorf("vault: empty cert DER")
	}
	if len(keyDER) == 0 {
		return fmt.Errorf("vault: empty key DER")
	}
	key, err := parseKey(keyDER)
	if err != nil {
		return fmt.Errorf("vault: parse key: %w", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("vault: parse leaf: %w", err)
	}
	e := &entry{cert: cert, certLeaf: leaf, expires: leaf.NotAfter}
	v.mu.Lock()
	v.current.Store(e)
	v.mu.Unlock()
	return nil
}

func parseKey(der []byte) (any, error) {
	if l := len(der); l == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(der), nil
	}
	return x509.ParsePKCS8PrivateKey(der)
}

func (v *Vault) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	v.mu.RLock()
	e := v.current.Load()
	v.mu.RUnlock()
	if e == nil {
		return nil, fmt.Errorf("vault: no certificate installed")
	}
	return &e.cert, nil
}

func (v *Vault) Current() *x509.Certificate {
	v.mu.RLock()
	defer v.mu.RUnlock()
	e := v.current.Load()
	if e == nil {
		return nil
	}
	return e.certLeaf
}

func (v *Vault) ExpiresAt() time.Time {
	v.mu.RLock()
	defer v.mu.RUnlock()
	e := v.current.Load()
	if e == nil {
		return time.Time{}
	}
	return e.expires
}

func (v *Vault) HasCert() bool {
	return v.current.Load() != nil
}


