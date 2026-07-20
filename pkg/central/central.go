package central

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"time"
)

func GenerateCert(sni string, ttl time.Duration) (der, keyDER []byte, pinHex string, tmpl *x509.Certificate, err error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", nil, err
	}

	tmpl = &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      pkix.Name{CommonName: sni},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{sni},
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("create cert: %w", err)
	}
	keyDER, err = x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("marshal key: %w", err)
	}
	sum := sha256.Sum256(der)
	pinHex = fmt.Sprintf("%x", sum)
	return
}

func PubkeyRawB64() (string, error) {
	b, err := os.ReadFile("certs/central.pub")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
