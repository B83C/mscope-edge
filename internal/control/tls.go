package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/subtle"
	"errors"
	"crypto/tls"
	"fmt"
	"math/big"
	"time"
)

func NewServerTLSConfig(priv ed25519.PrivateKey, sni string) (*tls.Config, error) {
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      pkix.Name{CommonName: sni},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{sni},
	}, &x509.Certificate{}, priv.Public(), priv)
	if err != nil {
		return nil, fmt.Errorf("control: create TLS cert: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  priv,
		}},
		MinVersion: tls.VersionTLS13,
	}, nil
}

func VerifyPeerPubkey(expected ed25519.PublicKey) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("control: no server certificate")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("control: parse cert: %w", err)
		}
		got, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("control: server cert key is not Ed25519")
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
			return errors.New("control: server cert pubkey does not match baked-in central key")
		}
		return nil
	}
}

func NewClientTLSConfig(expectedPub ed25519.PublicKey) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: VerifyPeerPubkey(expectedPub),
		MinVersion:            tls.VersionTLS13,
	}
}
