package central

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"mscope-hysteria/pkg/control"
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
	block, _ := pem.Decode(b)
	if block == nil {
		return "", fmt.Errorf("no PEM block in certs/central.pub")
	}
	return base64.StdEncoding.EncodeToString(block.Bytes), nil
}

func GenerateKeypair(path string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(priv)})
	if err := os.WriteFile(path, privPEM, 0600); err != nil {
		return err
	}
	if err := os.MkdirAll("certs", 0755); err != nil {
		return err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})
	return os.WriteFile("certs/central.pub", pubPEM, 0644)
}

func LoadKeypair(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an Ed25519 key")
	}
	return priv, nil
}

func LoadGrants(path string) (control.GrantsPayload, error) {
	if path == "" {
		return control.GrantsPayload{}, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return control.GrantsPayload{}, fmt.Errorf("grants file: %w", err)
	}
	var p control.GrantsPayload
	if err := json.Unmarshal(b, &p); err != nil {
		return control.GrantsPayload{}, fmt.Errorf("grants parse: %w", err)
	}
	return p, nil
}

func BuildRealmPayload(relayURL, realmID, token string, stun []string, staticAddr string) control.RealmPayload {
	disabled := relayURL == "" || realmID == ""
	return control.RealmPayload{
		RelayURL:   relayURL,
		RealmID:    realmID,
		Token:      token,
		STUN:       stun,
		StaticAddr: staticAddr,
		Disabled:   disabled,
	}
}

type Server struct {
	EdgeAddr string
	Priv     ed25519.PrivateKey
	Pub      ed25519.PublicKey
}

func Dial(ctx context.Context, addr string, priv ed25519.PrivateKey) (*control.Channel, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	if err := control.CentralHandshake(conn, priv); err != nil {
		conn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}

	tlsCfg, err := control.NewServerTLSConfig(priv, "hysteria-internal")
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("tls config: %w", err)
	}
	tlsConn := tls.Server(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	ch := control.NewChannel(tlsConn, control.Handlers{}, "central")
	go ch.Run(ctx)

	return ch, nil
}

func PushHello(ch *control.Channel, id string) error {
	return ch.Send(control.MsgHello, control.HelloPayload{
		CentralID: id, ProtocolVersion: 1,
	})
}

func PushConfig(ch *control.Channel, cfg control.ServerConfig) error {
	return ch.Send(control.MsgConfig, control.ConfigPayload{
		Version: 1, Config: cfg,
	})
}

func PushCert(ch *control.Channel, sni string, ttl time.Duration) (pin string, err error) {
	der, keyDER, pin, _, err := GenerateCert(sni, ttl)
	if err != nil {
		return "", err
	}
	return pin, ch.Send(control.MsgCert, control.CertPayload{
		Serial:    fmt.Sprintf("%d", time.Now().Unix()),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(ttl),
		CertDER:   der,
		KeyDER:    keyDER,
		PinSHA256: pin,
	})
}

func PushGrants(ch *control.Channel, g control.GrantsPayload) error {
	return ch.Send(control.MsgGrants, g)
}

func PushRealm(ch *control.Channel, r control.RealmPayload) error {
	return ch.Send(control.MsgRealm, r)
}

func mustPKCS8(priv ed25519.PrivateKey) []byte {
	b, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		panic(err)
	}
	return b
}
