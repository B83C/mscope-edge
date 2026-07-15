package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os/signal"
	"syscall"
	"time"

	"github.com/B83C/mscope-edge/pkg/control"
)

func main() {
	listenAddr := flag.String("listen", ":38473", "listen address")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}

	pubRaw := priv.Public().(ed25519.PublicKey)
	log.Printf("central pub key (base64): %s", base64.StdEncoding.EncodeToString(pubRaw))

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("mock-central listening on %s", *listenAddr)

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			return
		}
		go handleEdge(conn, priv)
	}
}

func handleEdge(conn net.Conn, priv ed25519.PrivateKey) {
	defer conn.Close()
	remote := conn.RemoteAddr()
	log.Printf("edge from %s", remote)

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})

	if err := control.CentralHandshake(conn, priv); err != nil {
		log.Printf("handshake: %v", err)
		return
	}

	tlsCfg, err := control.NewServerTLSConfig(priv, "hysteria-internal")
	if err != nil {
		log.Printf("tls config: %v", err)
		return
	}
	tlsConn := tls.Server(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("tls: %v", err)
		return
	}

	identCh := make(chan string, 1)
	var id string // set after identify via identCh
	var ch *control.Channel

	ch = control.NewChannel(tlsConn, control.Handlers{
		OnIdentify: func(p control.IdentifyPayload) error {
			select {
			case identCh <- p.DeviceID:
			default:
			}
			log.Printf("identity: device=%s name=%s pub=%v local=%v",
				p.DeviceID, p.Name, p.PublicIPs, p.LocalIPs)
			return nil
		},
		OnHeartbeat: func(p control.HeartbeatPayload) error {
			log.Printf("heartbeat from %s: uptime=%d conns=%d", id, p.Uptime, p.ConnCount)
			return nil
		},
		OnAuthRequest: func(p control.AuthRequestPayload) error {
			log.Printf("auth req: user=%s OK", p.UserID)
			ch.Send(control.MsgAuthResponse, control.AuthResponsePayload{
				RequestID: p.RequestID, OK: true, UserID: p.UserID,
			})
			return nil
		},
		OnDisconnected: func(p control.DisconnectedPayload) error {
			log.Printf("disconnected: user=%s", p.UserID)
			return nil
		},
		OnTrafficReport: func(p control.TrafficReportPayload) error {
			log.Printf("traffic: %d users", len(p.Users))
			return nil
		},
		OnError: func(p control.ErrorPayload) error {
			log.Printf("error from edge: %s", p.Message)
			return nil
		},
	}, "mock-central")

	go ch.Run(context.Background())

	select {
	case id = <-identCh:
	case <-time.After(30 * time.Second):
		log.Printf("identify timeout")
		return
	case <-ch.Done():
		return
	}

	if id == "" {
		return
	}

	ch.Send(control.MsgAccept, control.AcceptPayload{Message: "auto-approved"})
	log.Printf("auto-approved edge %s", id)

	cfg := control.ServerConfig{
		Listen:                "0.0.0.0:8445",
		MasqDomain:            "hackernews.com",
		CertSNI:               "hackernews.com",
		TCPMbps:               100,
		UDPIdleSecs:           60,
		IgnoreClientBandwidth: false,
		DisableUDP:            false,
		QUICMaxIdleTimeout:    "30s",
		QUICMaxIncomingStreams: 1024,
	}
	ch.Send(control.MsgConfig, control.ConfigPayload{Version: 1, Config: cfg})
	log.Printf("pushed config: listen=%s masq=%s", cfg.Listen, cfg.MasqDomain)

	serial := fmt.Sprintf("%d", time.Now().Unix())
	der, kd, pinRaw := generateCert(priv, "hackernews.com")
	pin := hex.EncodeToString(pinRaw[:])
	ch.Send(control.MsgCert, control.CertPayload{
		Serial:    serial,
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(720 * time.Hour),
		CertDER:   der,
		KeyDER:    kd,
		PinSHA256: pin,
	})
	log.Printf("pushed cert: serial=%s pin=%s (full)", serial, pin)

	ch.Send(control.MsgGrants, control.GrantsPayload{
		Version: uint64(time.Now().Unix()),
		Grants: []control.UserGrant{
			{UserID: "test", Secret: "test123", MaxClients: 3, ExpiresAt: time.Now().Add(365 * 24 * time.Hour)},
			{UserID: "demo", Secret: "demo456", MaxClients: 1, ExpiresAt: time.Now().Add(365 * 24 * time.Hour)},
		},
	})
	log.Printf("pushed 2 grants (test, demo)")

	<-ch.Done()
	log.Printf("edge %s disconnected", id)
}

func generateCert(priv ed25519.PrivateKey, sni string) (certDER, keyDER []byte, pinSHA256 [32]byte) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      pkix.Name{CommonName: sni},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(720 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{sni, "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	certPub, certPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, [32]byte{}
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, certPub, certPriv)
	if err != nil {
		return nil, nil, [32]byte{}
	}
	privBytes, _ := x509.MarshalPKCS8PrivateKey(certPriv)
	pinSHA256 = sha256.Sum256(derBytes)
	return derBytes, privBytes, pinSHA256
}
