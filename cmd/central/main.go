package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"mscope-hysteria/internal/control"
)

func main() {
	var (
		listen      = flag.String("listen", "0.0.0.0:38472", "control channel listen address for edges to connect to")
		usersFile   = flag.String("users-file", "", "path to JSON file with user grants (see users.json.example)")
		privPath    = flag.String("priv", "central.priv", "central private key (PEM, Ed25519)")
		centralID   = flag.String("id", "central-dev", "central identifier")
		sni         = flag.String("sni", "hysteria-internal", "SNI for generated data-plane cert")
		masq        = flag.String("masq", "https://example.com", "masquerade URL hint")
		tcpMbps     = flag.Int("tcpmbps", 100, "TCP bandwidth cap (Mbps)")
		genKey      = flag.Bool("gen-key", false, "generate a new central keypair and exit")
		certTTL     = flag.Duration("cert-ttl", 24*time.Hour, "cert lifetime; rotation period is half of this")
		serverPub   = flag.String("server-pub", "", "public server address clients connect to (e.g. hysteria.example.com:443)")
		serverListen = flag.String("server-listen", "0.0.0.0:443", "data plane listen address the edge should bind")
		disableUDP  = flag.Bool("disable-udp", false, "disable UDP forwarding on the edge")
		ignoreClientBW = flag.Bool("ignore-client-bw", false, "ignore client bandwidth claims")
		congestion   = flag.String("congestion", "", "congestion control: 'bbr' or 'brutal' (empty = hysteria default)")
		bbrProfile  = flag.String("bbr-profile", "", "BBR profile (e.g. 'default', 'low_latency')")
		quicStreamWin = flag.Uint64("quic-stream-rcv-win", 0, "QUIC initial stream receive window (default 8388608)")
		quicMaxStreamWin = flag.Uint64("quic-max-stream-rcv-win", 0, "QUIC max stream receive window")
		quicConnWin   = flag.Uint64("quic-conn-rcv-win", 0, "QUIC initial connection receive window (default 20971520)")
		quicMaxConnWin = flag.Uint64("quic-max-conn-rcv-win", 0, "QUIC max connection receive window")
		quicIdleTimeout = flag.String("quic-idle-timeout", "", "QUIC max idle timeout (e.g. '30s')")
		quicMaxStreams = flag.Int64("quic-max-streams", 0, "QUIC max incoming streams (default 1024)")
		quicDisableMTU = flag.Bool("quic-disable-mtu", false, "disable QUIC path MTU discovery")
		realmRelay  = flag.String("realm-relay", "", "realm relay URL to push to edge (e.g. https://relay.example.com); empty = no realm")
		realmID     = flag.String("realm-id", "", "realm id the edge should register under")
		realmToken  = flag.String("realm-token", "", "bearer token for the realm relay")
		realmSTUN   = flag.String("realm-stun", "", "comma-separated STUN servers for the edge to discover its public address (e.g. stun:stun.l.google.com:19302); empty = use built-in defaults")
		realmStatic = flag.String("realm-static-addr", "", "static public address for the edge (e.g. 1.2.3.4:443); use when the edge has a known stable public IP, skips STUN entirely")
	)
	flag.Parse()

	if *genKey {
		if err := writeKeypair(*privPath); err != nil {
			log.Fatalf("gen-key: %v", err)
		}
		log.Printf("wrote keypair to %s and certs/central.pub", *privPath)
		return
	}

	grants := loadGrants(*usersFile)

	priv, err := loadPriv(*privPath)
	if err != nil {
		log.Fatalf("load priv: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	log.Printf("central %s, pubkey %x", *centralID, pub)

	realmPayload := control.RealmPayload{
		RelayURL:   *realmRelay,
		RealmID:    *realmID,
		Token:      *realmToken,
		STUN:       normalizeSTUN(splitCSVNonEmpty(*realmSTUN)),
		StaticAddr: *realmStatic,
		Disabled:   *realmRelay == "" || *realmID == "",
	}
	if len(realmPayload.STUN) == 0 && realmPayload.StaticAddr == "" && !realmPayload.Disabled {
		realmPayload.STUN = defaultSTUNServers
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serverCfg := control.ServerConfig{
		Listen:                *serverListen,
		CertSNI:               *sni,
		TCPMbps:               *tcpMbps,
		UDPIdleSecs:           60,
		MasqDomain:            *masq,
		DisableUDP:            *disableUDP,
		IgnoreClientBandwidth: *ignoreClientBW,
		CongestionType:        *congestion,
		BBRProfile:            *bbrProfile,
		QUICStreamRcvWin:      *quicStreamWin,
		QUICMaxStreamRcvWin:   *quicMaxStreamWin,
		QUICConnRcvWin:        *quicConnWin,
		QUICMaxConnRcvWin:     *quicMaxConnWin,
		QUICMaxIdleTimeout:    *quicIdleTimeout,
		QUICMaxIncomingStreams: *quicMaxStreams,
		QUICDisablePathMTU:    *quicDisableMTU,
	}

	opts := centralOpts{
		priv:         priv,
		centralID:    *centralID,
		certTTL:      *certTTL,
		serverPub:    *serverPub,
		realmPayload: realmPayload,
		grants:       grants,
		serverCfg:    serverCfg,
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen %s: %v", *listen, err)
	}
	log.Printf("central: listening on %s for edge connections, %d grant(s)", ln.Addr(), len(grants.Grants))

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("central: accept: %v", err)
			continue
		}
		go handleEdge(ctx, conn, opts)
	}
}

type centralOpts struct {
	priv         ed25519.PrivateKey
	centralID    string
	certTTL      time.Duration
	serverPub    string
	realmPayload control.RealmPayload
	grants       control.GrantsPayload
	serverCfg    control.ServerConfig
}

func handleEdge(ctx context.Context, conn net.Conn, o centralOpts) {
	remote := conn.RemoteAddr()
	log.Printf("edge: incoming from %s", remote)

	if err := control.CentralHandshake(conn, o.priv); err != nil {
		log.Printf("edge: %s handshake failed: %v", remote, err)
		conn.Close()
		return
	}
	log.Printf("edge: %s handshake OK", remote)

	tlsCfg, err := control.NewServerTLSConfig(o.priv, o.serverCfg.CertSNI)
	if err != nil {
		log.Printf("edge: %s tls config: %v", remote, err)
		conn.Close()
		return
	}
	tlsConn := tls.Server(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("edge: %s tls handshake failed: %v", remote, err)
		conn.Close()
		return
	}
	log.Printf("edge: %s tls established", remote)

	ch := control.NewChannel(tlsConn, control.Handlers{
		OnError: func(p control.ErrorPayload) error {
			log.Printf("edge %s error: %s %s", remote, p.Code, p.Message)
			return nil
		},
	}, "central")
	go ch.Run(ctx)

	ch.Send(control.MsgHello, control.HelloPayload{
		CentralID: o.centralID, ProtocolVersion: 1,
	})

	cfg := control.ConfigPayload{Version: 1, Config: o.serverCfg}
	ch.Send(control.MsgConfig, cfg)

	der, keyDER, tmpl, err := generateSelfSignedCert(o.serverCfg.CertSNI, o.certTTL)
	if err == nil {
		pin := hex.EncodeToString(sha256Sum(der))
		ch.Send(control.MsgCert, control.CertPayload{
			Serial:    fmt.Sprintf("%d", tmpl.SerialNumber),
			NotBefore: tmpl.NotBefore,
			NotAfter:  tmpl.NotAfter,
			CertDER:   der,
			KeyDER:    keyDER,
			PinSHA256: pin,
		})
	}

	ch.Send(control.MsgGrants, o.grants)
	ch.Send(control.MsgRealm, o.realmPayload)

	log.Printf("edge: %s push complete, holding", remote)
	<-ctx.Done()
	conn.Close()
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

type runOnceOpts struct {
	edgeAddr     string
	priv         ed25519.PrivateKey
	centralID    string
	certTTL      time.Duration
	serverPub    string
	realmPayload control.RealmPayload
	grants       control.GrantsPayload
	serverCfg    control.ServerConfig
}

func runOnce(ctx context.Context, o runOnceOpts) error {
	conn, err := net.Dial("tcp", o.edgeAddr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	if err := control.CentralHandshake(conn, o.priv); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	log.Printf("handshake OK with %s", conn.RemoteAddr())

	tlsCfg, err := control.NewServerTLSConfig(o.priv, o.serverCfg.CertSNI)
	if err != nil {
		return fmt.Errorf("tls config: %w", err)
	}
	tlsConn := tls.Server(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("tls handshake: %w", err)
	}
	log.Printf("tls established with %s", tlsConn.RemoteAddr())

	ch := control.NewChannel(tlsConn, control.Handlers{
		OnError: func(p control.ErrorPayload) error {
			log.Printf("edge %s error: %s %s", o.edgeAddr, p.Code, p.Message)
			return nil
		},
	}, "central")
	go ch.Run(ctx)

	if err := ch.Send(control.MsgHello, control.HelloPayload{
		CentralID: o.centralID, ProtocolVersion: 1,
	}); err != nil {
		return err
	}
	if err := sendConfig(ch, o); err != nil {
		return err
	}
	if err := sendCert(ch, o); err != nil {
		return err
	}
	if err := sendGrants(ch, o); err != nil {
		return err
	}
	if err := sendRealm(ch, o.realmPayload); err != nil {
		return err
	}

	log.Printf("central: initial push complete, holding connection")
	<-ctx.Done()
	return nil
}

func sendConfig(ch *control.Channel, o runOnceOpts) error {
	cfg := control.ConfigPayload{
		Version: 1,
		Config:  o.serverCfg,
	}
	if err := ch.Send(control.MsgConfig, cfg); err != nil {
		return err
	}
	log.Printf("sent config v1 (listen=%s, sni=%s, tcpmbps=%d)", o.serverCfg.Listen, o.serverCfg.CertSNI, o.serverCfg.TCPMbps)
	return nil
}

func sendCert(ch *control.Channel, o runOnceOpts) error {
	der, keyDER, tmpl, err := generateSelfSignedCert(o.serverCfg.CertSNI, o.certTTL)
	if err != nil {
		return err
	}

	pinSum := sha256.Sum256(der)
	pinHex := hex.EncodeToString(pinSum[:])

	payload := control.CertPayload{
		Serial:    fmt.Sprintf("%d", tmpl.SerialNumber),
		NotBefore: tmpl.NotBefore,
		NotAfter:  tmpl.NotAfter,
		CertDER:   der,
		KeyDER:    keyDER,
		PinSHA256: pinHex,
	}
	if err := ch.Send(control.MsgCert, payload); err != nil {
		return err
	}
	log.Printf("sent cert serial=%s, pin=%s, not_after=%s", payload.Serial, pinHex, tmpl.NotAfter.Format(time.RFC3339))
	return nil
}

func sendGrants(ch *control.Channel, o runOnceOpts) error {
	if err := ch.Send(control.MsgGrants, o.grants); err != nil {
		return err
	}
	log.Printf("sent grants v1 (%d users)", len(o.grants.Grants))
	return nil
}

func loadGrants(path string) control.GrantsPayload {
	if path == "" {
		return control.GrantsPayload{
			Version: 1,
			Grants: []control.UserGrant{
				{UserID: "alice", Secret: "s3cret-alice", MaxClients: 2, ExpiresAt: time.Now().Add(48 * time.Hour)},
				{UserID: "bob", Secret: "s3cret-bob", MaxClients: 1, ExpiresAt: time.Now().Add(48 * time.Hour)},
			},
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("grants file: %v", err)
	}
	var p control.GrantsPayload
	if err := json.Unmarshal(b, &p); err != nil {
		log.Fatalf("grants file: %v", err)
	}
	return p
}

func sendRealm(ch *control.Channel, p control.RealmPayload) error {
	if err := ch.Send(control.MsgRealm, p); err != nil {
		return err
	}
	if p.Disabled {
		log.Printf("sent realm (disabled)")
	} else {
		log.Printf("sent realm (relay=%s, id=%s, stun=%d, static=%q)", p.RelayURL, p.RealmID, len(p.STUN), p.StaticAddr)
	}
	return nil
}

func generateSelfSignedCert(sni string, ttl time.Duration) ([]byte, []byte, *x509.Certificate, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      pkix.Name{CommonName: sni},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{sni},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, nil, err
	}
	return der, keyDER, tmpl, nil
}

func writeKeypair(path string) error {
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

func mustPKCS8(priv ed25519.PrivateKey) []byte {
	b, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		panic(err)
	}
	return b
}

func loadPriv(path string) (ed25519.PrivateKey, error) {
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

func splitCSVNonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func normalizeSTUN(servers []string) []string {
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		s = strings.TrimPrefix(s, "stun:")
		s = strings.TrimPrefix(s, "stuns:")
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Default STUN servers — same as upstream Hysteria (chosen for restricted regions).
// Ref: https://ip.skk.moe/stun
var defaultSTUNServers = []string{
	"stun.nextcloud.com:3478",
	"stun.sip.us:3478",
	"global.stun.twilio.com:3478",
}
