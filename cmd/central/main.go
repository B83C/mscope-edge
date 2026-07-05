package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"mscope-hysteria/pkg/control"
	"mscope-hysteria/pkg/central"
)

func main() {
	var (
		listen       = flag.String("listen", "0.0.0.0:38472", "control channel listen address for edges")
		usersFile    = flag.String("users-file", "", "path to JSON grants file (see users.json.example)")
		whitelistFile = flag.String("whitelist-file", "", "path to JSON file with allowed device IDs")
		privPath     = flag.String("priv", "central.priv", "central Ed25519 private key (PEM)")
		centralID    = flag.String("id", "central-dev", "central identifier")
		sni         = flag.String("sni", "hysteria-internal", "SNI for data-plane cert")
		masq        = flag.String("masq", "https://example.com", "masquerade URL")
		tcpMbps     = flag.Int("tcpmbps", 100, "TCP bandwidth cap (Mbps)")
		genKey      = flag.Bool("gen-key", false, "generate keypair and exit")
		certTTL     = flag.Duration("cert-ttl", 24*time.Hour, "cert TTL")
		serverListen = flag.String("server-listen", "0.0.0.0:443", "data plane listen address")
		disableUDP  = flag.Bool("disable-udp", false, "disable UDP")
		ignoreBw    = flag.Bool("ignore-client-bw", false, "ignore client bandwidth")
		congestion  = flag.String("congestion", "", "congestion: bbr or empty")
		bbrProfile  = flag.String("bbr-profile", "", "BBR profile")
		qStreamWin  = flag.Uint64("quic-stream-rcv-win", 0, "")
		qMaxStream  = flag.Uint64("quic-max-stream-rcv-win", 0, "")
		qConnWin    = flag.Uint64("quic-conn-rcv-win", 0, "")
		qMaxConn    = flag.Uint64("quic-max-conn-rcv-win", 0, "")
		qIdle       = flag.String("quic-idle-timeout", "", "")
		qMaxStreams = flag.Int64("quic-max-streams", 0, "")
		qDisableMTU = flag.Bool("quic-disable-mtu", false, "")
		rRelay      = flag.String("realm-relay", "", "realm relay URL")
		rID         = flag.String("realm-id", "", "realm id")
		rToken      = flag.String("realm-token", "", "realm token")
		rSTUN       = flag.String("realm-stun", "", "STUN servers (comma-separated)")
		rStatic     = flag.String("realm-static-addr", "", "static public address")
	)
	flag.Parse()

	if *genKey {
		if err := central.GenerateKeypair(*privPath); err != nil {
			log.Fatal(err)
		}
		b64, err := central.PubkeyRawB64()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("PUBKEY_B64=%s\n", b64)
		return
	}

	priv, err := central.LoadKeypair(*privPath)
	if err != nil {
		log.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	log.Printf("central %s pubkey %x", *centralID, pub)

	grants, err := central.LoadGrants(*usersFile)
	if err != nil {
		log.Fatal(err)
	}

	whitelist := loadWhitelist(*whitelistFile)

	realmPayload := central.BuildRealmPayload(*rRelay, *rID, *rToken, splitSTUN(*rSTUN), *rStatic)

	serverCfg := control.ServerConfig{
		Listen:                *serverListen,
		CertSNI:               *sni,
		TCPMbps:               *tcpMbps,
		UDPIdleSecs:           60,
		MasqDomain:            *masq,
		DisableUDP:            *disableUDP,
		IgnoreClientBandwidth: *ignoreBw,
		CongestionType:        *congestion,
		BBRProfile:            *bbrProfile,
		QUICStreamRcvWin:      *qStreamWin,
		QUICMaxStreamRcvWin:   *qMaxStream,
		QUICConnRcvWin:        *qConnWin,
		QUICMaxConnRcvWin:     *qMaxConn,
		QUICMaxIdleTimeout:    *qIdle,
		QUICMaxIncomingStreams: *qMaxStreams,
		QUICDisablePathMTU:    *qDisableMTU,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s, %d grant(s)", ln.Addr(), len(grants.Grants))

	go func() { <-ctx.Done(); ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("accept: %v", err)
			continue
		}
		go handleEdge(ctx, conn, priv, &serverCfg, &grants, &realmPayload, whitelist, *sni, *certTTL, *centralID)
	}
}

func handleEdge(ctx context.Context, conn net.Conn, priv ed25519.PrivateKey, cfg *control.ServerConfig, grants *control.GrantsPayload, realm *control.RealmPayload, whitelist map[string]bool, sni string, certTTL time.Duration, id string) {
	remote := conn.RemoteAddr()
	defer conn.Close()

	if err := control.CentralHandshake(conn, priv); err != nil {
		log.Printf("edge %s handshake: %v", remote, err)
		return
	}
	log.Printf("edge %s handshake OK", remote)

	tlsCfg, err := control.NewServerTLSConfig(priv, sni)
	if err != nil {
		log.Printf("edge %s tls config: %v", remote, err)
		return
	}
	tlsConn := tls.Server(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("edge %s tls: %v", remote, err)
		return
	}

	var edgeIdentity control.IdentifyPayload
	identified := make(chan struct{})

	ch := control.NewChannel(tlsConn, control.Handlers{
		OnIdentify: func(p control.IdentifyPayload) error {
			edgeIdentity = p
			close(identified)
			return nil
		},
		OnError: func(p control.ErrorPayload) error {
			log.Printf("edge %s error: %s %s", remote, p.Code, p.Message)
			return nil
		},
	}, "central")
	go ch.Run(ctx)

	// Wait for identification
	select {
	case <-identified:
	case <-time.After(10 * time.Second):
		log.Printf("edge %s identify timeout", remote)
		ch.Send(control.MsgReject, control.RejectPayload{Reason: "identify timeout"})
		return
	}

	log.Printf("edge %s identified: device=%s name=%s ip=%s", remote, edgeIdentity.DeviceID, edgeIdentity.Name, edgeIdentity.PublicIP)

	// Check whitelist
	if len(whitelist) > 0 {
		if !whitelist[edgeIdentity.DeviceID] {
			log.Printf("edge %s device %s NOT in whitelist, rejecting", remote, edgeIdentity.DeviceID)
			ch.Send(control.MsgReject, control.RejectPayload{Reason: "device not in whitelist"})
			return
		}
		log.Printf("edge %s device %s whitelisted, accepting", remote, edgeIdentity.DeviceID)
	}

	ch.Send(control.MsgAccept, control.AcceptPayload{Message: "welcome"})
	central.PushHello(ch, id)
	central.PushConfig(ch, *cfg)
	central.PushCert(ch, sni, certTTL)
	central.PushGrants(ch, *grants)
	central.PushRealm(ch, *realm)
	log.Printf("edge %s complete, holding", remote)
	<-ctx.Done()
}

func loadWhitelist(path string) map[string]bool {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("whitelist file: %v", err)
	}
	var ids []string
	if err := json.Unmarshal(b, &ids); err != nil {
		log.Fatalf("whitelist parse: %v", err)
	}
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	log.Printf("whitelist loaded: %d device(s)", len(ids))
	return m
}

func splitSTUN(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimPrefix(strings.TrimSpace(p), "stun:")
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
