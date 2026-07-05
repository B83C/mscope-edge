package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	hcore "github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/outbounds/speedtest"
	"github.com/apernet/hysteria/extras/v2/realm"
	"mscope-hysteria/internal/auth"
	"mscope-hysteria/internal/certvault"
	"mscope-hysteria/internal/configsource"
	"mscope-hysteria/pkg/control"
)

func main() {
	var (
		centralAddr = flag.String("central-addr", "127.0.0.1:38472", "central server address to dial")
		centralPub  = flag.String("central-pub", "certs/central.pub", "path to central public key (PEM)")
		edgeID      = flag.String("edge-id", "", "edge identifier (default: hostname)")
		dataListen  = flag.String("data-listen", "0.0.0.0:443", "hysteria data plane listen address")
	)
	flag.Parse()

	if *edgeID == "" {
		h, err := os.Hostname()
		if err != nil {
			log.Fatalf("hostname: %v", err)
		}
		*edgeID = h
	}

	pub, err := loadCentralPub(*centralPub)
	if err != nil {
		log.Fatalf("load central pub: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	e := &edge{
		centralPub: pub,
		edgeID:     *edgeID,
		dataListen: *dataListen,
		vault:      certvault.New(),
		cfgSrc:     configsource.New(),
		auth:       auth.NewStore(),
	}
	if err := e.run(ctx, *centralAddr); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("edge: %v", err)
	}
}

type edge struct {
	centralPub ed25519.PublicKey
	edgeID     string
	dataListen string

	vault  *certvault.Vault
	cfgSrc *configsource.Source
	auth   *auth.Store

	mu       sync.Mutex
	srv      hcore.Server
	hCfg     *hcore.Config
	srvReady bool
	lastCold string

	udpConn    *net.UDPConn
	punchConn  *realm.PunchPacketConn

	centralMu     sync.Mutex
	centralActive bool

	realmMu     sync.Mutex
	realmCancel context.CancelFunc
	realmCfg    realmConfig

	masqAtomic *atomicHandler

	readyCh chan struct{}
	stopped chan struct{}
}

func (e *edge) run(ctx context.Context, centralAddr string) error {
	e.readyCh = make(chan struct{})
	e.stopped = make(chan struct{})

	go e.serveDataPlane(ctx)

	log.Printf("control: dialing central at %s, edge id %s", centralAddr, e.edgeID)

	for {
		if ctx.Err() != nil {
			<-e.stopped
			return ctx.Err()
		}

		conn, err := net.Dial("tcp", centralAddr)
		if err != nil {
			log.Printf("control: dial %s failed: %v (retry in 5s)", centralAddr, err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
			}
			continue
		}

		e.handleCentral(ctx, conn)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func (e *edge) handleCentral(ctx context.Context, conn net.Conn) {
	remote := conn.RemoteAddr()
	log.Printf("control: incoming connection from %s", remote)

	e.centralMu.Lock()
	if e.centralActive {
		e.centralMu.Unlock()
		log.Printf("control: rejecting second central connection from %s (already active)", remote)
		conn.Close()
		return
	}
	e.centralActive = true
	e.centralMu.Unlock()

	if err := control.EdgeHandshake(conn, e.centralPub); err != nil {
		log.Printf("control: handshake from %s failed: %v", remote, err)
		conn.Close()
		e.centralMu.Lock()
		e.centralActive = false
		e.centralMu.Unlock()
		return
	}
	log.Printf("control: handshake from %s OK", remote)

	tlsCfg := control.NewClientTLSConfig(e.centralPub)
	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("control: tls handshake from %s failed: %v", remote, err)
		conn.Close()
		e.centralMu.Lock()
		e.centralActive = false
		e.centralMu.Unlock()
		return
	}
	log.Printf("control: tls established with %s", remote)

	e.mu.Lock()
	e.lastCold = ""
	e.mu.Unlock()

	// Identification exchange: send device ID, wait for accept/reject
	identCh := make(chan error, 1)

	var ch *control.Channel
	ch = control.NewChannel(tlsConn, control.Handlers{
		OnAccept: func(p control.AcceptPayload) error {
			log.Printf("control: accepted by central: %s", p.Message)
			identCh <- nil
			return nil
		},
		OnReject: func(p control.RejectPayload) error {
			log.Printf("control: REJECTED by central: %s", p.Reason)
			identCh <- fmt.Errorf("rejected: %s", p.Reason)
			return nil
		},
		OnHello: func(p control.HelloPayload) error {
			log.Printf("control: hello from central %s (proto v%d)", p.CentralID, p.ProtocolVersion)
			return ch.Send(control.MsgAck, nil)
		},
		OnConfig: func(p control.ConfigPayload) error {
			log.Printf("control: config version %d received", p.Version)
			if err := e.applyConfig(ctx, p); err != nil {
				log.Printf("control: config apply error: %v", err)
				return err
			}
			return nil
		},
		OnCert: func(p control.CertPayload) error {
			log.Printf("control: cert serial=%s pin=%s not_after=%s",
				p.Serial, p.PinSHA256[:8]+"...", p.NotAfter.Format(time.RFC3339))
			if err := e.applyCert(ctx, p); err != nil {
				return err
			}
			return nil
		},
		OnGrants: func(p control.GrantsPayload) error {
			log.Printf("control: grants version %d, %d users", p.Version, len(p.Grants))
			e.auth.Apply(p)
			for _, g := range p.Grants {
				if g.MaxClients > 0 {
					e.auth.SetMaxClients(g.UserID, g.MaxClients)
				}
			}
			return nil
		},
		OnRevoke: func(p control.RevokePayload) error {
			log.Printf("control: revoke version %d, %d users", p.Version, len(p.Users))
			e.auth.Revoke(p)
			return nil
		},
		OnDrain: func(p control.DrainPayload) error {
			log.Printf("control: drain requested: %s", p.Reason)
			e.mu.Lock()
			e.shutdownServerLocked()
			e.lastCold = ""
			e.mu.Unlock()
			return nil
		},
		OnRealm: func(p control.RealmPayload) error {
			return e.applyRealm(ctx, p)
		},
		OnCentralGone: func() {
			log.Printf("control: central gone, data plane and realm continue serving (cert=%s)",
				e.vault.ExpiresAt().Format(time.RFC3339))
		},
	}, e.edgeID)

	go ch.Run(ctx)

	// Identify: send hardware ID, wait for central verdict
	ch.Send(control.MsgIdentify, control.IdentifyPayload{
		DeviceID: deviceID(),
		Name:     e.edgeID,
		PublicIP: remoteAddrIP(remote),
		Version:  1,
	})

	select {
	case err := <-identCh:
		if err != nil {
			tlsConn.Close()
			e.centralMu.Lock()
			e.centralActive = false
			e.centralMu.Unlock()
			return
		}
	case <-time.After(10 * time.Second):
		log.Printf("control: identify timeout")
		tlsConn.Close()
		e.centralMu.Lock()
		e.centralActive = false
		e.centralMu.Unlock()
		return
	}

	// Wait for channel to close (central disconnect)
	<-ch.Done()

	e.centralMu.Lock()
	e.centralActive = false
	e.centralMu.Unlock()
}

func (e *edge) applyConfig(ctx context.Context, p control.ConfigPayload) error {
	if err := e.cfgSrc.Apply(p); err != nil {
		return err
	}
	cfg, _ := e.cfgSrc.Current()
	cold := coldFingerprint(cfg.Config)
	e.mu.Lock()
	currentCold := e.lastCold
	haveServer := e.srv != nil
	e.mu.Unlock()

	if !haveServer {
		return e.maybeBuildServer(ctx)
	}
	if cold != currentCold {
		log.Printf("data: cold config changed (port), rebuilding server")
		return e.rebuildServer(ctx)
	}
	log.Printf("data: hot config change, mutating live server")
	return e.applyHotConfig(cfg.Config)
}

func (e *edge) applyCert(ctx context.Context, p control.CertPayload) error {
	if err := e.vault.InstallFromDER(p.CertDER, p.KeyDER); err != nil {
		return err
	}
	e.mu.Lock()
	haveServer := e.srv != nil
	e.mu.Unlock()
	if haveServer {
		log.Printf("data: cert rotated, next handshake picks up new cert (no restart)")
		return nil
	}
	return e.maybeBuildServer(ctx)
}

func (e *edge) maybeBuildServer(ctx context.Context) error {
	if !e.vault.HasCert() {
		log.Printf("data: waiting for cert before building server")
		return nil
	}
	if _, ok := e.cfgSrc.Current(); !ok {
		log.Printf("data: waiting for config before building server")
		return nil
	}
	return e.rebuildServer(ctx)
}

func (e *edge) applyHotConfig(c control.ServerConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.hCfg == nil {
		return nil
	}
	if c.TCPMbps > 0 {
		e.hCfg.BandwidthConfig.MaxTx = uint64(c.TCPMbps) * 1024 * 1024
	}
	if c.UDPIdleSecs > 0 {
		e.hCfg.UDPIdleTimeout = time.Duration(c.UDPIdleSecs) * time.Second
	}
	if c.MasqDomain != "" && e.masqAtomic != nil {
		e.masqAtomic.Set(redirectMasq(c.MasqDomain))
	}
	return nil
}

func (e *edge) rebuildServer(ctx context.Context) error {
	if !e.vault.HasCert() {
		return nil
	}
	cfg, ok := e.cfgSrc.Current()
	if !ok {
		return nil
	}

	listenAddr := e.dataListen
	if cfg.Config.Listen != "" {
		listenAddr = cfg.Config.Listen
	}
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("resolve udp %q: %w", listenAddr, err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen udp %q: %w", listenAddr, err)
	}

	// Only wrap in PunchPacketConn when realm is configured.
	// The demux loop adds decode overhead to every packet;
	// with realm disabled we skip it entirely.
	hasRealm := e.realmCfg.RelayURL != "" && e.realmCfg.RealmID != ""
	var connForHcore net.PacketConn = udpConn
	var punchConn *realm.PunchPacketConn
	if hasRealm {
		punchConn, err = realm.NewPunchPacketConn(udpConn, 16)
		if err != nil {
			udpConn.Close()
			return fmt.Errorf("punch conn: %w", err)
		}
		connForHcore = punchConn
	}

	c := cfg.Config

	e.masqAtomic = &atomicHandler{}
	e.masqAtomic.Set(redirectMasq(c.MasqDomain))

	hCfg := &hcore.Config{
		TLSConfig: hcore.TLSConfig{
			GetCertificate: e.vault.GetCertificate,
		},
		Conn:                 connForHcore,
		Outbound:             &directOutbound{},
		Authenticator:        e.auth,
		EventLogger:          e.auth,
		TrafficLogger:        e.auth,
		MasqHandler:          e.masqAtomic,
		IgnoreClientBandwidth: c.IgnoreClientBandwidth,
		DisableUDP:           c.DisableUDP,
		QUICConfig: hcore.QUICConfig{
			InitialStreamReceiveWindow:     maybe(c.QUICStreamRcvWin, 8388608),
			MaxStreamReceiveWindow:         maybe(c.QUICMaxStreamRcvWin, 8388608),
			InitialConnectionReceiveWindow: maybe(c.QUICConnRcvWin, 20971520),
			MaxConnectionReceiveWindow:     maybe(c.QUICMaxConnRcvWin, 20971520),
			MaxIncomingStreams:             maybe(c.QUICMaxIncomingStreams, 1024),
			MaxIdleTimeout:                 parseDuration(c.QUICMaxIdleTimeout, 30*time.Second),
			DisablePathMTUDiscovery:        c.QUICDisablePathMTU,
		},
		CongestionConfig: hcore.CongestionConfig{
			Type:       c.CongestionType,
			BBRProfile: c.BBRProfile,
		},
	}
	if c.UDPIdleSecs > 0 {
		hCfg.UDPIdleTimeout = time.Duration(c.UDPIdleSecs) * time.Second
	}
	if c.TCPMbps > 0 {
		hCfg.BandwidthConfig.MaxTx = uint64(c.TCPMbps) * 1024 * 1024
	}

	srv, err := hcore.NewServer(hCfg)
	if err != nil {
		udpConn.Close()
		return fmt.Errorf("new server: %w", err)
	}

	e.mu.Lock()
	e.udpConn = udpConn
	e.punchConn = punchConn
	e.mu.Unlock()
	e.startRealmIfConfigured()

	e.mu.Lock()
	e.shutdownServerLocked()
	e.srv = srv
	e.hCfg = hCfg
	e.lastCold = coldFingerprint(cfg.Config)
	wasReady := e.srvReady
	e.srvReady = true
	e.mu.Unlock()

	if !wasReady {
		select {
		case e.readyCh <- struct{}{}:
		default:
		}
	}
	log.Printf("data: server (re)built, cert expires %s, masq=%s, tcpmbps=%d",
		e.vault.ExpiresAt().Format(time.RFC3339), cfg.Config.MasqDomain, cfg.Config.TCPMbps)
	return nil
}

func coldFingerprint(c control.ServerConfig) string {
	return c.Listen + "|" + c.CertSNI
}

func (e *edge) serveDataPlane(ctx context.Context) {
	defer close(e.stopped)
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.readyCh:
		}
		e.mu.Lock()
		srv := e.srv
		e.mu.Unlock()
		if srv == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}
		log.Printf("data: serving")
		if err := srv.Serve(); err != nil {
			log.Printf("data: serve ended: %v", err)
		}
		e.mu.Lock()
		e.srvReady = false
		e.mu.Unlock()
	}
}

func (e *edge) shutdownServerLocked() {
	if e.srv != nil {
		e.srv.Close()
		e.srv = nil
		e.hCfg = nil
	}
}

func (e *edge) applyRealm(_ context.Context, p control.RealmPayload) error {
	e.realmMu.Lock()
	e.realmCfg = realmConfig{
		RelayURL:   p.RelayURL,
		RealmID:    p.RealmID,
		Token:      p.Token,
		STUN:       p.STUN,
		StaticAddr: p.StaticAddr,
		DataListen: e.dataListen,
	}
	e.realmMu.Unlock()

	if p.Disabled || p.RelayURL == "" || p.RealmID == "" {
		log.Printf("realm: disabled or empty config, stopping realm loop")
		e.stopRealm()
		return nil
	}

	log.Printf("realm: config received, relay=%s realm=%s", p.RelayURL, p.RealmID)
	e.stopRealm()

	e.realmMu.Lock()
	needRebuild := e.punchConn == nil
	e.realmMu.Unlock()
	if needRebuild {
		if err := e.rebuildServer(context.Background()); err != nil {
			return fmt.Errorf("rebuild for realm: %w", err)
		}
	}
	e.startRealm()
	return nil
}

func (e *edge) startRealmIfConfigured() {
	e.realmMu.Lock()
	cfg := e.realmCfg
	e.realmMu.Unlock()
	if cfg.RelayURL == "" || cfg.RealmID == "" {
		return
	}
	e.startRealm()
}

func (e *edge) startRealm() {
	e.realmMu.Lock()
	if e.realmCancel != nil {
		e.realmMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.realmCancel = cancel
	e.realmMu.Unlock()

	go func() {
		runRealmLoop(ctx, e.realmCfgSnapshot(), e.punchConn, e.udpConn, e.edgeID)
	}()
}

func (e *edge) stopRealm() {
	e.realmMu.Lock()
	cancel := e.realmCancel
	e.realmCancel = nil
	e.realmMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (e *edge) realmCfgSnapshot() realmConfig {
	e.realmMu.Lock()
	defer e.realmMu.Unlock()
	return e.realmCfg
}

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

func redirectMasq(target string) http.Handler {
	if target == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "not found", http.StatusNotFound)
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target)
		w.WriteHeader(http.StatusFound)
	})
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

func remoteAddrIP(addr net.Addr) string {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP.String()
	default:
		return addr.String()
	}
}

func deviceID() string {
	b, err := os.ReadFile("/etc/machine-id")
	if err == nil && len(b) >= 32 {
		return string(b[:32])
	}
	b, err = os.ReadFile("/var/lib/dbus/machine-id")
	if err == nil && len(b) >= 32 {
		return string(b[:32])
	}
	b, err = os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err == nil && len(b) >= 36 {
		return string(b[:36])
	}
	// Last resort: generate a UUID and cache it
	idPath := edgeIDFile()
	if b, err := os.ReadFile(idPath); err == nil && len(b) > 0 {
		return string(b)
	}
	var buf [16]byte
	rand.Read(buf[:])
	id := fmt.Sprintf("%x", buf)
	os.WriteFile(idPath, []byte(id), 0644)
	return id
}

func edgeIDFile() string {
	cache, _ := os.UserCacheDir()
	if cache == "" {
		cache = "/tmp"
	}
	return cache + "/mscope-edge-id"
}

func loadCentralPub(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if len(block.Bytes) == ed25519.PublicKeySize {
		return ed25519.PublicKey(block.Bytes), nil
	}
	raw, err := hex.DecodeString(string(block.Bytes))
	if err != nil {
		return nil, fmt.Errorf("decode pubkey: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pubkey wrong size: %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}
