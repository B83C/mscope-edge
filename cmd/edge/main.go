package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/B83C/mscope-edge/internal/auth"
	"github.com/B83C/mscope-edge/internal/certvault"
	"github.com/B83C/mscope-edge/internal/configsource"
	"github.com/B83C/mscope-edge/pkg/control"
	hcore "github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/outbounds/speedtest"
	"github.com/apernet/hysteria/extras/v2/realm"
	// "github.com/go-logr/logr/funcr"
)

// Set at build time via -ldflags -X main.centralPubB64=<base64>
// If empty, falls back to -central-pub flag or certs/central.pub file.
var centralPubB64 string

func main() {
	var (
		centralAddr = flag.String("central-addr", "127.0.0.1:38472", "central server address")
		centralPub  = flag.String("central-pub", "", "path to central public key; overrides built-in")
		edgeID      = flag.String("edge-id", "", "edge name (default: hostname)")
	)
	flag.Parse()

	if *edgeID == "" {
		h, err := os.Hostname()
		if err != nil {
			log.Fatalf("hostname: %v", err)
		}
		*edgeID = h
	}

	var pub ed25519.PublicKey
	if *centralPub != "" {
		var err error
		pub, err = loadCentralPubFile(*centralPub)
		if err != nil {
			log.Fatalf("load central pub: %v", err)
		}
	} else if centralPubB64 != "" {
		b, err := base64.StdEncoding.DecodeString(centralPubB64)
		if err != nil {
			log.Fatalf("decode built-in central pub: %v", err)
		}
		pub = ed25519.PublicKey(b)
	} else {
		pub, _ = loadCentralPubFile("certs/central.pub")
		if pub == nil {
			log.Fatal("no central public key found. Either:\n" +
				"  1. Build with -ldflags=\"-X main.centralPubB64=$(base64 < certs/central.pub)\"\n" +
				"  2. Place certs/central.pub next to the binary\n" +
				"  3. Use -central-pub flag")
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	e := &edge{
		centralPub: pub,
		edgeID:     *edgeID,
		vault:      certvault.New(),
		cfgSrc:     configsource.New(),
		auth:       auth.NewStore(),
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGINT)

	go func() {
		<-sigChan
		fmt.Println("\n CTRL+C detected")

		buf := make([]byte, 1<<20)
		stackSize := runtime.Stack(buf, true)

		fmt.Printf("%s \n", buf[:stackSize])
		os.Exit(1)
	}()

	if err := e.run(ctx, *centralAddr); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("edge: %v", err)
	}
}

type edge struct {
	centralPub ed25519.PublicKey
	edgeID     string

	vault  *certvault.Vault
	cfgSrc *configsource.Source
	auth   *auth.Store

	mu       sync.Mutex
	srv      hcore.Server
	hCfg     *hcore.Config
	srvReady bool
	lastCold string

	udpConn   *net.UDPConn
	punchConn *realm.PunchPacketConn

	centralMu     sync.Mutex
	centralActive bool
	authCh        *control.Channel // set when central connected, for proxied auth
	authPending   sync.Map         // reqID → chan bool
	authSeq       atomic.Uint64

	realmMu     sync.Mutex
	realmCancel context.CancelFunc
	realmCfg    realmConfig

	masqAtomic *atomicHandler

	isPrivate bool
	publicIPs []string
	localIPs  []string

	readyCh chan struct{}
	stopped chan struct{}
}

// centralAuth proxies auth requests to central over the control channel.
// Falls back to local auth.Store if central is unreachable.
type centralAuth struct {
	edge *edge
}

func (a *centralAuth) Authenticate(addr net.Addr, auth string, tx uint64) (bool, string) {
	ch := a.edge.authCh
	if ch == nil {
		return a.edge.auth.Authenticate(addr, auth, tx)
	}

	reqID := fmt.Sprintf("%d", a.edge.authSeq.Add(1))
	resp := make(chan bool, 1)
	a.edge.authPending.Store(reqID, resp)
	defer a.edge.authPending.Delete(reqID)
	defer close(resp)

	err := ch.Send(control.MsgAuthRequest, control.AuthRequestPayload{
		RequestID: reqID,
		UserID:    splitAuth(auth),
		Secret:    splitSecret(auth),
		Addr:      addr.String(),
	})
	if err != nil {
		return a.edge.auth.Authenticate(addr, auth, tx)
	}

	select {
	case ok := <-resp:
		return ok, splitAuth(auth)
	case <-time.After(10 * time.Second):
		return a.edge.auth.Authenticate(addr, auth, tx)
	}
}

func splitAuth(auth string) string {
	idx := strings.IndexByte(auth, ':')
	if idx <= 0 {
		return auth
	}
	return auth[:idx]
}

func splitSecret(auth string) string {
	idx := strings.IndexByte(auth, ':')
	if idx <= 0 || idx == len(auth)-1 {
		return ""
	}
	return auth[idx+1:]
}

func (e *edge) run(ctx context.Context, centralAddr string) error {
	e.readyCh = make(chan struct{})
	e.stopped = make(chan struct{})

	go e.serveDataPlane(ctx)

	// On shutdown: close server so serveDataPlane exits, then stopped fires
	go func() {
		<-ctx.Done()
		e.mu.Lock()
		e.shutdownServerLocked()
		e.mu.Unlock()
	}()

	log.Printf("control: dialing central at %s, edge id %s", centralAddr, e.edgeID)

	// Discover network info once at startup
	e.publicIPs, e.localIPs, e.isPrivate = discoverNetworkInfo()
	log.Printf("network: public=%v local=%v private=%v", e.publicIPs, e.localIPs, e.isPrivate)

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
		OnUpgrade: func(p control.UpgradePayload) error {
			return e.applyUpgrade(ctx, p)
		},
		OnAuthResponse: func(p control.AuthResponsePayload) error {
			if v, ok := e.authPending.Load(p.RequestID); ok {
				v.(chan bool) <- p.OK
			}
			return nil
		},
		OnCentralGone: func() {
			log.Printf("control: central gone, data plane and realm continue serving (cert=%s)",
				e.vault.ExpiresAt().Format(time.RFC3339))
			e.authCh = nil
		},
	}, e.edgeID)
	e.authCh = ch
	go e.trafficReportLoop(ctx, ch)

	e.auth.OnDisconnect = func(id string) {
		if ch := e.authCh; ch != nil {
			ch.Send(control.MsgDisconnected, control.DisconnectedPayload{UserID: id})
		}
	}

	go ch.Run(ctx)

	// Identify: send hardware ID + network info, wait for central verdict
	pubIPs, locIPs, isPrivate := e.netInfo()
	ident := control.IdentifyPayload{
		DeviceID:   deviceID(),
		Name:       e.edgeID,
		PublicIPs:  pubIPs,
		LocalIPs:   locIPs,
		IsPrivate:  isPrivate,
		Version:    1,
	}
	for _, ip := range pubIPs {
		if net.ParseIP(ip).To4() != nil {
			ident.PublicIPv4 = ip
		} else {
			ident.PublicIPv6 = ip
		}
	}
	ch.Send(control.MsgIdentify, ident)

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
	if !ok || cfg.Config.Listen == "" {
		return nil
	}
	listenAddr := cfg.Config.Listen
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
		Conn:                  connForHcore,
		Outbound:              &directOutbound{},
		Authenticator:         &centralAuth{edge: e},
		EventLogger:           e.auth,
		TrafficLogger:         e.auth,
		MasqHandler:           e.masqAtomic,
		IgnoreClientBandwidth: c.IgnoreClientBandwidth,
		DisableUDP:            c.DisableUDP,
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

func (e *edge) trafficReportLoop(ctx context.Context, ch *control.Channel) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		stats := e.auth.AllStats()
		users := make([]control.UserTraffic, 0, len(stats))
		for id, st := range stats {
			if st.Tx > 0 || st.Rx > 0 {
				users = append(users, control.UserTraffic{
					UserID: id, Tx: st.Tx, Rx: st.Rx, Online: st.Online,
				})
			}
		}
		if len(users) == 0 {
			continue
		}
		ch.Send(control.MsgTrafficReport, control.TrafficReportPayload{Users: users})
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

func (e *edge) applyUpgrade(ctx context.Context, p control.UpgradePayload) error {
	log.Printf("upgrade: version=%s url=%s sha256=%s", p.Version, p.URL, p.SHA256)

	if p.URL == "" || p.SHA256 == "" {
		return fmt.Errorf("upgrade: invalid payload")
	}

	// Download
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
	if err != nil {
		return fmt.Errorf("upgrade: request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("upgrade: download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("upgrade: download status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("upgrade: read: %w", err)
	}

	// Verify SHA256
	sum := sha256.Sum256(body)
	gotHex := hex.EncodeToString(sum[:])
	if gotHex != p.SHA256 {
		return fmt.Errorf("upgrade: sha256 mismatch: got %s, want %s", gotHex, p.SHA256)
	}

	// Write to temp
	tmpPath := "/tmp/mscope-edge-upgrade"
	if err := os.WriteFile(tmpPath, body, 0755); err != nil {
		return fmt.Errorf("upgrade: write: %w", err)
	}

	// Get current executable path
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("upgrade: executable: %w", err)
	}

	// Backup current binary
	backupPath := "/tmp/mscope-edge-rollback"
	if err := os.Rename(self, backupPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("upgrade: backup: %w", err)
	}

	// Replace with new binary
	if err := os.Rename(tmpPath, self); err != nil {
		os.Rename(backupPath, self) // restore
		os.Remove(tmpPath)
		return fmt.Errorf("upgrade: replace: %w", err)
	}

	log.Printf("upgrade: swapped, restarting...")

	// Graceful shutdown: stop data plane, close channel
	e.mu.Lock()
	e.shutdownServerLocked()
	e.mu.Unlock()

	// Restart with new binary
	return syscall.Exec(self, os.Args, os.Environ())
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

func (e *edge) netInfo() ([]string, []string, bool) {
	if len(e.publicIPs) > 0 {
		return e.publicIPs, e.localIPs, e.isPrivate
	}
	return discoverNetworkInfo()
}

func createIPClient(networkType string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				dialer := &net.Dialer{Timeout: 5 * time.Second}
				return dialer.DialContext(ctx, networkType, addr)
			},
		},
	}
}

// isAccessibleIPv4 returns true if the IP is a globally routable,
// public address that can accept direct incoming traffic from the internet.
func isAccessibleIPv4(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return false // Not a valid IPv4
	}

	// 1. Standard Private Network Ranges (RFC 1918)
	if ipv4[0] == 10 ||
		(ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31) ||
		(ipv4[0] == 192 && ipv4[1] == 168) {
		return false
	}

	// 2. Carrier-Grade NAT / CGNAT (RFC 6598: 100.64.0.0/10)
	if ipv4[0] == 100 && (ipv4[1] >= 64 && ipv4[1] <= 127) {
		return false
	}

	// 3. Local Loopback (127.0.0.0/8)
	if ipv4[0] == 127 {
		return false
	}

	// 4. Link-Local / Autoconfiguration (RFC 3927: 169.254.0.0/10)
	if ipv4[0] == 169 && ipv4[1] == 254 {
		return false
	}

	// If it passes all exclusions, it is an internet-accessible public IP
	return true
}

func discoverIPs() (ipv4 string, ipv6 string, isIPv4Accessible bool) {
	// Fetch IPv4
	clientV4 := createIPClient("tcp4")
	resp, err := clientV4.Get("https://ipify.org")
	if err == nil && resp.StatusCode == http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		ipv4 = strings.TrimSpace(string(b))
	}

	// Fetch IPv6
	clientV6 := createIPClient("tcp6")
	resp, err = clientV6.Get("https://ipinfo.io")
	if err == nil && resp.StatusCode == http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		ipv6 = strings.TrimSpace(string(b))
	}

	// Evaluate accessibility
	isIPv4Accessible = isAccessibleIPv4(ipv4)

	return ipv4, ipv6, isIPv4Accessible
}

func discoverNetworkInfo() (publicIPs, localIPs []string, isPrivate bool) {
	// Collect all local IPs (IPv4 + IPv6, non-loopback)
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				localIPs = append(localIPs, ipnet.IP.String())
			}
		}
	}

	// Discover public IPv4
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err == nil && resp.StatusCode == 200 {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		v4 := strings.TrimSpace(string(b))
		if v4 != "" {
			publicIPs = append(publicIPs, v4)
		}
	} else {
		// Fallback: ifconfig.me returns whichever it sees
		resp, err = client.Get("https://ifconfig.me/ip")
		if err == nil && resp.StatusCode == 200 {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			ip := strings.TrimSpace(string(b))
			if ip != "" && len(publicIPs) == 0 {
				publicIPs = append(publicIPs, ip)
			}
		}
	}

	// Discover public IPv6
	resp, err = client.Get("https://api6.ipify.org")
	if err == nil && resp.StatusCode == 200 {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		v6 := strings.TrimSpace(string(b))
		if v6 != "" {
			publicIPs = append(publicIPs, v6)
		}
	}

	// Determine NAT status
	for _, ip := range publicIPs {
		if isPrivateIP(ip) {
			isPrivate = true
		}
	}
	for _, ip := range localIPs {
		if isPrivateIP(ip) {
			isPrivate = true
		}
	}

	return
}

func isPrivateIP(ipStr string) bool {
	if ipStr == "" {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	// RFC1918
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return true
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return true
		case ip4[0] == 192 && ip4[1] == 168:
			return true
		case ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127: // CGNAT
			return true
		case ip.IsLinkLocalUnicast():
			return true
		}
	}
	return false
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

func loadCentralPubFile(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return decodeCentralPub(b)
}

func decodeCentralPub(b []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if len(block.Bytes) == ed25519.PublicKeySize {
		return ed25519.PublicKey(block.Bytes), nil
	}
	return nil, fmt.Errorf("pubkey wrong size: %d", len(block.Bytes))
}
