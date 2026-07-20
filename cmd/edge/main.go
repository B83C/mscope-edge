package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/B83C/mscope-edge/internal/auth"
	"github.com/B83C/mscope-edge/internal/certvault"
	"github.com/B83C/mscope-edge/internal/configsource"
	hcore "github.com/apernet/hysteria/core/v2/server"
	"github.com/coder/websocket"
)

var (
	mtlsCertB64 string
	mtlsKeyB64  string
	version     = "dev" // set at build: -ldflags="-X main.version=v1.0.0"
)

func main() {
	workerURL := flag.String("worker-url", "http://localhost:8777", "Cloudflare Worker URL")
	flag.Parse()

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("hostname: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	e := &edge{
		edgeID:    hostname,
		vault:     certvault.New(),
		cfgSrc:    configsource.New(),
		auth:      auth.NewStore(),
		workerURL: *workerURL,
	}

	if mtlsCertB64 != "" && mtlsKeyB64 != "" {
		certPEM, _ := base64.StdEncoding.DecodeString(mtlsCertB64)
		keyPEM, _ := base64.StdEncoding.DecodeString(mtlsKeyB64)
		if len(certPEM) > 0 && len(keyPEM) > 0 {
			cert, err := tls.X509KeyPair(certPEM, keyPEM)
			if err == nil {
				e.workerTLS = &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS13,
				}
				log.Printf("mtls: client cert loaded (cn=%s)", "mscope-edge")
			}
		}
	}

	if *workerURL != "" {
		log.Printf("worker: using Cloudflare Worker at %s", *workerURL)
		e.workerDeviceID = deviceID()
	}

	if err := e.run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("edge: %v", err)
	}
}

type edge struct {
	edgeID string

	vault  *certvault.Vault
	cfgSrc *configsource.Source
	auth   *auth.Store

	mu       sync.Mutex
	srv      hcore.Server
	hCfg     *hcore.Config
	srvReady bool
	lastCold string

	udpConn     *net.UDPConn
	tcpListener net.Listener
	tcpServer   *http.Server

	workerURL      string
	workerDeviceID string
	workerTLS      *tls.Config
	workerWSConn   *websocket.Conn
	workerWSMu     sync.Mutex

	masqAtomic *atomicHandler

	isPrivate bool
	publicIPs []string
	localIPs  []string

	readyCh chan struct{}
	stopped chan struct{}
}

func (e *edge) run(ctx context.Context) error {
	e.readyCh = make(chan struct{})
	e.stopped = make(chan struct{})

	go e.serveDataPlane(ctx)

	go func() {
		<-ctx.Done()
		e.mu.Lock()
		e.shutdownServerLocked()
		e.mu.Unlock()
	}()

	e.publicIPs, e.localIPs, e.isPrivate = discoverNetworkInfo()
	log.Printf("network: public=%v local=%v private=%v", e.publicIPs, e.localIPs, e.isPrivate)

	if err := e.bootstrapFromWorker(ctx); err != nil {
		log.Printf("worker: bootstrap error: %v", err)
	}
	e.auth.OnConnect = func(id string) {
		if ws := e.workerWS(); ws != nil {
			body, _ := json.Marshal(map[string]any{"type": "connect", "userID": id})
			ws.Write(ctx, websocket.MessageText, body)
		}
	}
	e.auth.OnDisconnect = func(id string) {
		if ws := e.workerWS(); ws != nil {
			body, _ := json.Marshal(map[string]any{"type": "disconnect", "userID": id})
			ws.Write(ctx, websocket.MessageText, body)
		}
	}
	go e.workerWSLoop(ctx)
	<-ctx.Done()
	<-e.stopped
	return ctx.Err()
}

// realm + upgrade functions removed — not used
