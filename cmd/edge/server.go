package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/B83C/mscope-edge/pkg/control"
	hcore "github.com/apernet/hysteria/core/v2/server"
)

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
		e.masqAtomic.Set(masqHandler(c.MasqDomain))
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
	connForHcore := net.PacketConn(udpConn)
	c := cfg.Config

	e.masqAtomic = &atomicHandler{}
	e.masqAtomic.Set(masqHandler(c.MasqDomain))

	hCfg := &hcore.Config{
		TLSConfig: hcore.TLSConfig{
			GetCertificate: e.vault.GetCertificate,
		},
		Conn:                  connForHcore,
		Outbound:              &directOutbound{},
		Authenticator:         e.auth,
		EventLogger:           e.auth,
		TrafficLogger:         e.auth,
		MasqHandler:           e.masqAtomic,
		IgnoreClientBandwidth: c.IgnClBandwidth,
		DisableUDP:            c.DisableUDP,
		QUICConfig: hcore.QUICConfig{
			InitialStreamReceiveWindow:     maybe(c.QUICStreamRcvWin, 8388608),
			MaxStreamReceiveWindow:         maybe(c.QUICMaxStreamRcvWin, 8388608),
			InitialConnectionReceiveWindow: maybe(c.QUICConnRcvWin, 20971520),
			MaxConnectionReceiveWindow:     maybe(c.QUICMaxConnRcvWin, 20971520),
			MaxIncomingStreams:             int64(maybe(c.QUICMaxIncomingStreams, uint64(1024))),
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
	e.mu.Unlock()

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
	if e.tcpListener == nil && c.MasqDomain != "" {
		tcpAddr, err := net.ResolveTCPAddr("tcp", listenAddr)
		if err == nil {
			tcpLn, err := net.ListenTCP("tcp", tcpAddr)
			if err == nil {
				e.tcpListener = tcpLn
				go e.serveMasqTCP(ctx, tcpLn, c.MasqDomain)
				log.Printf("data: tcp masq on %s -> %s", listenAddr, c.MasqDomain)
			}
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
	if e.tcpListener != nil {
		e.tcpListener.Close()
		e.tcpListener = nil
	}
	if e.tcpServer != nil {
		e.tcpServer.Close()
		e.tcpServer = nil
	}
}
