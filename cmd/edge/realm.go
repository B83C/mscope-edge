package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"mscope-hysteria/pkg/control"

	"github.com/apernet/hysteria/extras/v2/realm"
)

type realmConfig struct {
	RelayURL   string
	RealmID    string
	Token      string
	STUN       []string
	StaticAddr string
	DataListen string
}

func runRealmLoop(ctx context.Context, cfg realmConfig, punchConn *realm.PunchPacketConn, udpConn *net.UDPConn, edgeID string) {
	if cfg.RelayURL == "" || cfg.RealmID == "" {
		return
	}

	baseURL, token, err := parseRealmBase(cfg.RelayURL, cfg.Token)
	if err != nil {
		log.Printf("realm: bad config: %v", err)
		return
	}

	client, err := realm.NewClient(realm.ClientConfig{
		BaseURL: baseURL,
		Token:   token,
		HTTPClient: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{}}},
	})
	if err != nil {
		log.Printf("realm: client: %v", err)
		return
	}
	_ = edgeID

	puncher, err := realm.NewServerPuncher(ctx, punchConn)
	if err != nil {
		log.Printf("realm: server puncher: %v", err)
		return
	}

	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		if err := runRealmSession(ctx, cfg, client, puncher, udpConn); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("realm: session ended: %v (retry in %s)", err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
	}
}

func runRealmSession(ctx context.Context, cfg realmConfig, client *realm.Client, puncher *realm.ServerPuncher, udpConn *net.UDPConn) error {
	addrs, err := discoverOwnAddrs(ctx, cfg, udpConn)
	if err != nil {
		return fmt.Errorf("discover addresses: %w", err)
	}
	log.Printf("realm: discovered addresses: %v", addrs)

	regCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	resp, err := client.Register(regCtx, cfg.RealmID, addrPortsToStrings(addrs))
	cancel()
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	ttl := time.Duration(resp.TTL) * time.Second
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	log.Printf("realm: registered, session=%s, ttl=%s", resp.SessionID, ttl)
	defer func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = client.Deregister(dctx, cfg.RealmID, resp.SessionID)
		dcancel()
	}()

	heartbeatDone := make(chan error, 1)
	go heartbeatLoop(ctx, client, cfg.RealmID, resp.SessionID, ttl, heartbeatDone)

	streamCtx, streamCancel := context.WithCancel(ctx)
	defer streamCancel()
	stream, err := client.Events(streamCtx, cfg.RealmID, resp.SessionID)
	if err != nil {
		return fmt.Errorf("events: %w", err)
	}
	defer stream.Close()
	log.Printf("realm: events stream open")

	for {
		select {
		case hbErr := <-heartbeatDone:
			if hbErr != nil && !errors.Is(hbErr, context.Canceled) && ctx.Err() == nil {
				return fmt.Errorf("heartbeat: %w", hbErr)
			}
			return nil
		default:
		}
		ev, err := stream.Next()
		if err != nil {
			if errors.Is(err, context.Canceled) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("event: %w", err)
		}
		go handlePunchEvent(ctx, puncher, cfg, resp.SessionID, addrs, ev)
	}
}

func heartbeatLoop(ctx context.Context, client *realm.Client, realmID, sessionID string, ttl time.Duration, done chan<- error) {
	interval := ttl / 2
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			done <- ctx.Err()
			return
		case <-t.C:
			hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_, err := client.Heartbeat(hctx, realmID, sessionID, realm.HeartbeatRequest{})
			cancel()
			if err != nil {
				done <- err
				return
			}
		}
	}
}

func handlePunchEvent(ctx context.Context, puncher *realm.ServerPuncher, cfg realmConfig, sessionID string, ourAddrs []netip.AddrPort, ev *realm.PunchEvent) {
	meta := realm.PunchMetadata{Nonce: ev.Nonce, Obfs: ev.Obfs}
	attemptID := ev.Nonce

	peerAddrs := make([]netip.AddrPort, 0, len(ev.Addresses))
	for _, a := range ev.Addresses {
		if ap, err := netip.ParseAddrPort(a); err == nil {
			peerAddrs = append(peerAddrs, ap)
		}
	}
	if len(peerAddrs) == 0 {
		log.Printf("realm: punch event with no parseable addresses")
		return
	}

	log.Printf("realm: punch attempt %s from %v", attemptID, peerAddrs)

	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	result, err := puncher.Respond(pctx, attemptID, ourAddrs, peerAddrs, meta, realm.PunchConfig{
		Timeout:  10 * time.Second,
		Interval: 100 * time.Millisecond,
	})
	if err != nil {
		log.Printf("realm: punch %s failed: %v", attemptID, err)
		return
	}
	log.Printf("realm: punch %s succeeded, peer=%s", attemptID, result.PeerAddr)

	respCtx, respCancel := context.WithTimeout(ctx, 5*time.Second)
	defer respCancel()
	_ = clientConnectResponse(respCtx, cfg, sessionID, ev.Nonce, ourAddrs)
}

func clientConnectResponse(ctx context.Context, cfg realmConfig, sessionID, nonce string, addrs []netip.AddrPort) error {
	baseURL, token, err := parseRealmBase(cfg.RelayURL, cfg.Token)
	if err != nil {
		return err
	}
	c, err := realm.NewClient(realm.ClientConfig{
		BaseURL:    baseURL,
		Token:      token,
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
	})
	if err != nil {
		return err
	}
	return c.ConnectResponse(ctx, cfg.RealmID, sessionID, nonce, addrPortsToStrings(addrs))
}

func discoverOwnAddrs(ctx context.Context, cfg realmConfig, udpConn *net.UDPConn) ([]netip.AddrPort, error) {
	if cfg.StaticAddr != "" {
		if ap, err := netip.ParseAddrPort(cfg.StaticAddr); err == nil {
			return []netip.AddrPort{ap}, nil
		}
	}
	if len(cfg.STUN) == 0 {
		return nil, errors.New("no STUN servers configured and no static address")
	}
	if udpConn == nil {
		return nil, errors.New("no UDP conn available for STUN")
	}
	family := realm.AddrFamilyAny
	stunCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return realm.Discover(stunCtx, udpConn, realm.STUNConfig{
		Servers: cfg.STUN,
		Timeout: 5 * time.Second,
		Family:  family,
	})
}

func parseRealmBase(rawURL, token string) (*url.URL, string, error) {
	if token == "" {
		return nil, "", errors.New("token is required")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, "", fmt.Errorf("relay URL scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, "", errors.New("relay URL has no host")
	}
	return u, token, nil
}

func addrPortsToStrings(addrs []netip.AddrPort) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

func addrToAddrPortFromUDP(listen string) netip.AddrPort {
	host, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return netip.AddrPort{}
	}
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	ip, _ := netip.ParseAddr(host)
	return netip.AddrPortFrom(ip, port)
}

var _ = control.PinPayload{}
