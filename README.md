# mscope-edge

A wrapper around [Hysteria 2](https://github.com/apernet/hysteria). The **edge** runs behind NAT at home; the **central** is a public server (or embedded in your dashboard) that pushes certs, configs, and user grants to the edge over a TLS-encrypted control channel.

No port forwarding needed. The edge dials out to central.

## How a client connects

```yaml
# client.yaml
server: hysteria.example.com:443

tls:
  sni: hysteria-internal          # arbitrary, not verified
  pinSHA256: "9d41a6a03670ed6d..."  # hex of SHA-256(cert DER), rotated daily

auth: "user1:CHANGE_ME"
```

The edge speaks the **stock Hysteria 2 wire protocol** — clients don't need custom code.

## Architecture

```
                    homes (NAT)                    cloud / vps
                 ┌──────────────┐          ┌──────────────────────┐
                 │   edge       │   dials   │   central            │
                 │  (no public  │◄─────────│   (listens on TCP)   │
                 │   port)      │  TLS +    │                      │
                 │              │  Ed25519  │  pushes:             │
                 │  ┌────────┐  │   auth    │   - TLS cert         │
                 │  │hysteria│  │           │   - server config    │
                 │  │   core │──┼──────────►│   - user grants      │
                 │  │ (QUIC) │  │  clients  │   - realm config     │
                 │  └────────┘  │           └──────────────────────┘
                 └──────────────┘
```

## Connection flow

```
1. edge dials → central:38472 (TCP)
2. Ed25519 challenge-response (edge verifies central's key)
3. TLS 1.3 handshake (pinned cert, encrypted channel)
4. Edge sends hardware ID (device_id, name, public_ip)
5. Central checks whitelist → accepts or rejects
6. If accepted: central pushes cert, config, grants, realm config
7. Edge builds the Hysteria data plane on the configured UDP port
8. Clients connect to the edge directly or via realm NAT punching
```

## Hot reload

| Field | Hot? | Notes |
|---|---|---|
| TLS cert | ✅ | `GetCertificate` → next handshake picks up new cert |
| User grants | ✅ | `auth.Store` mutates in place |
| `TCPMbps` | ✅ for new conns | Mutated on live `*hcore.Config` |
| `MaxClients` | ✅ | Counter in `auth.Store` |
| `UDPIdleSecs` | ✅ for new conns | |
| `MasqDomain` | ✅ | `atomicHandler` swaps live |
| `Listen` port | ❌ | UDP socket bound at construction |
| Realm config | ✅ | Realm loop restarts |

## Run

### 1. Generate keypair (one time)

```sh
go run ./cmd/central -gen-key
# writes central.priv and certs/central.pub
```

### 2. Start central (on your public server)

```sh
./central \
  -listen 0.0.0.0:38472 \
  -users-file users.json \
  -priv central.priv
```

Central listens on TCP 38472 for incoming edge connections. Multiple edges can connect; each is handled in its own goroutine.

### 3. Start edge (on your home network)

```sh
./edge \
  -central-addr central.example.com:38472 \
  -data-listen 0.0.0.0:443 \
  -central-pub /path/to/certs/central.pub
```

Edge dials central, authenticates, receives config/cert/grants, then starts the Hysteria data plane. No port forwarding needed.

## Edge identity & whitelist

On connect, the edge sends its hardware ID (from `/etc/machine-id` or equivalent) to central. Central checks a whitelist:

```sh
./central -whitelist-file /path/to/whitelist.json
```

```json
["d30ca57ef1304aeb98141d26535c146d"]
```

If `-whitelist-file` is omitted, all edges are accepted. The device ID is always logged so you can populate the whitelist later.

## Use as a library (in your dashboard server)

```go
import "mscope-hysteria/pkg/central"

priv, _ := central.LoadKeypair("central.priv")
ch, _ := central.Dial(ctx, "edge:38472", priv)

central.PushHello(ch, "central-dev")
central.PushConfig(ch, serverConfig)
pin, _ := central.PushCert(ch, "hysteria-internal", 24*time.Hour)
central.PushGrants(ch, grants)
central.PushRealm(ch, realmPayload)
```

See `pkg/central/central.go` for all exported functions.

## Realm (NAT-traversal)

The edge can register with a [realm relay](https://github.com/apernet/hysteria-realm-server) so `realm://` clients can punch through NAT. Config is pushed by central:

```sh
./central \
  -realm-relay "https://relay.example.com" \
  -realm-id "my-realm" \
  -realm-token "shared-secret-with-relay"
```

Default STUN servers (same as upstream Hysteria, chosen for restricted regions):
- `stun.nextcloud.com:3478`
- `stun.sip.us:3478`
- `global.stun.twilio.com:3478`

## Client config

```yaml
server: hysteria.example.com:443
tls:
  sni: hysteria-internal
  insecure: true
  pinSHA256: "9d41a6a03670ed6d2ef26ec843a96f168a0d3dcb3d7c714f1ea3f4d59f5ea778"
auth: "user1:CHANGE_ME"
```

The pin is 64-character lowercase hex (SHA-256 of the cert DER). Rotated daily.

## All flags

### Edge (`./edge`)

| Flag | Default | Description |
|---|---|---|
| `-central-addr` | `127.0.0.1:38472` | Central address to dial |
| `-data-listen` | `0.0.0.0:443` | Hysteria UDP data plane |
| `-central-pub` | `certs/central.pub` | Central's Ed25519 public key (PEM) |
| `-edge-id` | hostname | Edge name sent during identification |

### Central (`./central`)

| Flag | Default | Description |
|---|---|---|
| `-listen` | `0.0.0.0:38472` | TCP listen address for edges |
| `-users-file` | — | JSON file with user grants |
| `-whitelist-file` | — | JSON array of allowed device IDs |
| `-priv` | `central.priv` | Ed25519 private key |
| `-server-listen` | `0.0.0.0:443` | Data plane port pushed to edges |
| `-masq` | `https://example.com` | Masquerade URL |
| `-disable-udp` | `false` | Disable UDP forwarding |
| `-congestion` | `""` | Congestion control: `bbr` or empty |
| `-quic-*` | varies | QUIC tuning |
| `-realm-*` | — | Realm relay config |

## Docker

```sh
docker run -d --name mscope-edge \
  -v /path/to/certs:/etc/mscope \
  -p 443:443/udp \
  ghcr.io/B83C/mscope-edge:latest \
  -central-addr central.example.com:38472 \
  -data-listen 0.0.0.0:443 \
  -central-pub /etc/mscope/central.pub
```

Multi-arch: amd64, arm64, arm/v7. Auto-built via GitHub Actions on push to `main`.

## What's not implemented (yet)

- Per-message signing on the JSON stream (handshake only authenticates the connection)
- Cert renewal loop (currently keyed to central connect; TTL expires after 24h without reconnect)
- NAT keepalive for realm relay UDP mappings
- Punch optimizations (100ms interval is conservative)
- API endpoint for TrafficLogger stats (exported via `auth.Store.AllStats()` — your dashboard can call it directly)

## License

Same as upstream Hysteria (MIT).
