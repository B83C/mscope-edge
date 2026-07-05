# mscope-hysteria

A wrapper around [Hysteria 2](https://github.com/apernet/hysteria) that runs the data plane as an **ephemeral**, **stateless-on-the-surface** edge node. All config, TLS material, and per-user credentials are pushed live from a central controller over an Ed25519-authenticated control channel. Nothing sensitive lives on disk on the edge beyond the central's public key.

The server speaks the **stock Hysteria 2 wire protocol** — clients don't need any custom code. They fetch a daily config (containing a cert pin) and connect normally.

## How a client connects

```yaml
# client.yaml
server: hysteria.example.com:443

tls:
  sni: hysteria-internal          # arbitrary, not verified
  pinSHA256: "yW/Brp4UtDSP2Ndy..."  # base64 of SHA-256(cert DER), rotated daily

auth: "alice:my-secret"
```

The pin in the client config matches the cert installed in the edge's in-memory vault. The pin is published by the central (file or HTTP) and the user is responsible for getting it to their clients (config file, app update, etc.).

The same edge accepts connections from:
- Direct clients who know the IP:port
- `realm://` clients who discover the IP:port via NAT-traversal rendezvous

The server is unaware of which path the client took.

## Architecture

```
                 ┌────────────────────┐
                 │   central          │  ./cmd/central
                 │   (trusted)        │
                 │                    │  writes pin.json
                 │                    │  serves /pin over HTTP
                 └────────┬───────────┘
                          │  TCP, ephemeral
                          │  Ed25519 challenge-response
                          │  JSON message stream
                          │
                 ┌────────┴───────────┐
                 │   edge             │  ./cmd/edge
                 │  ┌──────────────┐  │
                 │  │ in-mem cert  │◄─┼── pushed by central, never on disk
                 │  │ in-mem grant │◄─┼── pushed by central, TTL'd locally
                 │  │  registry    │  │
                 │  │ + session    │  │
                 │  │   counter    │  │
                 │  └──────┬───────┘  │
                 │         │          │
                 │  ┌──────▼───────┐  │
                 │  │ hysteria/core│  │  UDP, single port
                 │  │  GetCert     │  │  ─────────────────► clients
                 │  │  AuthStore   │  │     (direct or realm)
                 │  │  EventLogger │  │
                 │  └──────────────┘  │
                 └────────────────────┘
```

## Hot reload: what doesn't kill connections

Most config changes do **not** require a server restart. The edge tracks a "cold fingerprint" of fields that genuinely need a restart, and only rebuilds when those change.

| Field | Hot? | Notes |
|---|---|---|
| TLS cert | ✅ | `GetCertificate` hook picks up new cert on next handshake |
| User grants | ✅ | `auth.Store.Apply()` mutates in place |
| `TCPMbps` (bandwidth cap) | ✅ for new conns | Mutated on the live `*hcore.Config` |
| `MaxClients` (per-user cap) | ✅ | Counter in `auth.Store` |
| `UDPIdleSecs` | ✅ for new conns | Same as bandwidth |
| `MasqDomain` | ❌ Cold | `http.Handler` set at construction; rare change |
| `Listen` port | ❌ Cold | UDP socket bound at construction; rare change |
| Realm config | ✅ | Realm manager restarts on `MsgRealm`, data plane unaffected |

So in practice the server only restarts when central pushes a port change or a masq domain change — both rare. Daily cert rotation, bandwidth tuning, grant changes, and realm (re)config are all hot.

## Realm (NAT-traversal) support

The edge optionally registers with a [Hysteria realm relay](https://github.com/apernet/hysteria-realm-server) so clients using `realm://` URLs can reach the edge through NAT punching. The relay config is **pushed by central** over the control channel — the edge binary has no realm-related flags.

To enable, run central with:

```sh
./central \
  -realm-relay "https://relay.example.com" \
  -realm-id "my-realm" \
  -realm-token "shared-secret-with-relay" \
  # either: STUN discovery (default servers if omitted)
  -realm-stun "stun:stun.nextcloud.com:3478" \
  # or: a known static public address (skips STUN)
  -realm-static-addr "1.2.3.4:443"
```

### Default STUN servers

When `-realm-stun` is empty AND `-realm-static-addr` is empty, central uses these defaults (same as upstream Hysteria — chosen for restricted regions, see [ip.skk.moe/stun](https://ip.skk.moe/stun)):

- `stun.nextcloud.com:3478`
- `stun.sip.us:3478`
- `global.stun.twilio.com:3478`

Override with `-realm-stun` if your network blocks any of these or you want a regional server.

### `-realm-static-addr` vs `-realm-stun`

| Use case | Flag |
|---|---|
| Edge is on a VPS with a known stable public IP | `-realm-static-addr "1.2.3.4:443"` (skips STUN entirely) |
| Edge is behind NAT / home router | `-realm-stun` (default servers) |
| Edge is behind NAT, fallback to a guessed IP | both (static is used if set, STUN only if static is empty) |

### What happens

Central pushes the `MsgRealm` to the edge after cert/config/grants. The edge then:

1. Discovers its own public address (STUN, or uses the static override)
2. Registers with the relay (`POST /v1/{realm-id}`)
3. Heartbeats every `ttl/2`
4. Watches the SSE event stream for incoming punch attempts
5. For each attempt, demuxes punch packets via `PunchPacketConn` and runs `ServerPuncher.Respond`

If central goes down, the edge stops the realm manager cleanly. The data plane keeps running for direct clients.

The UDP listener on the edge is always wrapped in `realm.PunchPacketConn` — even without realm config, no harm done; the demuxer just passes everything through.

### Running the relay

Use the upstream `hysteria-realm-server` binary as a separate process. It has its own minimal config (listen addr, token, TLS cert). We don't ship a relay — we just connect to one.

```sh
# separate host
hysteria-realm-server \
  --listen :8443 \
  --token shared-secret \
  --cert /etc/relay/cert.pem \
  --key /etc/relay/key.pem
```

## Components

| Package | Role |
|---|---|
| `internal/control/handshake.go` | Ed25519 challenge-response over TCP |
| `internal/control/framing.go` | Length-prefixed frames, 32B challenge |
| `internal/control/messages.go` | JSON envelope + payload types |
| `internal/control/channel.go` | Per-connection channel, heartbeat, dispatch |
| `internal/certvault/vault.go` | In-memory TLS cert with `GetCertificate` hook |
| `internal/auth/ttl.go` | TTL'd user grants, session counter, `EventLogger` impl |
| `internal/configsource/source.go` | Latest `ServerConfig` from control channel |
| `cmd/edge/main.go` | Edge binary: listens for central, runs hysteria |
| `cmd/central/main.go` | Central CLI: listens for edges, pushes cert+config+grants |
| `pkg/central/central.go` | Central library: importable by your dashboard server |

## Build

```sh
go build -o edge ./cmd/edge
go build -o central ./cmd/central
```

Requires Go 1.22+. Pulls in `github.com/apernet/hysteria/core/v2` as a Go module.

## Use as a library (for your dashboard/server)

```go
import "mscope-hysteria/pkg/central"

func pushConfigToEdge(ctx context.Context, addr string) error {
    priv, _ := central.LoadKeypair("central.priv")
    ch, _ := central.Dial(ctx, addr, priv)
    defer ch.Close()

    central.PushHello(ch, "central-dev")
    central.PushConfig(ch, control.ServerConfig{
        Listen:  "0.0.0.0:443",
        CertSNI: "hysteria-internal",
        TCPMbps: 200,
    })
    pin, _ := central.PushCert(ch, "hysteria-internal", 24*time.Hour)
    central.PushGrants(ch, grants)
    central.PushRealm(ch, realmPayload)
    
    // pin is the hex-encoded SHA-256 of the cert;
    // distribute it to clients via your dashboard
    return nil
}
```

See `pkg/central/central.go` for all exported functions:
- `GenerateCert(sni, ttl) → der, key, pinHex`
- `GenerateKeypair(path)` / `LoadKeypair(path) → priv`
- `LoadGrants(path) → GrantsPayload`
- `Dial(ctx, addr, priv) → *control.Channel`
- `PushHello/Config/Cert/Grants/Realm(ch, ...)`

## Run

### 1. Generate the central keypair (once)

```sh
go run ./cmd/central -gen-key
```

Writes:
- `central.priv` — central's Ed25519 private key (PKCS8, mode 0600)
- `certs/central.pub` — central's Ed25519 public key (PEM, baked into edge builds)

The pubkey is the only thing the edge needs. It is **not** a secret.

### 2. Start the edge

```sh
./edge -listen 0.0.0.0:38472 -data-listen 0.0.0.0:443
```

- Listens on TCP 38472 for central (fixed)
- Initial data plane listen is `0.0.0.0:443`, but **central can override** this via the pushed config
- Holds no cert on disk; serves no traffic until central connects

### 3. Start the central

```sh
./central \
  -edge edge1.example.com:38472 \
  -edge edge2.example.com:38472 \
  -users-file users.json \
  -priv central.priv \
  -sni hysteria-internal \
  -masq "https://your-masq-site.example.com" \
  -tcpmbps 200 \
  -cert-ttl 24h \
  -server-pub "hysteria.example.com:443" \
  -server-listen 0.0.0.0:443
```

Central:
- `-edge` is **repeatable** — manages multiple edges simultaneously
- Connects to each edge, performs the Ed25519 handshake, pushes hello/config/cert/grants/realm
- If `-edge` is omitted, defaults to `127.0.0.1:38472`
- `-users-file` reads user grants from a JSON file (see `users.json.example`)
- If `-users-file` is omitted, two test users (alice, bob) are created with 48h expiry
- The pushed config's `Listen` field tells the edge which UDP port to bind for the data plane — overrides any `-data-listen` value
- Stays connected; heartbeats exchanged
- Cert pin is computed but **not** published — your dashboard server handles that

## Pin distribution

The pin is the SHA-256 hex of the cert's DER form (64-character lowercase hex string). It changes whenever the cert rotates (default: every 12h, half of the 24h TTL). Clients must fetch a fresh pin before each rotation.

**The central does not publish the pin.** It's embedded in the `CertPayload` sent to the edge (for logging) and computed inside `sendCert`, but the user is responsible for distributing it to clients.

## Client config

Your clients connect to the edge using the stock `hysteria` client with `pinSHA256` (hex format) plus `insecure: true`:

```yaml
server: 203.0.113.50:443
tls:
  sni: hysteria-internal
  insecure: true
  pinSHA256: "9d41a6a03670ed6d2ef26ec843a96f168a0d3dcb3d7c714f1ea3f4d59f5ea778"
auth: "alice:s3cret-alice"
```

The `insecure: true` is required because the cert is self-signed (no public CA chain). `pinSHA256` is checked independently on top of it. The pin format is **64-character lowercase hex** — the same format `openssl x509 -noout -fingerprint -sha256` outputs (but without colons).

## Auth format

Clients send `auth` as `userID:secret`. The `auth.Store` hashes the secret with SHA-256, looks up the user, constant-time compares, and enforces:

- TTL on the grant
- Per-user concurrent session cap (via `EventLogger` Disconnect decrement)

## Handshake protocol

```
edge                         central
  | --- 32 random bytes --->  |
  | <-- {ts, sig(challenge||ts)} -- |
  |   verify sig(central.pub)        |
  |   check |now - ts| < 5 min       |
```

After handshake the same TCP connection carries length-prefixed JSON envelopes. The edge sends heartbeats every 10s; the central pushes certs, configs, grants, revocations as needed.

## Speedtest

Speedtest works out of the box. The edge's outbound handler intercepts `@SpeedTest` requests and returns the speedtest server implementation from `extras/outbounds/speedtest`. No extra config needed — just run:

```sh
hysteria speedtest -c client.yaml
```

## All central flags

| Flag | Default | Description |
|---|---|---|
| `-edge` | `127.0.0.1:38472` | Repeatable: edge control addresses to manage |
| `-users-file` | — | JSON file with user grants (see `users.json.example`) |
| `-priv` | `central.priv` | Ed25519 private key (PEM) |
| `-id` | `central-dev` | Central identifier |
| `-sni` | `hysteria-internal` | SNI for generated cert |
| `-masq` | `https://example.com` | Masquerade URL hint |
| `-tcpmbps` | `100` | TCP bandwidth cap (Mbps) |
| `-cert-ttl` | `24h` | Cert TTL; rotation at half of this |
| `-server-pub` | — | Public server address for client configs |
| `-server-listen` | `0.0.0.0:443` | Data plane listen address pushed to edges |
| `-disable-udp` | `false` | Disable UDP forwarding |
| `-ignore-client-bw` | `false` | Ignore client bandwidth claims |
| `-congestion` | `""` | Congestion control: `bbr` or `brutal` |
| `-bbr-profile` | `""` | BBR profile (`default`, `low_latency`, etc.) |
| `-quic-*-rcv-win` | varies | QUIC stream/connection receive windows |
| `-quic-idle-timeout` | `30s` | QUIC max idle timeout |
| `-quic-max-streams` | `1024` | QUIC max incoming streams |
| `-quic-disable-mtu` | `false` | Disable QUIC path MTU discovery |
| `-realm-*` | — | Realm relay config (see above) |

All flags map directly to fields in the pushed `ServerConfig` and are applied when the edge builds (or rebuilds) the data plane server.

## What's not implemented (yet)

- **No per-message Ed25519 signing on every envelope.** Handshake proves identity; subsequent messages rely on the TCP connection not being hijacked. Add per-message signing in `channel.recvLoop` and `Channel.Send` if you need it.
- **No encryption on the control channel.** Messages travel in plaintext over TCP. The data is signed configs/certs which are public-by-design, but if you need privacy, wrap with Noise or TLS.
- **No sliding-window replay protection.** Add a window of recent `(timestamp, sequence)` tuples if needed.
- **Cert renewal is currently driven by central's restart**, not a separate timer. The cert TTL is set at generation; a future version can add a renewal loop that re-pushes `MsgCert` while keeping the control connection alive.
- **No NAT keepalive loop** in the realm manager. The edge's NAT mapping to the relay may time out (depends on the home router). Hysteria's realm package doesn't ship one — would need to be added as a periodic UDP "ping" to the relay.
- **The control channel is single-connection.** If central reconnects, the edge rebuilds. Future: keep state across reconnects.
- **Punch optimizations not applied.** The default 100ms interval, no burst-start, no skip-on-public-IP. The basic version works; optimizations can come later.
- **TrafficLogger** is implemented in `auth.Store` and tracks per-user tx/rx + online state. Stats are accessible via `AllStats()` and `UserStats(id)` — but there's no API endpoint yet to expose them. Your dashboard can import auth.Store and poll these methods.

## License

Same as upstream Hysteria (MIT).
