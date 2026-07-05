## Auth flow

```
edge                              central
 │  TCP dial ─────────────────────► │
 │  Ed25519 challenge (32 bytes) ──►│
 │  ◄── {ts, sig(challenge||ts)} ── │   central proves identity
 │   verify sig(centralPub)         │
 │  ◄── TLS 1.3 (pinned cert) ──── │   encrypted channel
 │  {device_id, name, ip} ─────────►│   edge identifies itself
 │                                  │
 │  ◄── MsgAccept / MsgReject ──── │   central checks whitelist
 │  ◄── MsgHello ───────────────── │
 │  ◄── MsgConfig ──────────────── │
 │  ◄── MsgCert ────────────────── │
 │  ◄── MsgGrants ──────────────── │
 │  ◄── MsgRealm ───────────────── │
```

- **Edge verifies central**: using the baked-in `central.pub` (Ed25519 challenge-response)
- **Central verifies edge**: by checking `device_id` against the whitelist (`-whitelist-file`)
- Device ID is hardware-bound (`/etc/machine-id`, persistent across reboots)

## Build

### 1. Generate a keypair (one time)

```sh
go run ./cmd/central -gen-key
# Outputs: PUBKEY_B64=<base64 of the raw 32-byte public key>
#
# Writes: central.priv  (keep this — your webserver uses it to sign)
#         certs/central.pub
```

### 2. Build the edge with the key baked in

```sh
B64=$(go run ./cmd/central -gen-key 2>&1 | grep PUBKEY_B64 | sed 's/PUBKEY_B64=//')

go build \
  -ldflags="-X main.centralPubB64=$B64" \
  -o edge ./cmd/edge
```

The resulting `edge` binary has the central's public key embedded. It will **only connect to a central that holds the matching private key**. This prevents rogue servers from impersonating your central.

### 3. Run central (on your public server)

```sh
./central \
  -listen 0.0.0.0:38472 \
  -priv central.priv \
  -users-file users.json \
  -whitelist-file whitelist.json
```

Central listens on TCP 38472. Multiple edges can connect.

### 4. Run edge (on your home network)

```sh
./edge -central-addr central.example.com:38472 -data-listen 0.0.0.0:443
```

That's it. No `-central-pub` flag. The key is baked in. The edge connects, proves central's identity, sends its hardware ID, gets config/cert/grants, and starts serving.

## Web server integration

Your dashboard server imports `pkg/central` to push configs to edges:

```go
import "github.com/B83C/mscope-edge/pkg/central"

// Load the private key (from central.priv, generated in step 1)
priv, _ := central.LoadKeypair("central.priv")

// Connect to an edge and push config
ch, _ := central.Dial(ctx, "edge-ip:38472", priv)

central.PushHello(ch, "my-dashboard")
central.PushConfig(ch, serverCfg)          // QUIC tuning, UDP, masq, etc.
central.PushGrants(ch, grantsPayload)       // user credentials
pin, _ := central.PushCert(ch, sni, 24*time.Hour)  // self-signed TLS cert
central.PushRealm(ch, realmPayload)          // NAT punching config
```

The `central.Dial()` call:
1. Accepts the edge's Ed25519 challenge (proves central's identity using `central.priv`)
2. Establishes TLS using the same key
3. Receives the edge's `MsgIdentify` (device_id, name, IP)
4. Returns `*control.Channel` for further pushes

You can log the edge identity and decide whether to proceed:

```go
ch, _ := central.Dial(ctx, edgeAddr, priv)
// ch has already received MsgIdentify from the edge
// Log it or check whitelist in your DB
```

## Edge identity & whitelist

The edge identifies itself with:
- **device_id**: from `/etc/machine-id` (hardware-bound, persistent)
- **name**: the `-edge-id` flag (defaults to hostname)
- **public_ip**: the IP address central sees the connection from

Whitelist file (JSON array of device IDs):

```json
["d30ca57ef1304aeb98141d26535c146d"]
```

```sh
./central -whitelist-file /path/to/whitelist.json
```

If omitted, all edges are accepted. The device ID is always logged so you can populate the whitelist later from your database.

## Docker

Build with your key baked in:

```sh
B64=$(go run ./cmd/central -gen-key 2>&1 | grep PUBKEY_B64 | sed 's/PUBKEY_B64=//')

docker build \
  --build-arg CENTRAL_PUB_B64="$B64" \
  -t mscope-edge .
```

Or pull from GHCR (if you've set the `CENTRAL_PUB_B64` secret):

```sh
docker run -d --name mscope-edge \
  -p 443:443/udp \
  ghcr.io/B83C/mscope-edge:latest \
  -central-addr central.example.com:38472 \
  -data-listen 0.0.0.0:443
```

Multi-arch: amd64, arm64, arm/v7. Auto-built on push to `main` if `CENTRAL_PUB_B64` secret is set in the repo.

## Central flags

| Flag | Default | Description |
|---|---|---|
| `-listen` | `0.0.0.0:38472` | TCP listen for edges |
| `-priv` | `central.priv` | Ed25519 private key |
| `-users-file` | — | JSON grants file |
| `-whitelist-file` | — | JSON device ID whitelist |
| `-server-listen` | `0.0.0.0:443` | Data plane port pushed to edges |
| `-masq` | `https://example.com` | Masquerade URL |
| `-disable-udp` | `false` | Disable UDP |
| `-congestion` | `""` | Congestion: `bbr` or empty |
| `-realm-*` | — | Realm relay config |

## Edge flags

| Flag | Default | Description |
|---|---|---|
| `-central-addr` | `127.0.0.1:38472` | Central address to dial |
| `-data-listen` | `0.0.0.0:443` | UDP data plane port |
| `-central-pub` | `""` | Override baked-in key (PEM file path) |
| `-edge-id` | hostname | Edge name sent during identification |
