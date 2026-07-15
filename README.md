# mscope-edge

Hysteria2 VPN edge node with central control channel. Edge connects to central via TCP, gets config + TLS cert + user grants, and starts serving Hysteria2/QUIC on the configured UDP port. A TCP masquerade listener runs on the same port for port scan camouflage.

## Auth flow

```
edge                              central
 │  TCP dial ─────────────────────► │
 │  Ed25519 challenge (32 bytes) ──►│
 │  ◄── {ts, sig(challenge||ts)} ── │   central proves identity
 │   verify sig(centralPub)         │
 │  ◄── TLS 1.3 (pinned cert) ──── │   encrypted channel
 │  {device_id, name, ips} ────────►│   edge identifies itself
 │                                  │
 │  ◄── MsgAccept / MsgReject ──── │   central checks auth
 │  ◄── MsgHello ───────────────── │
 │  ◄── MsgConfig ──────────────── │   QUIC tuning, port, masq domain
 │  ◄── MsgCert ────────────────── │   TLS cert + pinSHA256
 │  ◄── MsgGrants ──────────────── │   user credentials
 │  ◄── MsgRealm ───────────────── │   NAT punch relay config
```

- **Edge verifies central**: Ed25519 challenge-response using baked-in `centralPubB64`
- **Central verifies edge**: by checking `hysteria_token` in DB, plan, allowlist
- Device ID from `/etc/machine-id` (persistent across reboots)

## Quick deploy (ARM64 edge)

```sh
cd mscope-hysteria
GOOS=linux GOARCH=arm64 go build \
  -ldflags="-X main.centralPubB64=YOUR_BASE64_PUBKEY" \
  -o /tmp/edge-arm64 ./cmd/edge/

scp -i pulumi /tmp/edge-arm64 ubuntu@sg0-1.b83c.eu.org:/tmp/bin/edge
ssh -i pulumi ubuntu@sg0-1.b83c.eu.org '
  pkill -f edge; sleep 1
  nohup /tmp/bin/edge -central-addr 47.100.197.29:38472 > /tmp/edge.log 2>&1 &
'
```

## Local dev with mock central

```sh
go build -o /tmp/mock-central ./cmd/mock-central/     # starts on :38473
/tmp/mock-central &
PUBKEY=$(grep "central pub key" /tmp/mc.log | awk '{print $NF}')
go build -ldflags="-X main.centralPubB64=$PUBKEY" -o /tmp/edge ./cmd/edge/
/tmp/edge -central-addr :38473
```

Mock central auto-approves, pushes config + cert + grants, and the edge starts serving on `0.0.0.0:8445`. Test with:

```sh
hysteria client -c /tmp/hy.yaml   # socks5 on :1080
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

## Edge flags

| Flag | Default | Description |
|------|---------|-------------|
| `-central-addr` | `127.0.0.1:38472` | Central address to dial |
| `-central-pub` | `""` | Override baked-in key (PEM file) |
| `-edge-id` | hostname | Edge name sent in identify |

## What the edge does

1. Dial central TCP → Ed25519 handshake → TLS 1.3
2. Send `IdentifyPayload` (device_id, name, public/local IPs)
3. Receive `MsgAccept` → wait for config + cert + grants
4. Build Hysteria2 server on the configured UDP port
5. Start **TCP masquerade listener** on the same port (HTTP reverse proxy to masq domain)
6. Report `status:running:PORT` back to central
7. Proxy auth requests to central via control channel
8. Report traffic every 60s
9. On Ctrl+C: close channel immediately (no 60s hang)

## TCP masquerade

The edge listens on the same port via **TCP** (alongside Hysteria UDP). Any TCP connection receives an HTTP reverse-proxy response from the masq domain, logging each hit:

```
masq: GET / from 1.2.3.4:56789
```

This hides the Hysteria server from TCP port scans.

## Docker

Build with your key baked in:

```sh
docker build --build-arg CENTRAL_PUB_B64="$B64" -t mscope-edge .
```

Or pull from GHCR (requires `CENTRAL_PUB_B64` secret):

```sh
docker run -d --name mscope-edge \
  ghcr.io/B83C/mscope-edge:latest \
  -central-addr central.example.com:38472
```
