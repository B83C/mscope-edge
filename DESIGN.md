# mscope-edge Design

## Architecture

```
[Client] --QUIC/UDP--> [Edge] --TCP--> [Central (auth_server)]
                              |
                         [frp tunnel] 47.100.197.29:38472
```

- **Edge**: ARM64 binary on sg0-1, connects to central via frp TCP
- **Central**: Go auth_server, listens on :38472 for edges, :8000 for web UI
- **Client**: Hysteria2 client, connects to edge's UDP port via subscription URL

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 38472 | TCP | Central ↔ Edge control channel |
| 8000 | TCP | Web dashboard |
| 8443 | UDP | Hysteria2/QUIC data plane |
| 8443 | TCP | Masquerade HTTP reverse proxy (same port as UDP) |

## Keypair

- Ed25519 keypair stored in `central.priv` / `certs/central.pub`
- Auth_server signs TLS certs with this key during edge handshake
- Edge bakes the public key at build time via `-ldflags="-X main.centralPubB64=..."`
- `go run` picks up `central.priv` from CWD

## Auth Flow

### 1. Control Channel Handshake (TCP :38472)

```
Edge                         Central
 │  TCP dial ───────────────► │
 │  challenge (32 bytes) ────►│
 │  ◄── {ts, sig(challenge+ts}│  Ed25519: central proves identity
 │  verify sig(centralPub)    │
 │  ◄── TLS 1.3 ──────────── │  pinned cert (central's Ed25519 key)
 │  {device_id, name, ips} ──►│  identify exchange
 │                            │
 │  ◄── MsgAccept            │  auto if reconnecting approved edge
 │  ◄── MsgConfig            │  listen port, masq domain, QUIC params
 │  ◄── MsgCert              │  TLS cert + pinSHA256 for client
 │  ◄── MsgGrants            │  user credentials (token→user mapping)
 │  ◄── MsgRealm             │  (optional) NAT punching config
```

### 2. Client Auth (Hysteria QUIC)

```
Client                         Edge                  Central
 │  QUIC connect ────────────► │                       │
 │  auth = "user:secret"       │                       │
 │                             │  MsgAuthRequest ─────►│
 │                             │  ◄── MsgAuthResponse ─│  checks hysteria_token,
 │                             │      {ok, userID}    │  credits, plan, limits
 │  ◄── accepted / rejected    │                       │
```

### 3. Disconnect Reporting

When a Hysteria client disconnects, the edge calls `OnDisconnect(id)` which sends `MsgDisconnected` to central. Central decrements the global session counter.

### 4. Traffic Reporting

Edge sends `MsgTrafficReport` every 60s with aggregated Tx/Rx per user.

## Token System

| Token | Scope | Storage |
|-------|-------|---------|
| `session_token` | Web session auth | `sessions` DB table, rotated on login/logout |
| `hysteria_token` | Proxy auth + subscription URL | `users.hysteria_token` column, FIXED per user |

## Subscription URL

Format:
```
hysteria2://credits-N-plan-X-Nserver@0.0.0.0:0/?insecure=1#💰 N Credits | Plan | N Server
hysteria2://USER_TOKEN@IP:PORT/?fastopen=1&pinSHA256=PIN#Name (conns/64) 🇸🇬
```

- First line: heading with credits, plan, server count (remark only, `0.0.0.0:0`)
- Per-server lines: real IP from `public_ip`, port from `config_json.listen`
- Remark: `Name (current_conns/64) 🇸🇬` where flag from `loc_code`
- Pin from `pin_sha256` in edge_nodes

## Config Push

### On dashboard "Save Config":
1. Save config JSON to `config_json` column
2. Push `MsgConfig` to connected edge
3. If no TLS cert stored (`pin_sha256` empty), auto-generate one via `GenerateCert()` and push `MsgCert`

### On edge reconnect (approved):
1. Push stored config from `config_json`
2. Push stored cert from `cert_der`/`key_der` columns
3. Push user grants (plan-based + allowlist)

### On edge reconnect (pending):
1. Send `MsgAccept {pending admin approval}`
2. Wait for admin to approve via dashboard

## Masquerade

### TCP Listener
- Edge listens on the **same port** as Hysteria UDP (e.g., 8443)
- Serves HTTP reverse proxy to `masq_domain` from config
- Uses Go `httputil.ReverseProxy`, proxies `http://masq_domain`
- Logs each request: `masq: GET /path from IP:PORT`

### Goal
- TCP port scan sees a real web server responding
- Hysteria/QUIC traffic is on UDP, invisible to TCP scans

## Signal Handling (Ctrl+C)

When SIGINT/SIGTERM received:
1. Context cancels
2. Goroutine closes control channel → `recvLoop` unblocks immediately
3. Data plane server closed
4. Clean exit (no 60s wait)

## Status Reporting

After `rebuildServer`:
1. Edge sends `MsgError {code: "status", message: "running:PORT"}`
2. Central's `OnError` checks `code == "status"` → stores in `server_status` column
3. Dashboard returns `server_status` in `ServersJSON`

On disconnect:
1. `server_status` cleared
2. `error_msg` cleared

## Session Limits

- Global session store tracks per-user connection count across all edges
- Default max: 3 concurrent sessions per user
- Checked during `OnAuthRequest`: reject if `current >= maxConns`

## Credits

- Weekly deduction: `current_time - last_deduction > 7*86400`
- Deduction amount from `plan_credits_per_week` (DB)
- Credits checked in `OnAuthRequest`: reject if `credits <= 0`

## Node Access

Accessible to user if:
1. User is admin, OR
2. Node has no `required_plan`, OR
3. User's plan matches `required_plan`, OR
4. User is in node's explicit allowlist (`node_allowed_users`)

## Database Schema (edge_nodes)

| Column | Type | Purpose |
|--------|------|---------|
| device_id | TEXT PK | From `/etc/machine-id` |
| name | TEXT | Edge name |
| public_ip | TEXT | Comma-separated public IPs |
| local_ip | TEXT | Comma-separated local IPs |
| lat/lng | REAL | Geo coordinates |
| loc_code | TEXT | Country code (SG, MY, etc.) |
| approved | INT | 0=pending, 1=approved |
| connected | INT | 0=offline, 1=online |
| pin_sha256 | TEXT | TLS cert pin |
| cert_der/key_der | TEXT | TLS cert/key (base64) |
| config_json | TEXT | Last pushed config |
| error_msg | TEXT | Last error from edge |
| server_status | TEXT | Edge status ("running:PORT") |
| required_plan | TEXT | Plan filter |
| mode | TEXT | 'direct' or 'realm' |

## Local Development

### Mock Central
```
go build -o /tmp/mock-central ./cmd/mock-central/
/tmp/mock-central                                    # starts on :38473
go build -ldflags="-X main.centralPubB64=$(grep pubkey /tmp/mc.log | awk '{print $NF}')" -o /tmp/edge ./cmd/edge/
/tmp/edge -central-addr :38473
```

Mock central:
- Auto-accepts all edges
- Pushes config (port 8445, masq hackernews.com)
- Pushes self-signed TLS cert
- Pushes test grants (user: test/test123)
- Stores nothing in DB

### Quick ARM64 Deploy
```
GOOS=linux GOARCH=arm64 go build -ldflags="-X main.centralPubB64=KEY" -o /tmp/edge-arm64 ./cmd/edge/
scp -i pulumi /tmp/edge-arm64 ubuntu@sg0-1.b83c.eu.org:/tmp/bin/edge
ssh -i pulumi ubuntu@sg0-1.b83c.eu.org 'pkill -f edge; sleep 1; nohup /tmp/bin/edge -central-addr 47.100.197.29:38472 > /tmp/edge.log 2>&1 &'
```
