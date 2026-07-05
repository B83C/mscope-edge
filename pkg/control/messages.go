package control

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"time"
)

type MessageType string

const (
	MsgHello    MessageType = "hello"
	MsgHeartbeat MessageType = "heartbeat"
	MsgConfig   MessageType = "config"
	MsgCert     MessageType = "cert"
	MsgGrants   MessageType = "grants"
	MsgRevoke   MessageType = "revoke"
	MsgDrain    MessageType = "drain"
	MsgRealm    MessageType = "realm"
	MsgIdentify MessageType = "identify"
	MsgAccept   MessageType = "accept"
	MsgReject   MessageType = "reject"
	MsgAck      MessageType = "ack"
	MsgError    MessageType = "error"
)

type Envelope struct {
	Type      MessageType     `json:"t"`
	Timestamp int64           `json:"ts"`
	Sequence  uint64          `json:"seq"`
	Payload   json.RawMessage `json:"p"`
}

type HelloPayload struct {
	CentralID    string `json:"central_id"`
	ProtocolVersion int  `json:"protocol_version"`
}

type HeartbeatPayload struct {
	EdgeID     string `json:"edge_id"`
	Uptime     int64  `json:"uptime"`
	ConnCount  int    `json:"conn_count"`
}

type ServerConfig struct {
	Listen                string `json:"listen"`
	CertSNI               string `json:"cert_sni"`
	TCPMbps               int    `json:"tcpmbps"`
	MaxClients            int    `json:"max_clients"`
	UDPIdleSecs           int    `json:"udp_idle_secs"`
	MasqDomain            string `json:"masq_domain"`
	DisableUDP            bool   `json:"disable_udp"`
	IgnoreClientBandwidth bool   `json:"ignore_client_bw"`
	CongestionType        string `json:"congestion_type"`
	BBRProfile            string `json:"bbr_profile"`
	QUICStreamRcvWin      uint64 `json:"quic_stream_rcv_win"`
	QUICMaxStreamRcvWin   uint64 `json:"quic_max_stream_rcv_win"`
	QUICConnRcvWin        uint64 `json:"quic_conn_rcv_win"`
	QUICMaxConnRcvWin     uint64 `json:"quic_max_conn_rcv_win"`
	QUICMaxIdleTimeout    string `json:"quic_max_idle_timeout"`
	QUICMaxIncomingStreams int64  `json:"quic_max_incoming_streams"`
	QUICDisablePathMTU    bool   `json:"quic_disable_path_mtu"`
}

type ConfigPayload struct {
	Version   uint64       `json:"version"`
	Config    ServerConfig `json:"config"`
}

type CertPayload struct {
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	CertDER   []byte    `json:"cert_der"`
	KeyDER    []byte    `json:"key_der"`
	PinSHA256 string    `json:"pin_sha256"`
	Sig       []byte    `json:"sig"`
}

type PinPayload struct {
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	PinSHA256 string    `json:"pin_sha256"`
	SNI       string    `json:"sni"`
	Server    string    `json:"server"`
	IssuedAt  time.Time `json:"issued_at"`
}

type RealmPayload struct {
	RelayURL   string   `json:"relay_url"`
	RealmID    string   `json:"realm_id"`
	Token      string   `json:"token"`
	STUN       []string `json:"stun"`
	StaticAddr string   `json:"static_addr"`
	Disabled   bool     `json:"disabled"`
}

func (c CertPayload) Cert() (*x509.Certificate, ed25519.PrivateKey, error) {
	if len(c.CertDER) == 0 || len(c.KeyDER) == 0 {
		return nil, nil, errors.New("control: empty cert or key")
	}
	cert, err := x509.ParseCertificate(c.CertDER)
	if err != nil {
		return nil, nil, err
	}
	var key ed25519.PrivateKey
	if l := len(c.KeyDER); l == ed25519.PrivateKeySize {
		key = ed25519.PrivateKey(c.KeyDER)
	} else {
		pk, err := x509.ParsePKCS8PrivateKey(c.KeyDER)
		if err != nil {
			return nil, nil, err
		}
		var ok bool
		key, ok = pk.(ed25519.PrivateKey)
		if !ok {
			return nil, nil, errors.New("control: cert key is not Ed25519")
		}
	}
	return cert, key, nil
}

type UserGrant struct {
	UserID     string    `json:"user_id"`
	Secret     string    `json:"secret"`
	MaxClients int       `json:"max_clients"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type GrantsPayload struct {
	Version uint64      `json:"version"`
	Grants  []UserGrant `json:"grants"`
}

type RevokePayload struct {
	Version uint64   `json:"version"`
	Users   []string `json:"users"`
}

type DrainPayload struct {
	Reason string `json:"reason"`
}

type ErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type IdentifyPayload struct {
	DeviceID  string `json:"device_id"`
	Name      string `json:"name"`
	PublicIP  string `json:"public_ip"`
	LocalIP   string `json:"local_ip"`
	IsPrivate bool   `json:"is_private"`
	Country   string `json:"country,omitempty"`
	City      string `json:"city,omitempty"`
	Version   int    `json:"version"`
}

type AcceptPayload struct {
	Message string `json:"message"`
}

type RejectPayload struct {
	Reason string `json:"reason"`
}
