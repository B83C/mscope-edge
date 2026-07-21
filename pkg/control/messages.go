package control

import (
	"time"
)

// ServerConfig is the Hysteria2 server configuration
// pushed to the edge. Unknown JSON fields are preserved
// for forward compatibility.
type ServerConfig struct {
	Listen          string `json:"listen,omitempty"`
	MasqDomain      string `json:"masq_domain,omitempty"`
	CertSNI         string `json:"cert_sni,omitempty"`
	TCPMbps         int    `json:"tcpmbps,omitempty"`
	UDPIdleSecs     int    `json:"udp_idle_secs,omitempty"`
	IgnClBandwidth  bool   `json:"ignore_client_bandwidth,omitempty"`
	DisableUDP      bool   `json:"disable_udp,omitempty"`
	QUICStreamRcvWin      uint64 `json:"quic_stream_rcv_win,omitempty"`
	QUICMaxStreamRcvWin   uint64 `json:"quic_max_stream_rcv_win,omitempty"`
	QUICConnRcvWin        uint64 `json:"quic_conn_rcv_win,omitempty"`
	QUICMaxConnRcvWin     uint64 `json:"quic_max_conn_rcv_win,omitempty"`
	QUICMaxIncomingStreams uint64 `json:"quic_max_incoming_streams,omitempty"`
	QUICMaxIdleTimeout    string `json:"quic_max_idle_timeout,omitempty"`
	QUICDisablePathMTU    bool   `json:"quic_disable_path_mtu,omitempty"`
	CongestionType        string `json:"congestion_type,omitempty"`
	BBRProfile            string `json:"bbr_profile,omitempty"`
}

// ConfigPayload wraps a ServerConfig with metadata.
type ConfigPayload struct {
	Config ServerConfig `json:"config"`
}

// CertPayload carries a TLS certificate and its SHA-256 pin.
type CertPayload struct {
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	CertDER   []byte    `json:"cert_der"`
	KeyDER    []byte    `json:"key_der"`
	PinSHA256 string    `json:"pin_sha256"`
}

// UserGrant contains credentials for a single user.
type UserGrant struct {
	UserID     string    `json:"userID"`
	Secret     string    `json:"secret"`
	MaxClients int       `json:"maxClients"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

// GrantsPayload carries a list of UserGrant.
type GrantsPayload struct {
	Grants []UserGrant `json:"grants"`
}
