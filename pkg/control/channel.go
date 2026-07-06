package control

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Handlers struct {
	OnHello    func(HelloPayload) error
	OnHeartbeat func(HeartbeatPayload) error
	OnConfig   func(ConfigPayload) error
	OnCert     func(CertPayload) error
	OnGrants   func(GrantsPayload) error
	OnRevoke   func(RevokePayload) error
	OnDrain    func(DrainPayload) error
	OnRealm    func(RealmPayload) error
	OnIdentify func(IdentifyPayload) error
	OnAccept   func(AcceptPayload) error
	OnReject   func(RejectPayload) error
	OnUpgrade      func(UpgradePayload) error
	OnAuthRequest  func(AuthRequestPayload) error
	OnAuthResponse func(AuthResponsePayload) error
	OnDisconnected func(DisconnectedPayload) error
	OnError        func(ErrorPayload) error
	OnCentralGone func()
}

type Channel struct {
	conn     net.Conn
	enc      *json.Encoder
	dec      *json.Decoder
	handlers Handlers
	edgeID   string
	started  time.Time

	seqSend atomic.Uint64
	seqRecv atomic.Uint64

	closed chan struct{}
	closeOnce sync.Once
}

func NewChannel(conn net.Conn, h Handlers, edgeID string) *Channel {
	return &Channel{
		conn:     conn,
		enc:      json.NewEncoder(conn),
		dec:      json.NewDecoder(conn),
		handlers: h,
		edgeID:   edgeID,
		started:  time.Now(),
		closed:   make(chan struct{}),
	}
}

func (c *Channel) Send(t MessageType, payload any) error {
	env := Envelope{
		Type:      t,
		Timestamp: time.Now().Unix(),
		Sequence:  c.seqSend.Add(1),
	}
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		env.Payload = raw
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	defer c.conn.SetWriteDeadline(time.Time{})
	return c.enc.Encode(&env)
}

func (c *Channel) recvLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.closed:
			return
		default:
		}

		_ = c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		var env Envelope
		if err := c.dec.Decode(&env); err != nil {
			c.closeOnce.Do(func() { close(c.closed) })
			if c.handlers.OnCentralGone != nil {
				c.handlers.OnCentralGone()
			}
			return
		}

		if last := c.seqRecv.Load(); env.Sequence <= last {
			continue
		}
		c.seqRecv.Store(env.Sequence)

		if err := c.dispatch(env); err != nil {
			_ = c.Send(MsgError, ErrorPayload{Code: "handler", Message: err.Error()})
		}
	}
}

func (c *Channel) dispatch(env Envelope) error {
	switch env.Type {
	case MsgHello:
		var p HelloPayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return err
		}
		if c.handlers.OnHello != nil {
			return c.handlers.OnHello(p)
		}
	case MsgConfig:
		var p ConfigPayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return err
		}
		if c.handlers.OnConfig != nil {
			return c.handlers.OnConfig(p)
		}
	case MsgCert:
		var p CertPayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return err
		}
		if c.handlers.OnCert != nil {
			return c.handlers.OnCert(p)
		}
	case MsgGrants:
		var p GrantsPayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return err
		}
		if c.handlers.OnGrants != nil {
			return c.handlers.OnGrants(p)
		}
	case MsgRevoke:
		var p RevokePayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return err
		}
		if c.handlers.OnRevoke != nil {
			return c.handlers.OnRevoke(p)
		}
	case MsgDrain:
		var p DrainPayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return err
		}
		if c.handlers.OnDrain != nil {
			return c.handlers.OnDrain(p)
		}
	case MsgRealm:
		var p RealmPayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return err
		}
		if c.handlers.OnRealm != nil {
			return c.handlers.OnRealm(p)
		}
	case MsgIdentify:
		var p IdentifyPayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return err
		}
		if c.handlers.OnIdentify != nil {
			return c.handlers.OnIdentify(p)
		}
	case MsgAccept:
		var p AcceptPayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return err
		}
		if c.handlers.OnAccept != nil {
			return c.handlers.OnAccept(p)
		}
	case MsgReject:
		var p RejectPayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return err
		}
		if c.handlers.OnReject != nil {
			return c.handlers.OnReject(p)
		}
	case MsgHeartbeat:
		var p HeartbeatPayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return err
		}
		if c.handlers.OnHeartbeat != nil {
			return c.handlers.OnHeartbeat(p)
		}
		return nil
	case MsgUpgrade:
		var p UpgradePayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return err
		}
		if c.handlers.OnUpgrade != nil {
			return c.handlers.OnUpgrade(p)
		}
		return nil
	case MsgAck:
		return nil
	case MsgError:
		var p ErrorPayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return err
		}
		if c.handlers.OnError != nil {
			return c.handlers.OnError(p)
		}
		return nil
	case MsgAuthRequest:
		var p AuthRequestPayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return err
		}
		if c.handlers.OnAuthRequest != nil {
			return c.handlers.OnAuthRequest(p)
		}
		return nil
	case MsgAuthResponse:
		var p AuthResponsePayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return err
		}
		if c.handlers.OnAuthResponse != nil {
			return c.handlers.OnAuthResponse(p)
		}
		return nil
	case MsgDisconnected:
		var p DisconnectedPayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return err
		}
		if c.handlers.OnDisconnected != nil {
			return c.handlers.OnDisconnected(p)
		}
		return nil
	default:
		return fmt.Errorf("control: unknown message type %q", env.Type)
	}
	return nil
}

func (c *Channel) heartbeatLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.closed:
			return
		case <-t.C:
			_ = c.Send(MsgHeartbeat, HeartbeatPayload{
				EdgeID: c.edgeID,
				Uptime: int64(time.Since(c.started).Seconds()),
			})
		}
	}
}

func (c *Channel) Run(ctx context.Context) error {
	go c.heartbeatLoop(ctx)
	c.recvLoop(ctx)
	return nil
}

func (c *Channel) Close() {
	c.closeOnce.Do(func() { close(c.closed) })
	_ = c.conn.Close()
}

func (c *Channel) Done() <-chan struct{} { return c.closed }

var ErrNotImplemented = errors.New("control: feature not yet implemented")
var _ = ed25519.PublicKey(nil)
