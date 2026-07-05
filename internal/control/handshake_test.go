package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"
)

func TestEdgeCentralHandshake_Success(t *testing.T) {
	edgePub, centralPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	edgeConn, centralConn := net.Pipe()
	var wg sync.WaitGroup
	wg.Add(2)

	var edgeErr, centralErr error
	go func() {
		edgeErr = EdgeHandshake(edgeConn, edgePub)
		wg.Done()
	}()
	go func() {
		centralErr = CentralHandshake(centralConn, centralPriv)
		wg.Done()
	}()

	wg.Wait()
	edgeConn.Close()
	centralConn.Close()

	if edgeErr != nil {
		t.Errorf("edge handshake failed: %v", edgeErr)
	}
	if centralErr != nil {
		t.Errorf("central handshake failed: %v", centralErr)
	}
}

func TestEdgeHandshake_WrongKey(t *testing.T) {
	_, centralPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)

	edgeConn, centralConn := net.Pipe()
	done := make(chan struct{})
	var edgeErr error

	go func() {
		edgeErr = EdgeHandshake(edgeConn, wrongPub)
		edgeConn.Close()
		close(done)
	}()
	go func() {
		CentralHandshake(centralConn, centralPriv)
		centralConn.Close()
	}()

	<-done

	if edgeErr == nil {
		t.Fatal("expected error, got nil")
	}
	if edgeErr != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature, got %v", edgeErr)
	}
}

func TestFraming_RoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	payload := []byte("hello test frame")

	go func() {
		if err := writeFrame(b, payload); err != nil {
			t.Error(err)
		}
	}()

	got, err := readFrame(a)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("got %q, want %q", got, payload)
	}
}

func TestChannelSendRecv(t *testing.T) {
	a, b := net.Pipe()

	var got HelloPayload
	done := make(chan struct{})

	go func() {
		var env Envelope
		if err := json.NewDecoder(a).Decode(&env); err != nil {
			return
		}
		json.Unmarshal(env.Payload, &got)
		close(done)
	}()

	ch := NewChannel(b, Handlers{}, "test")
	go ch.Run(context.Background())

	ch.Send(MsgHello, HelloPayload{CentralID: "c1", ProtocolVersion: 1})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}

	if got.CentralID != "c1" {
		t.Errorf("got %q, want %q", got.CentralID, "c1")
	}
	b.Close()
	a.Close()
}

func TestChannelDispatch(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	gotHello := make(chan struct{})
	gotConfig := make(chan struct{})

	ch := NewChannel(a, Handlers{
		OnHello: func(p HelloPayload) error {
			close(gotHello)
			return nil
		},
		OnConfig: func(p ConfigPayload) error {
			close(gotConfig)
			return nil
		},
	}, "tester")
	go ch.Run(context.Background())

	// Send from the other side
	go func() {
		env := Envelope{Type: MsgHello, Payload: mustMarshal(HelloPayload{CentralID: "x"}), Timestamp: 1, Sequence: 1}
		json.NewEncoder(b).Encode(env)
		env2 := Envelope{Type: MsgConfig, Payload: mustMarshal(ConfigPayload{Version: 1}), Timestamp: 2, Sequence: 2}
		json.NewEncoder(b).Encode(env2)
	}()

	select {
	case <-gotHello:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for hello")
	}
	select {
	case <-gotConfig:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for config")
	}
}

func TestClientTLSVerify(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	tlsCfg := NewClientTLSConfig(pub)
	if tlsCfg == nil {
		t.Fatal("NewClientTLSConfig returned nil")
	}
	if !tlsCfg.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=true")
	}
	if tlsCfg.VerifyPeerCertificate == nil {
		t.Error("expected VerifyPeerCertificate to be set")
	}
}

func mustMarshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func TestFraming_EmptyFrame(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	go func() {
		var lenBuf [4]byte
		b.Write(lenBuf[:])
	}()

	_, err := readFrame(a)
	if err == nil {
		t.Error("expected error for empty frame")
	}
}

func TestFraming_LargeFrame(t *testing.T) {
	a, b := net.Pipe()
	done := make(chan error, 1)

	go func() {
		_, err := readFrame(a)
		done <- err
	}()

	// Write a length header claiming the frame is huge
	var lenBuf [4]byte
	lenBuf[0] = 0x20 // > maxFrameSize
	b.Write(lenBuf[:])
	b.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Error("expected error for oversized frame")
		}
	case <-time.After(time.Second):
		t.Error("timeout")
	}
	a.Close()
}

func BenchmarkHandshake(b *testing.B) {
	edgePub, centralPriv, _ := ed25519.GenerateKey(rand.Reader)
	for i := 0; i < b.N; i++ {
		a, c := net.Pipe()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			EdgeHandshake(a, edgePub)
			a.Close()
			wg.Done()
		}()
		go func() {
			CentralHandshake(c, centralPriv)
			c.Close()
			wg.Done()
		}()
		wg.Wait()
	}
}
