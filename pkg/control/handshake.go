package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const (
	handshakeTimeout = 10 * time.Second
)

type HandshakeRequest struct {
	Timestamp int64
	Signature []byte
}

func encodeHandshake(req HandshakeRequest) ([]byte, error) {
	if len(req.Signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("control: signature must be %d bytes", ed25519.SignatureSize)
	}
	buf := make([]byte, 8+ed25519.SignatureSize)
	binary.BigEndian.PutUint64(buf[:8], uint64(req.Timestamp))
	copy(buf[8:], req.Signature)
	return buf, nil
}

func decodeHandshake(b []byte) (HandshakeRequest, error) {
	if len(b) != 8+ed25519.SignatureSize {
		return HandshakeRequest{}, fmt.Errorf("control: handshake payload wrong size: %d", len(b))
	}
	return HandshakeRequest{
		Timestamp: int64(binary.BigEndian.Uint64(b[:8])),
		Signature: append([]byte(nil), b[8:]...),
	}, nil
}

func generateChallenge() ([]byte, error) {
	b := make([]byte, challengeSize)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func CentralHandshake(conn net.Conn, priv ed25519.PrivateKey) error {
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	challenge, err := readChallenge(conn)
	if err != nil {
		return fmt.Errorf("control: read challenge: %w", err)
	}

	ts := time.Now().Unix()
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(ts))
	sig := ed25519.Sign(priv, append(challenge, tsBuf[:]...))

	payload, err := encodeHandshake(HandshakeRequest{Timestamp: ts, Signature: sig})
	if err != nil {
		return err
	}
	if err := writeFrame(conn, payload); err != nil {
		return fmt.Errorf("control: write handshake: %w", err)
	}
	return nil
}

func EdgeHandshake(conn net.Conn, centralPub ed25519.PublicKey) error {
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	challenge, err := generateChallenge()
	if err != nil {
		return err
	}
	if err := writeChallenge(conn, challenge); err != nil {
		return fmt.Errorf("control: write challenge: %w", err)
	}

	frame, err := readFrame(conn)
	if err != nil {
		return fmt.Errorf("control: read handshake frame: %w", err)
	}
	req, err := decodeHandshake(frame)
	if err != nil {
		return err
	}

	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(req.Timestamp))
	if !ed25519.Verify(centralPub, append(challenge, tsBuf[:]...), req.Signature) {
		return ErrInvalidSignature
	}

	now := time.Now()
	delta := now.Sub(time.Unix(req.Timestamp, 0))
	if delta < 0 {
		delta = -delta
	}
	if delta > 5*time.Minute {
		return fmt.Errorf("control: handshake timestamp skew too large: %s", delta)
	}
	return nil
}
