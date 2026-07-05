// Package control implements the ephemeral control channel between an edge
// node and the central server. The edge does not know the central's address;
// the central connects in, proves possession of the private key corresponding
// to the baked-in central public key via an Ed25519 challenge-response
// handshake, and then takes control of the edge.
package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	challengeSize = 32
	maxFrameSize  = 1 << 20
)

var (
	ErrInvalidSignature = errors.New("control: invalid central signature")
	ErrFrameTooLarge    = errors.New("control: frame exceeds max size")
	ErrShortRead        = errors.New("control: short read")
)

func writeChallenge(w io.Writer, challenge []byte) error {
	if len(challenge) != challengeSize {
		return fmt.Errorf("control: challenge must be %d bytes", challengeSize)
	}
	_, err := w.Write(challenge)
	return err
}

func readChallenge(r io.Reader) ([]byte, error) {
	buf := make([]byte, challengeSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > maxFrameSize {
		return ErrFrameTooLarge
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || n > maxFrameSize {
		return nil, ErrFrameTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
