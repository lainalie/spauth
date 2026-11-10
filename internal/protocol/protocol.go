// Package protocol implements the SPA v3 wire format.
//
// There is NO time in the protocol: replay protection comes from a server
// challenge, so client and server clocks do not matter at all.
//
//	client -> HELLO(token)                         server remembers token, picks random challenge
//	client <- CHALLENGE(token, challenge, your_ip)
//	client -> OPEN(token, challenge, your_ip)      server checks challenge + source IP, whitelists the IP
//	client <- OK(token, challenge, opened_ip)
//
// Every message is exactly PacketSize bytes: nonce(12) | ChaCha20-Poly1305(frame) | tag(16),
// with no plaintext header (looks like random bytes). Client->server messages use one key,
// server->client messages another (see crypto.SubKeys), so nothing can be reflected back.
// All four messages have the same size: the server can never amplify traffic.
//
//	frame = version(1) | type(1) | ip(4) | token(16) | challenge(16)
//
// A captured OPEN is useless to an attacker: the challenge is single-use, short-lived,
// and bound to the source IP the server saw in HELLO.
package protocol

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	Version       = byte(3)
	TypeHello     = byte(1)
	TypeChallenge = byte(2)
	TypeOpen      = byte(3)
	TypeOK        = byte(4)

	NonceSize  = chacha20poly1305.NonceSize
	FrameSize  = 1 + 1 + 4 + 16 + 16
	PacketSize = NonceSize + FrameSize + chacha20poly1305.Overhead
)

var (
	ErrPacket = errors.New("invalid SPA packet")

	// aad is not transmitted; it domain-separates this protocol version.
	aad = []byte("SPA-v3")
)

type Frame struct {
	Type      byte
	IP        [4]byte
	Token     [16]byte // chosen by the client, echoed by the server
	Challenge [16]byte // chosen by the server, echoed by the client
}

func NewToken() ([16]byte, error) {
	var t [16]byte
	_, err := rand.Read(t[:])
	return t, err
}

// Seal encrypts a frame. Retransmissions resend the same returned packet.
func Seal(key []byte, f Frame) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	var plain [FrameSize]byte
	plain[0], plain[1] = Version, f.Type
	copy(plain[2:6], f.IP[:])
	copy(plain[6:22], f.Token[:])
	copy(plain[22:], f.Challenge[:])

	out := make([]byte, NonceSize, PacketSize)
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return aead.Seal(out, out[:NonceSize], plain[:], aad), nil
}

// Open authenticates and decodes a packet. Any failure is ErrPacket.
func Open(key, packet []byte) (Frame, error) {
	var f Frame
	if len(packet) != PacketSize {
		return f, ErrPacket
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return f, err
	}
	plain, err := aead.Open(nil, packet[:NonceSize], packet[NonceSize:], aad)
	if err != nil || len(plain) != FrameSize || plain[0] != Version {
		return f, ErrPacket
	}
	f.Type = plain[1]
	copy(f.IP[:], plain[2:6])
	copy(f.Token[:], plain[6:22])
	copy(f.Challenge[:], plain[22:])
	return f, nil
}
