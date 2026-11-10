package protocol

import (
	"bytes"
	"testing"
)

var (
	kC2S = bytes.Repeat([]byte{1}, 32)
	kS2C = bytes.Repeat([]byte{2}, 32)
)

func frame(t byte) Frame {
	f := Frame{Type: t, IP: [4]byte{203, 0, 113, 7}}
	copy(f.Token[:], bytes.Repeat([]byte{0xA1}, 16))
	copy(f.Challenge[:], bytes.Repeat([]byte{0xB2}, 16))
	return f
}

func TestRoundTripAllTypesSameSize(t *testing.T) {
	for _, typ := range []byte{TypeHello, TypeChallenge, TypeOpen, TypeOK} {
		p, err := Seal(kC2S, frame(typ))
		if err != nil || len(p) != PacketSize {
			t.Fatalf("type %d: err=%v len=%d", typ, err, len(p))
		}
		got, err := Open(kC2S, p)
		if err != nil || got != frame(typ) {
			t.Fatalf("type %d: %v %+v", typ, err, got)
		}
	}
}

func TestWrongKeyAndEveryByteTamper(t *testing.T) {
	p, _ := Seal(kC2S, frame(TypeOpen))
	if _, err := Open(kS2C, p); err == nil {
		t.Fatal("packet opened with the other direction's key")
	}
	for i := range p {
		q := append([]byte{}, p...)
		q[i] ^= 1
		if _, err := Open(kC2S, q); err == nil {
			t.Fatalf("tampered byte %d accepted", i)
		}
	}
	if _, err := Open(kC2S, p[:len(p)-1]); err == nil {
		t.Fatal("short packet accepted")
	}
	if _, err := Open(kC2S, append(p, 0)); err == nil {
		t.Fatal("long packet accepted")
	}
}

func TestFreshNoncePerSeal(t *testing.T) {
	a, _ := Seal(kC2S, frame(TypeHello))
	b, _ := Seal(kC2S, frame(TypeHello))
	if bytes.Equal(a[:NonceSize], b[:NonceSize]) || bytes.Equal(a, b) {
		t.Fatal("nonce reused")
	}
}

func TestNoPlaintextMarker(t *testing.T) {
	p, _ := Seal(kC2S, frame(TypeHello))
	if bytes.Contains(p, []byte("SPA")) {
		t.Fatal("plaintext marker in packet")
	}
}
