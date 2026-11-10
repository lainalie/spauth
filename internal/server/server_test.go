package server

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"

	"spa-prototype/internal/crypto"
	"spa-prototype/internal/protocol"
)

var keys = crypto.Keys{
	ClientToServer: bytes.Repeat([]byte{1}, 32),
	ServerToClient: bytes.Repeat([]byte{2}, 32),
}

type fakeFW struct {
	calls []netip.Addr
	fail  bool
}

func (f *fakeFW) Allow(ip netip.Addr) (int, error) {
	if f.fail {
		return 0, errors.New("boom")
	}
	f.calls = append(f.calls, ip)
	return len(f.calls), nil
}

var (
	cli   = netip.MustParseAddrPort("203.0.113.7:50000")
	other = netip.MustParseAddrPort("198.51.100.9:50000")
	t0    = time.Unix(1_000_000, 0)
)

func seal(t *testing.T, key []byte, f protocol.Frame) []byte {
	p, err := protocol.Seal(key, f)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func hello(t *testing.T, token [16]byte) []byte {
	return seal(t, keys.ClientToServer, protocol.Frame{Type: protocol.TypeHello, Token: token})
}

func open(t *testing.T, key []byte, p []byte) protocol.Frame {
	f, err := protocol.Open(key, p)
	if err != nil {
		t.Fatalf("reply does not authenticate: %v", err)
	}
	return f
}

// handshake runs HELLO and returns the challenge frame and an OPEN packet.
func handshake(t *testing.T, s *Server, token [16]byte, src netip.AddrPort, now time.Time) (protocol.Frame, []byte) {
	r := s.Handle(hello(t, token), src, now)
	if r == nil {
		t.Fatal("no CHALLENGE for valid HELLO")
	}
	ch := open(t, keys.ServerToClient, r)
	if ch.Type != protocol.TypeChallenge || ch.Token != token || ch.IP != src.Addr().As4() {
		t.Fatalf("bad challenge %+v", ch)
	}
	return ch, seal(t, keys.ClientToServer, protocol.Frame{Type: protocol.TypeOpen, IP: ch.IP, Token: token, Challenge: ch.Challenge})
}

var tok = [16]byte{1, 2, 3}

func TestFullHandshake(t *testing.T) {
	fw := &fakeFW{}
	s := New(keys, fw)
	ch, op := handshake(t, s, tok, cli, t0)
	r := s.Handle(op, cli, t0)
	if r == nil {
		t.Fatal("no OK")
	}
	ok := open(t, keys.ServerToClient, r)
	if ok.Type != protocol.TypeOK || ok.Token != tok || ok.Challenge != ch.Challenge || ok.IP != cli.Addr().As4() {
		t.Fatalf("bad OK %+v", ok)
	}
	if len(fw.calls) != 1 || fw.calls[0] != cli.Addr() {
		t.Fatalf("firewall calls: %v", fw.calls)
	}
}

func TestSilenceOnGarbageAndWrongKey(t *testing.T) {
	fw := &fakeFW{}
	s := New(keys, fw)
	if s.Handle([]byte("hello"), cli, t0) != nil {
		t.Fatal("reply to garbage")
	}
	wrong := seal(t, bytes.Repeat([]byte{9}, 32), protocol.Frame{Type: protocol.TypeHello, Token: tok})
	if s.Handle(wrong, cli, t0) != nil {
		t.Fatal("reply to wrong key")
	}
	// the server's own reply key must not be usable as a client key
	if s.Handle(seal(t, keys.ServerToClient, protocol.Frame{Type: protocol.TypeHello, Token: tok}), cli, t0) != nil {
		t.Fatal("reply to s2c-keyed packet")
	}
	if len(fw.calls) != 0 {
		t.Fatal("firewall touched")
	}
}

func TestHelloRetransmitGivesSameChallenge(t *testing.T) {
	s := New(keys, &fakeFW{})
	a, _ := handshake(t, s, tok, cli, t0)
	b, _ := handshake(t, s, tok, cli, t0.Add(time.Second))
	if a.Challenge != b.Challenge {
		t.Fatal("retransmitted HELLO must get the same challenge")
	}
}

func TestOpenRetransmitIsIdempotent(t *testing.T) {
	fw := &fakeFW{}
	s := New(keys, fw)
	_, op := handshake(t, s, tok, cli, t0)
	for i := 0; i < 3; i++ {
		if s.Handle(op, cli, t0.Add(time.Duration(i)*time.Second)) == nil {
			t.Fatalf("no OK on attempt %d (lost OK must be re-sent)", i)
		}
	}
	if len(fw.calls) != 1 {
		t.Fatalf("firewall called %d times", len(fw.calls))
	}
}

func TestReplayedOpenFromOtherIPDropped(t *testing.T) {
	fw := &fakeFW{}
	s := New(keys, fw)
	_, op := handshake(t, s, tok, cli, t0)
	if s.Handle(op, other, t0) != nil || len(fw.calls) != 0 {
		t.Fatal("attacker address got access with a captured OPEN")
	}
	if s.Handle(op, cli, t0) == nil {
		t.Fatal("legitimate client must still succeed afterwards")
	}
}

func TestReplayedHelloFromOtherIPDropped(t *testing.T) {
	s := New(keys, &fakeFW{})
	h := hello(t, tok)
	if s.Handle(h, cli, t0) == nil {
		t.Fatal("first HELLO")
	}
	if s.Handle(h, other, t0) != nil {
		t.Fatal("replayed HELLO answered")
	}
}

// The attacker has their own valid session only if they know the password.
// Mixing a challenge from one session with the token of another must fail.
func TestOpenMustMatchTokenAndChallenge(t *testing.T) {
	fw := &fakeFW{}
	s := New(keys, fw)
	chA, _ := handshake(t, s, [16]byte{1}, cli, t0)
	_, _ = handshake(t, s, [16]byte{2}, cli, t0)
	mixed := seal(t, keys.ClientToServer, protocol.Frame{Type: protocol.TypeOpen, IP: chA.IP, Token: [16]byte{2}, Challenge: chA.Challenge})
	if s.Handle(mixed, cli, t0) != nil || len(fw.calls) != 0 {
		t.Fatal("mismatched token/challenge accepted")
	}
	bogus := seal(t, keys.ClientToServer, protocol.Frame{Type: protocol.TypeOpen, IP: chA.IP, Token: [16]byte{1}, Challenge: [16]byte{0xEE}})
	if s.Handle(bogus, cli, t0) != nil {
		t.Fatal("unknown challenge accepted")
	}
	wrongIP := seal(t, keys.ClientToServer, protocol.Frame{Type: protocol.TypeOpen, IP: [4]byte{1, 2, 3, 4}, Token: [16]byte{1}, Challenge: chA.Challenge})
	if s.Handle(wrongIP, cli, t0) != nil {
		t.Fatal("OPEN with wrong echoed IP accepted")
	}
}

func TestOpenWithoutHelloIsSilent(t *testing.T) {
	s := New(keys, &fakeFW{})
	p := seal(t, keys.ClientToServer, protocol.Frame{Type: protocol.TypeOpen, IP: cli.Addr().As4(), Token: tok, Challenge: [16]byte{7}})
	if s.Handle(p, cli, t0) != nil {
		t.Fatal("OPEN without a session answered")
	}
}

func TestChallengeExpires(t *testing.T) {
	fw := &fakeFW{}
	s := New(keys, fw)
	_, op := handshake(t, s, tok, cli, t0)
	if s.Handle(op, cli, t0.Add(sessionTTL+10*time.Second)) != nil || len(fw.calls) != 0 {
		t.Fatal("expired challenge accepted")
	}
}

func TestFirewallFailureNoOKThenRetry(t *testing.T) {
	fw := &fakeFW{fail: true}
	s := New(keys, fw)
	_, op := handshake(t, s, tok, cli, t0)
	if s.Handle(op, cli, t0) != nil {
		t.Fatal("OK sent although access was not granted")
	}
	fw.fail = false
	if s.Handle(op, cli, t0.Add(time.Second)) == nil || len(fw.calls) != 1 {
		t.Fatal("retransmission must retry the firewall action")
	}
}

func TestResendBudget(t *testing.T) {
	s := New(keys, &fakeFW{})
	_, op := handshake(t, s, tok, cli, t0)
	n := 0
	for i := 0; i < 100; i++ {
		if s.Handle(op, cli, t0) != nil {
			n++
		}
	}
	if n > maxResends+1 {
		t.Fatalf("answered %d times, budget is %d", n, maxResends)
	}
}

func TestSessionTableBounded(t *testing.T) {
	s := New(keys, &fakeFW{})
	for i := 0; i < maxSessions+50; i++ {
		var tk [16]byte
		tk[0], tk[1] = byte(i), byte(i>>8)
		s.Handle(hello(t, tk), cli, t0)
	}
	if len(s.byToken) > maxSessions {
		t.Fatalf("table grew to %d", len(s.byToken))
	}
}

// Nothing in a packet carries time, so wildly different server clocks change nothing.
func TestClockIsIrrelevant(t *testing.T) {
	for _, now := range []time.Time{time.Unix(0, 0), time.Unix(4_000_000_000, 0)} {
		fw := &fakeFW{}
		s := New(keys, fw)
		_, op := handshake(t, s, tok, cli, now)
		if s.Handle(op, cli, now) == nil || len(fw.calls) != 1 {
			t.Fatalf("failed with clock %v", now)
		}
	}
}
