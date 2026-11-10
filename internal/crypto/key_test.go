package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSubKeysDifferPerDirection(t *testing.T) {
	k, err := SubKeys(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k.ClientToServer, k.ServerToClient) || len(k.ClientToServer) != 32 {
		t.Fatal("directional keys must differ")
	}
}

func TestKeyFileRoundTripAndPerms(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "key")
	m := bytes.Repeat([]byte{4}, 32)
	if err := SaveMasterKey(p, m); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	got, err := LoadMasterKey(p)
	if err != nil || !bytes.Equal(got, m) {
		t.Fatalf("roundtrip: %v", err)
	}
	os.Chmod(p, 0o644)
	if _, err := LoadMasterKey(p); err == nil {
		t.Fatal("world-readable key file accepted")
	}
}

func TestGeneratePassword(t *testing.T) {
	seen := map[string]bool{}
	counts := map[rune]int{}
	for i := 0; i < 2000; i++ {
		p, err := GeneratePassword()
		if err != nil {
			t.Fatal(err)
		}
		if len(p) != 20 || strings.Trim(p, passwordAlphabet) != "" {
			t.Fatalf("bad password %q", p)
		}
		if seen[p] {
			t.Fatal("duplicate password")
		}
		seen[p] = true
		for _, c := range p {
			counts[c]++
		}
	}
	if len(counts) != 62 { // 40000 draws: every symbol must appear (also a rough uniformity check)
		t.Fatalf("only %d distinct symbols used", len(counts))
	}
	for c, n := range counts { // expected ~645 each; wildly off means bias
		if n < 450 || n > 850 {
			t.Fatalf("symbol %q appears %d times", c, n)
		}
	}
}

func TestDeriveIsDeterministic(t *testing.T) {
	a, b := DeriveMaster([]byte("same password 123")), DeriveMaster([]byte("same password 123"))
	if !bytes.Equal(a, b) || bytes.Equal(a, DeriveMaster([]byte("other password 123"))) {
		t.Fatal("derive")
	}
}
