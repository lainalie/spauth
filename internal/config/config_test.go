package config

import (
	"path/filepath"
	"os"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir() + "/spa"
	in := Config{Port: 40123, RetentionMinutes: 90}
	if err := Save(dir, in); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(ConfigPath(dir)); st.Mode().Perm() != 0o600 {
		t.Fatal("config must be 0600")
	}
	out, err := Load(dir)
	if err != nil || out != in || out.Retention() != 90*time.Minute {
		t.Fatalf("%v %+v", err, out)
	}
}

func TestValidate(t *testing.T) {
	for _, c := range []Config{{Port: 0}, {Port: 1, RetentionMinutes: -1}, {Port: 1, RetentionMinutes: MaxRetentionMinutes + 1}} {
		if c.Validate() == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	if (Config{Port: 1, RetentionMinutes: 0}).Validate() != nil {
		t.Fatal("0 (forever) must be valid")
	}
}

func TestTelegramRoundTripAndPaths(t *testing.T) {
	dir := t.TempDir() + "/spa"
	in := Config{Port: 40123, Telegram: true}
	if err := Save(dir, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(dir)
	if err != nil || out != in || !out.Telegram {
		t.Fatalf("%v %+v", err, out)
	}
	if RulesPath("/etc/spa") != filepath.Join("/etc/spa", "spa.nft") || TelegramPath("/etc/spa") != filepath.Join("/etc/spa", "telegram.nft") {
		t.Fatalf("paths: %s %s", RulesPath("/etc/spa"), TelegramPath("/etc/spa"))
	}
}

// A failed write leaves neither a temp file behind nor damage to the target.
func TestWriteFileAtomicCleansUpOnFailure(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil { // renaming a file onto a directory fails
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(target, []byte("data"), 0o600); err == nil {
		t.Fatal("expected an error")
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("temp files left behind: %v", ents)
	}
}

func TestWriteFileAtomicReplacesContent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	for _, s := range []string{"one", "two, longer", "3"} {
		if err := WriteFileAtomic(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(p); string(b) != s {
			t.Fatalf("got %q, want %q", b, s)
		}
	}
}
