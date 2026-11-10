package config

import (
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
