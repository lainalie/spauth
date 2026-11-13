package firewall

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Real output shape of `nft -j list set inet spa allowed` (nft 1.0.9): bare element,
// element with comment, element with timeout + comment.
const realJSON = `{"nftables": [{"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "allowed", "table": "spa", "type": "ipv4_addr", "handle": 3, "flags": ["timeout"], "elem": ["192.0.2.1", {"elem": {"val": "198.51.100.9", "comment": "id=2 added=2026-11-08T10:01:00Z"}}, {"elem": {"val": "203.0.113.7", "timeout": 900, "expires": 899, "comment": "id=5 added=2026-11-08T10:05:00Z"}}]}}]}`

const emptyJSON = `{"nftables": [{"set": {"family": "inet", "name": "allowed", "table": "spa"}}]}`

type call struct {
	stdin string
	args  []string
}

func fake(listJSON string, failOn string) (*Nft, *[]call) {
	var calls []call
	n := &Nft{
		RulesPath: filepath.Join(os.TempDir(), "spa-test-rules"),
		Now:       func() time.Time { return time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC) },
	}
	n.Run = func(stdin string, args ...string) ([]byte, error) {
		calls = append(calls, call{stdin, args})
		joined := strings.Join(args, " ")
		if failOn != "" && strings.Contains(joined, failOn) {
			return nil, errors.New("nft failed")
		}
		switch {
		case strings.HasPrefix(joined, "-j list set"):
			return []byte(listJSON), nil
		case joined == "list table inet spa":
			return []byte("table inet spa {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n"), nil
		case joined == "list chain inet spa input":
			return []byte("chain input {\n\ttype filter hook input priority filter; policy drop;\n}\n"), nil
		}
		return nil, nil
	}
	return n, &calls
}

// script returns the stdin of the `-f -` transaction among the calls.
func script(calls []call) string {
	for _, c := range calls {
		if len(c.args) == 2 && c.args[0] == "-f" && c.args[1] == "-" {
			return c.stdin
		}
	}
	return ""
}

func TestParseRealJSON(t *testing.T) {
	n, _ := fake(realJSON, "")
	es, err := n.List()
	if err != nil || len(es) != 3 {
		t.Fatalf("%v %v", err, es)
	}
	if es[0].IP != netip.MustParseAddr("192.0.2.1") || es[0].ID != 0 || !es[0].Permanent {
		t.Fatalf("manual entry: %+v", es[0])
	}
	if es[1].ID != 2 || es[1].Added != "2026-11-08T10:01:00Z" || !es[1].Permanent {
		t.Fatalf("permanent entry: %+v", es[1])
	}
	if es[2].ID != 5 || es[2].Permanent || es[2].Expires != 899*time.Second {
		t.Fatalf("timed entry: %+v", es[2])
	}
}

func TestParseEmptySet(t *testing.T) {
	es, err := parseSet([]byte(emptyJSON))
	if err != nil || len(es) != 0 {
		t.Fatalf("%v %v", err, es)
	}
	if _, err := parseSet([]byte("garbage")); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestFirstClientGetsNumberOne(t *testing.T) {
	n, calls := fake(emptyJSON, "")
	id, err := n.Allow(netip.MustParseAddr("203.0.113.7"))
	if err != nil || id != 1 {
		t.Fatalf("id=%d err=%v", id, err)
	}
	want := "add element inet spa allowed { 203.0.113.7 }\n" +
		"delete element inet spa allowed { 203.0.113.7 }\n" +
		"add element inet spa allowed { 203.0.113.7 comment \"id=1 added=2026-11-08T10:00:00Z\" }\n"
	if got := script(*calls); got != want {
		t.Fatalf("script:\n%s", got)
	}
}

func TestNumbering(t *testing.T) {
	// set holds: manual 192.0.2.1 (no id), 198.51.100.9 = #2, 203.0.113.7 = #5
	n, calls := fake(realJSON, "")
	id, _ := n.Allow(netip.MustParseAddr("10.1.1.1"))
	if id != 6 {
		t.Fatalf("new client must get max+1 = 6, got %d", id)
	}
	if !strings.Contains(script(*calls), `comment "id=6 `) {
		t.Fatal("comment lacks the number")
	}
	for ip, want := range map[string]int{"198.51.100.9": 2, "203.0.113.7": 5} {
		if id, _ := n.Allow(netip.MustParseAddr(ip)); id != want {
			t.Fatalf("%s re-knock must keep #%d, got %d", ip, want, id)
		}
	}
	// an address that was added by hand (no number) gets one on its first knock
	if id, _ := n.Allow(netip.MustParseAddr("192.0.2.1")); id != 6 {
		t.Fatalf("manual entry got %d", id)
	}
}

func TestAllowWithRetention(t *testing.T) {
	n, calls := fake(emptyJSON, "")
	n.Retention = 15 * time.Minute
	n.Allow(netip.MustParseAddr("203.0.113.7"))
	if !strings.Contains(script(*calls), "{ 203.0.113.7 timeout 900s comment") {
		t.Fatalf("no timeout:\n%s", script(*calls))
	}
}

func TestAllowRejectsIPv6(t *testing.T) {
	n, calls := fake(emptyJSON, "")
	if _, err := n.Allow(netip.MustParseAddr("2001:db8::1")); err == nil {
		t.Fatal("IPv6 accepted")
	}
	if len(*calls) != 0 {
		t.Fatal("nft was invoked")
	}
}

func TestAllowFailsWhenNftFails(t *testing.T) {
	n, _ := fake(emptyJSON, "-f -")
	if _, err := n.Allow(netip.MustParseAddr("1.2.3.4")); err == nil {
		t.Fatal("nft failure must be reported (server then sends no OK)")
	}
}

func TestDeleteByNumberAndIP(t *testing.T) {
	for _, key := range []string{"5", "203.0.113.7", "2", "198.51.100.9", "192.0.2.1"} {
		n, calls := fake(realJSON, "")
		got, err := n.Delete(key)
		if err != nil || len(got) != 1 {
			t.Fatalf("%s: %v %v", key, err, got)
		}
		sc := script(*calls)
		if !strings.HasPrefix(sc, "delete element inet spa allowed { ") || strings.Count(sc, "delete") != 1 {
			t.Fatalf("%s: script %q", key, sc)
		}
	}
	n, _ := fake(realJSON, "")
	for _, key := range []string{"99", "8.8.8.8"} {
		if _, err := n.Delete(key); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: want ErrNotFound, got %v", key, err)
		}
	}
	for _, key := range []string{"-", "0", "-3", "abc", "", "1.2.3"} {
		if _, err := n.Delete(key); !errors.Is(err, ErrBadKey) {
			t.Fatalf("%q: want ErrBadKey, got %v", key, err)
		}
	}
}

func TestVerifyLocked(t *testing.T) {
	n, _ := fake(emptyJSON, "")
	if err := n.VerifyLocked(); err != nil {
		t.Fatal(err)
	}
	n.Run = func(string, ...string) ([]byte, error) {
		return []byte("chain input {\n type filter hook input priority filter; policy accept;\n}"), nil
	}
	if n.VerifyLocked() == nil {
		t.Fatal("policy accept must not count as locked")
	}
	n.Run = func(string, ...string) ([]byte, error) { return nil, errors.New("No such file or directory") }
	if n.VerifyLocked() == nil {
		t.Fatal("missing table must not count as locked")
	}
}

func TestPersistWritesSnapshot(t *testing.T) {
	n, _ := fake("", "")
	n.RulesPath = filepath.Join(t.TempDir(), "spa.nft")
	n.BootConf = "/etc/nftables.conf"
	if err := n.Persist(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(n.RulesPath)
	got := string(b)
	if !strings.HasPrefix(got, ManagedMarker) || !strings.Contains(got, "\ntable inet spa {") {
		t.Fatalf("snapshot:\n%s", got)
	}
	// the snapshot is included from nftables.conf, which already flushes: it must not flush itself
	if strings.Contains(got, "flush ruleset") {
		t.Fatalf("snapshot must not flush the ruleset:\n%s", got)
	}
	if st, _ := os.Stat(n.RulesPath); st.Mode().Perm() != 0o600 {
		t.Fatal("snapshot must be 0600")
	}
}

// If the live ruleset is not ours any more (flushed, or replaced by another
// firewall), the good snapshot on disk must not be overwritten.
func TestPersistKeepsGoodSnapshotWhenTableIsGone(t *testing.T) {
	n, _ := fake("", "")
	n.RulesPath = filepath.Join(t.TempDir(), "spa.nft")
	if err := os.WriteFile(n.RulesPath, []byte("GOOD"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]Runner{
		"table missing": func(string, ...string) ([]byte, error) { return nil, errors.New("No such file or directory") },
		"not drop":      func(string, ...string) ([]byte, error) { return []byte("table inet spa {\n}\n"), nil },
	} {
		n.Run = run
		if n.Persist() == nil {
			t.Fatalf("%s: Persist must fail", name)
		}
		if b, _ := os.ReadFile(n.RulesPath); string(b) != "GOOD" {
			t.Fatalf("%s: snapshot was overwritten: %q", name, b)
		}
	}
}

func TestEnsureLoadedUsesBootConf(t *testing.T) {
	n, calls := fake("", "")
	n.BootConf = "/etc/nftables.conf"
	var loadedFrom string
	run := n.Run
	n.Run = func(stdin string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if joined == "list table inet spa" {
			return nil, errors.New("no such table") // table is not active
		}
		if len(args) == 2 && args[0] == "-f" {
			loadedFrom = args[1]
			return nil, nil
		}
		return run(stdin, args...)
	}
	loaded, err := n.EnsureLoaded()
	if err != nil || !loaded || loadedFrom != "/etc/nftables.conf" {
		t.Fatalf("loaded=%v err=%v from=%q calls=%v", loaded, err, loadedFrom, *calls)
	}
}

func TestBaselineContent(t *testing.T) {
	r := Baseline(40123, false)
	for _, must := range []string{
		"table inet spa", "policy drop", "udp dport 40123 accept",
		"ct state established ct direction reply accept", "ip saddr @allowed accept",
		"icmp type { destination-unreachable, time-exceeded, parameter-problem } drop",
	} {
		if !strings.Contains(r, must) {
			t.Errorf("baseline lacks %q", must)
		}
	}
	// nothing may admit ICMP/ping or other ports
	for _, bad := range []string{"icmp type echo", "tcp dport", "policy accept;\n\t\tiif"} {
		if strings.Contains(r, bad) {
			t.Errorf("baseline must not contain %q", bad)
		}
	}
}

// The UDP exceptions must be IPv4-only (the daemon listens on udp4), and the
// kernel's own ICMP/ICMPv6 error messages must be suppressed on output.
func TestBaselineIPv4OnlyExceptionsAndSilentICMP(t *testing.T) {
	r := Baseline(40123, false)
	for _, line := range strings.Split(r, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "udp ") && strings.HasSuffix(line, "accept") &&
			!strings.HasPrefix(line, "meta nfproto ipv4 ") {
			t.Errorf("UDP exception is not pinned to IPv4: %q", line)
		}
	}
	for _, must := range []string{
		"icmp type { destination-unreachable, time-exceeded, parameter-problem } drop",
		"icmpv6 type { destination-unreachable, time-exceeded, parameter-problem } drop",
	} {
		if !strings.Contains(r, must) {
			t.Errorf("baseline lacks %q", must)
		}
	}
}

func TestTelegramIncludedBeforeTable(t *testing.T) {
	conf := MainConf("/etc/spa/telegram.nft", "/etc/spa/spa.nft", true)
	flush := strings.Index(conf, "flush ruleset")
	tg := strings.Index(conf, `include "/etc/spa/telegram.nft"`)
	tbl := strings.Index(conf, `include "/etc/spa/spa.nft"`)
	if !(flush >= 0 && flush < tg && tg < tbl) {
		t.Fatalf("order must be flush, telegram, spa table:\n%s", conf)
	}
	if !strings.HasPrefix(conf, ManagedMarker) {
		t.Fatal("config must start with the managed marker")
	}
	if strings.Contains(MainConf("/etc/spa/telegram.nft", "/etc/spa/spa.nft", false), "telegram") {
		t.Fatal("telegram must not be mentioned when it was not chosen")
	}
}

func TestTelegramFileAndRule(t *testing.T) {
	f := TelegramFile()
	for _, cidr := range []string{
		"91.108.56.0/22", "91.108.4.0/22", "91.108.8.0/22", "91.108.16.0/22", "91.108.12.0/22",
		"149.154.160.0/20", "91.105.192.0/23", "91.108.20.0/22", "185.76.151.0/24",
	} {
		if !strings.Contains(f, cidr) {
			t.Errorf("telegram.nft lacks %s", cidr)
		}
	}
	if !strings.Contains(f, "define TELEGRAM_CIDRS = {") {
		t.Fatalf("telegram.nft must define the variable:\n%s", f)
	}
	if strings.Contains(Baseline(40123, false), "TELEGRAM_CIDRS") {
		t.Fatal("no telegram rule when it was not chosen")
	}
	if !strings.Contains(Baseline(40123, true), "ip saddr $TELEGRAM_CIDRS accept") {
		t.Fatal("telegram rule missing")
	}
}

// ---- real nft, only when explicitly enabled (run inside `unshare -n`) ----

func realNft(t *testing.T) *Nft {
	if os.Getenv("SPA_NFT_TEST") != "1" {
		t.Skip("set SPA_NFT_TEST=1 and run inside a private netns (unshare -n)")
	}
	bin, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("no nft")
	}
	dir := t.TempDir()
	rules, boot := filepath.Join(dir, "spa.nft"), filepath.Join(dir, "nftables.conf")
	if err := os.WriteFile(rules, []byte(Baseline(40123, false)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(boot, []byte(MainConf(filepath.Join(dir, "telegram.nft"), rules, false)), 0o600); err != nil {
		t.Fatal(err)
	}
	n := New(bin, rules, boot, 0)
	if err := n.Check(boot); err != nil {
		t.Fatalf("config does not validate: %v", err)
	}
	if loaded, err := n.EnsureLoaded(); err != nil || !loaded {
		t.Fatalf("EnsureLoaded: %v %v", loaded, err)
	}
	return n
}

func TestRealNftLifecycle(t *testing.T) {
	n := realNft(t)
	if err := n.VerifyLocked(); err != nil {
		t.Fatalf("baseline must be locked: %v", err)
	}
	a, b := netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("198.51.100.9")

	if id, err := n.Allow(a); err != nil || id != 1 {
		t.Fatalf("first client: id=%d err=%v", id, err)
	}
	n.Retention = 15 * time.Minute
	if id, err := n.Allow(b); err != nil || id != 2 {
		t.Fatalf("second client: id=%d err=%v", id, err)
	}
	// re-knock: same number, timeout refreshed (now timed because retention is set)
	if id, err := n.Allow(a); err != nil || id != 1 {
		t.Fatalf("refresh: id=%d err=%v", id, err)
	}
	es, err := n.List()
	if err != nil || len(es) != 2 {
		t.Fatalf("%v %+v", err, es)
	}
	if es[0].IP != b || es[0].ID != 2 || es[0].Permanent || es[0].Expires < 14*time.Minute {
		t.Fatalf("second entry: %+v", es[0])
	}
	if es[1].IP != a || es[1].ID != 1 || es[1].Permanent {
		t.Fatalf("first entry (refreshed): %+v", es[1])
	}

	// snapshot survives a "reboot": wipe the ruleset, reload from file
	if _, err := n.Run("", "flush", "ruleset"); err != nil {
		t.Fatal(err)
	}
	if loaded, err := n.EnsureLoaded(); err != nil || !loaded {
		t.Fatalf("reload: %v %v", loaded, err)
	}
	if es, _ = n.List(); len(es) != 2 || es[0].ID != 2 || es[0].Expires < 14*time.Minute {
		t.Fatalf("after reload: %+v", es)
	}

	if _, err := n.Delete("2"); err != nil { // by number
		t.Fatal(err)
	}
	if id, _ := n.Allow(netip.MustParseAddr("192.0.2.50")); id != 2 { // max is #1 now
		t.Fatalf("next number after deleting #2: %d", id)
	}
	if _, err := n.Delete("203.0.113.7"); err != nil { // by IP
		t.Fatal(err)
	}
	if _, err := n.Delete("192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	if es, _ = n.List(); len(es) != 0 {
		t.Fatalf("not empty: %+v", es)
	}
	n.Run("", "flush", "ruleset")
	n.EnsureLoaded()
	if es, _ = n.List(); len(es) != 0 {
		t.Fatalf("deletion not persisted: %+v", es)
	}
}
