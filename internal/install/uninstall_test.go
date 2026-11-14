package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// realistic outputs for the two commands TakeSnapshot reads
func snapshotSys(t *testing.T) *sys {
	s := fakeSys(t)
	base := sh
	sh = func(name string, args ...string) (string, error) {
		line := strings.TrimSpace(name + " " + strings.Join(args, " "))
		switch line {
		case "nft list ruleset":
			s.calls = append(s.calls, line)
			return "table inet filter {\n\tchain input { policy accept; }\n}", nil
		case "iptables-save":
			s.calls = append(s.calls, line)
			return "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT", nil
		}
		return base(name, args...)
	}
	return s
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// What init saves is what uninstall reads: rules, boot config, and which services were running/enabled.
func TestStateRoundTrip(t *testing.T) {
	snapshotSys(t)
	dir := t.TempDir()
	boot := filepath.Join(dir, "etc-nftables.conf")
	write(t, boot, "OLD BOOT CONFIG")

	snap, err := TakeSnapshot(dir, boot, units())
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveState(dir, snap); err != nil {
		t.Fatal(err)
	}
	if !StateExists(dir) {
		t.Fatal("restore.json was not written")
	}
	if st, _ := os.Stat(StatePath(dir)); st.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("restore.json must be private: %v", st.Mode())
	}

	got, src, err := LoadSnapshot(dir, boot)
	if err != nil || src != SourceState {
		t.Fatalf("%v %v", err, src)
	}
	if !strings.Contains(got.Nft, "table inet filter") || strings.HasPrefix(got.Nft, "flush ruleset") {
		t.Fatalf("nft rules: %q", got.Nft)
	}
	if !strings.Contains(got.Iptables["iptables"], "COMMIT") {
		t.Fatalf("iptables: %v", got.Iptables)
	}
	if !got.BootExisted || string(got.BootData) != "OLD BOOT CONFIG" {
		t.Fatalf("boot config: %v %q", got.BootExisted, got.BootData)
	}
	byName := map[string]Finding{}
	for _, u := range got.Units {
		byName[u.Name] = u
	}
	if !byName["ufw.service"].wasActive || !byName["ufw.service"].wasEnabled ||
		byName["nftables.service"].wasActive || !byName["nftables.service"].wasEnabled {
		t.Fatalf("service states were not preserved: %+v", got.Units)
	}
	if len(got.Units) != 3 { // the informational "nftables ruleset" finding has no unit
		t.Fatalf("units: %+v", got.Units)
	}
}

// A missing copy must stop uninstall BEFORE anything is changed: restoring "an empty ruleset" would open the host.
func TestLoadSnapshotFailsWhenACopyIsMissing(t *testing.T) {
	snapshotSys(t)
	dir := t.TempDir()
	boot := filepath.Join(dir, "etc-nftables.conf")
	write(t, boot, "x")
	snap, _ := TakeSnapshot(dir, boot, nil)
	if err := SaveState(dir, snap); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{rulesetFile, "iptables-save.rules", bootFile} {
		keep, _ := os.ReadFile(filepath.Join(snap.Dir, name))
		os.Remove(filepath.Join(snap.Dir, name))
		if _, src, err := LoadSnapshot(dir, boot); err == nil || src != SourceNone {
			t.Fatalf("%s missing: want an error, got err=%v src=%v", name, err, src)
		}
		write(t, filepath.Join(snap.Dir, name), string(keep))
	}
	if _, _, err := LoadSnapshot(dir, boot); err != nil {
		t.Fatalf("all copies present again: %v", err)
	}
}

// A host set up by an older init: the EARLIEST backup is the original state.
func TestLoadSnapshotLegacy(t *testing.T) {
	dir := t.TempDir()
	boot := filepath.Join(dir, "nftables.conf")
	if _, src, err := LoadSnapshot(dir, boot); err != nil || src != SourceNone {
		t.Fatalf("empty dir: %v %v", err, src)
	}
	write(t, filepath.Join(dir, "backup-1700000100", rulesetFile), "flush ruleset\ntable inet ORIGINAL {\n}\n")
	write(t, filepath.Join(dir, "backup-1700000100", "iptables-save.rules"), "*filter\nCOMMIT\n")
	write(t, filepath.Join(dir, "backup-1700000900", rulesetFile), "flush ruleset\ntable inet spa {\n}\n") // a re-init
	write(t, filepath.Join(dir, "nftables.conf.orig"), "ORIG BOOT")

	snap, src, err := LoadSnapshot(dir, boot)
	if err != nil || src != SourceLegacy {
		t.Fatalf("%v %v", err, src)
	}
	if !strings.Contains(snap.Nft, "ORIGINAL") || strings.Contains(snap.Nft, "table inet spa") {
		t.Fatalf("must use the earliest backup, got %q", snap.Nft)
	}
	if snap.Iptables["iptables"] == "" || !snap.BootExisted || string(snap.BootData) != "ORIG BOOT" {
		t.Fatalf("%+v", snap)
	}
	if len(snap.Units) != 0 {
		t.Fatal("an older init did not record services")
	}
}

type layout struct{ p Paths }

func layoutOn(t *testing.T) layout {
	root := t.TempDir()
	l := layout{Paths{Dir: filepath.Join(root, "etc-spa"), Bin: filepath.Join(root, "bin", "spa-server"), UnitDir: filepath.Join(root, "units")}}
	write(t, l.p.Bin, "binary")
	write(t, filepath.Join(l.p.UnitDir, "spa-firewall.service"), "u1")
	write(t, filepath.Join(l.p.UnitDir, "spa-server.service"), "u2")
	write(t, filepath.Join(l.p.UnitDir, "ufw.service"), "someone else's unit")
	write(t, filepath.Join(l.p.Dir, "key"), "secret")
	return l
}

func (l layout) allGone() bool {
	return !exists(l.p.Bin) && !exists(filepath.Join(l.p.UnitDir, "spa-firewall.service")) &&
		!exists(filepath.Join(l.p.UnitDir, "spa-server.service")) && !exists(l.p.Dir)
}

func (l layout) allKept() bool {
	return exists(l.p.Bin) && exists(filepath.Join(l.p.UnitDir, "spa-firewall.service")) &&
		exists(filepath.Join(l.p.UnitDir, "spa-server.service")) && exists(filepath.Join(l.p.Dir, "key"))
}

func fullSnap(t *testing.T) Snapshot {
	boot := filepath.Join(t.TempDir(), "nftables.conf")
	write(t, boot, "OUR CONFIG")
	return Snapshot{
		Units: units(), Nft: "table inet filter {\n}", Iptables: map[string]string{"iptables": "*filter\nCOMMIT"},
		BootConf: boot, BootData: []byte("ORIGINAL CONFIG"), BootExisted: true,
	}
}

// The restore comes first, the services last; then the tool is removed.
func TestUninstallRestoresThenRemoves(t *testing.T) {
	s := fakeSys(t)
	s.fail["nft list table inet spa"] = 0 // our table is gone after the restore
	l := layoutOn(t)
	snap := fullSnap(t)

	if problems := Uninstall(snap, l.p, false); len(problems) > 0 {
		t.Fatalf("%v\n%s", problems, strings.Join(s.calls, "\n"))
	}
	if !l.allGone() {
		t.Fatal("the utility was not removed completely")
	}
	if !exists(filepath.Join(l.p.UnitDir, "ufw.service")) {
		t.Fatal("somebody else's unit file was removed")
	}
	if b, _ := os.ReadFile(snap.BootConf); string(b) != "ORIGINAL CONFIG" {
		t.Fatalf("the old nftables config was not restored: %q", b)
	}

	stop := s.index("systemctl disable --now spa-server.service", 0)
	nft := s.index("nft -f - <<flush ruleset", 0)
	ipt := s.index("iptables-restore", 0)
	start := s.index("systemctl start ufw.service", 0)
	startDocker := s.index("systemctl start docker.service", 0)
	reload := s.index("systemctl daemon-reload", 0)
	if stop < 0 || nft < 0 || ipt < 0 || start < 0 || startDocker < 0 || reload < 0 {
		t.Fatalf("incomplete:\n%s", strings.Join(s.calls, "\n"))
	}
	if !(stop < nft && nft < start && ipt < start && nft < startDocker && start < reload) {
		t.Fatalf("wrong order (daemon off, rules back, services on, reload):\n%s", strings.Join(s.calls, "\n"))
	}
	if s.index("systemctl start nftables.service", 0) >= 0 {
		t.Fatal("a service that was not running was started")
	}
	if s.index("systemctl enable nftables.service", 0) < 0 {
		t.Fatal("a service that was enabled at boot was not re-enabled")
	}
	if s.index("systemctl disable spa-firewall.service", 0) < 0 {
		t.Fatal("autostart of our firewall unit was not removed")
	}
}

func TestUninstallKeepFiles(t *testing.T) {
	s := fakeSys(t)
	s.fail["nft list table inet spa"] = 0
	l := layoutOn(t)
	if problems := Uninstall(fullSnap(t), l.p, true); len(problems) > 0 {
		t.Fatal(problems)
	}
	if exists(l.p.Bin) || !exists(filepath.Join(l.p.Dir, "key")) {
		t.Fatal("--keep-files must keep the directory and still remove the program")
	}
}

// If the old state cannot be restored, nothing is deleted, so the command can be repeated.
func TestUninstallRemovesNothingWhenRestoreFails(t *testing.T) {
	for name, failOn := range map[string]string{
		"a service does not start": "systemctl start ufw.service",
		"iptables-restore fails":   "iptables-restore",
		"nft restore fails":        "nft -f -",
	} {
		s := fakeSys(t)
		s.fail["nft list table inet spa"] = 0
		s.fail[failOn] = 0
		l := layoutOn(t)
		problems := Uninstall(fullSnap(t), l.p, false)
		if len(problems) == 0 {
			t.Fatalf("%s: no problem reported", name)
		}
		if !l.allKept() {
			t.Fatalf("%s: files were removed although the restore failed", name)
		}
	}
}

// If our table is still loaded after the restore, the host is not what was promised.
func TestUninstallDetectsOurTableStillLoaded(t *testing.T) {
	fakeSys(t) // `nft list table inet spa` succeeds: the table is still there
	l := layoutOn(t)
	problems := Uninstall(fullSnap(t), l.p, false)
	if len(problems) == 0 || !strings.Contains(strings.Join(problems, ";"), "still loaded") || !l.allKept() {
		t.Fatalf("problems=%v kept=%v", problems, l.allKept())
	}
}

// No record at all (or nft rules that did not exist): the table is removed by an
// explicit flush, and an nftables.conf that did not exist before is deleted.
func TestUninstallWithoutPreviousRules(t *testing.T) {
	s := fakeSys(t)
	s.fail["nft list table inet spa"] = 0
	l := layoutOn(t)
	boot := filepath.Join(t.TempDir(), "nftables.conf")
	write(t, boot, "OUR CONFIG")
	if problems := Uninstall(Snapshot{BootConf: boot, Iptables: map[string]string{}}, l.p, false); len(problems) > 0 {
		t.Fatal(problems)
	}
	if s.index("nft flush ruleset", 0) < 0 {
		t.Fatalf("our table was not removed:\n%s", strings.Join(s.calls, "\n"))
	}
	if exists(boot) {
		t.Fatal("an nftables.conf that did not exist before init must be deleted")
	}
	if !l.allGone() {
		t.Fatal("the utility was not removed")
	}
}

func TestDescribe(t *testing.T) {
	d := strings.Join(fullSnap(t).Describe(), "\n")
	for _, want := range []string{"nftables rules from before", "iptables rules (iptables)", "previous content", "ufw.service: enabled at boot, started", "nftables.service: enabled at boot"} {
		if !strings.Contains(d, want) {
			t.Errorf("description lacks %q:\n%s", want, d)
		}
	}
}
