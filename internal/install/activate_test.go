package install

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sys replaces the system-command hooks with a recorder, so the exact order of
// operations can be asserted without touching the host.
type sys struct {
	calls []string
	// fail makes a command fail when its text contains the key; the value says
	// how many times it may still succeed before (0 = fail at once).
	fail map[string]int
}

func fakeSys(t *testing.T) *sys {
	s := &sys{fail: map[string]int{}}
	oldSh, oldShIn, oldLook := sh, shIn, lookPath
	t.Cleanup(func() { sh, shIn, lookPath = oldSh, oldShIn, oldLook })

	do := func(line string) error {
		s.calls = append(s.calls, line)
		for key, okLeft := range s.fail {
			if strings.Contains(line, key) {
				if okLeft > 0 {
					s.fail[key] = okLeft - 1
					return nil
				}
				return errors.New("injected failure")
			}
		}
		return nil
	}
	sh = func(name string, args ...string) (string, error) {
		return "", do(name + " " + strings.Join(args, " "))
	}
	shIn = func(stdin, name string, args ...string) (string, error) {
		first, _, _ := strings.Cut(stdin, "\n")
		return "", do(name + " " + strings.Join(args, " ") + " <<" + first)
	}
	lookPath = func(f string) (string, error) { return "/usr/sbin/" + f, nil }
	return s
}

func (s *sys) index(substr string, from int) int {
	for i := from; i < len(s.calls); i++ {
		if strings.Contains(s.calls[i], substr) {
			return i
		}
	}
	return -1
}

func (s *sys) last(substr string) int {
	for i := len(s.calls) - 1; i >= 0; i-- {
		if strings.Contains(s.calls[i], substr) {
			return i
		}
	}
	return -1
}

func units() []Finding {
	return []Finding{
		{Name: "ufw.service", unit: "ufw.service", wasActive: true, wasEnabled: true},
		{Name: "nftables.service", unit: "nftables.service", wasEnabled: true},
		{Name: "docker.service", unit: "docker.service", wasActive: true, wasEnabled: true},
		{Name: "nftables ruleset"}, // informational: no unit
	}
}

// The core of the ordering fix: our ruleset is loaded and verified BEFORE any
// other firewall is touched, and loaded again after they were stopped.
func TestActivateLoadsOurRulesBeforeDisablingOthers(t *testing.T) {
	s := fakeSys(t)
	verified := 0
	_, err := Activate(Activation{
		Snapshot: Snapshot{Units: units()},
		Verify:   func() error { verified++; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}

	first := s.index("systemctl restart spa-firewall.service", 0)
	ufwOff := s.index("ufw --force disable", 0)
	dockerOff := s.index("systemctl disable --now docker.service", 0)
	if first < 0 || ufwOff < 0 || dockerOff < 0 {
		t.Fatalf("missing calls:\n%s", strings.Join(s.calls, "\n"))
	}
	if !(first < ufwOff && first < dockerOff) {
		t.Fatalf("other firewalls were disabled before our rules were loaded:\n%s", strings.Join(s.calls, "\n"))
	}
	// and re-applied after the others were stopped (a stop may flush the ruleset)
	if again := s.last("systemctl restart spa-firewall.service"); again <= dockerOff {
		t.Fatalf("our rules were not re-applied after the others were disabled:\n%s", strings.Join(s.calls, "\n"))
	}
	if verified != 2 {
		t.Fatalf("verified %d times, want 2 (after load and after disabling)", verified)
	}
}

// Nothing after activation may flush the whole nft ruleset (that would remove
// our own table), and nftables.service is only disabled, not stopped (its stop
// action is `nft flush ruleset`).
func TestActivateNeverFlushesNftAndDoesNotStopNftablesService(t *testing.T) {
	s := fakeSys(t)
	if _, err := Activate(Activation{Snapshot: Snapshot{Units: units()}}); err != nil {
		t.Fatal(err)
	}
	for _, c := range s.calls {
		if strings.Contains(c, "nft flush") {
			t.Fatalf("nft ruleset was flushed: %q", c)
		}
		if strings.Contains(c, "nftables.service") && strings.Contains(c, "--now") {
			t.Fatalf("nftables.service must not be stopped: %q", c)
		}
	}
	if s.index("systemctl disable nftables.service", 0) < 0 {
		t.Fatalf("nftables.service was not disabled:\n%s", strings.Join(s.calls, "\n"))
	}
}

// Our ruleset does not come up: the old firewalls were never touched, and the
// old state is restored (before, protection was gone and nothing came back).
func TestActivateFailureBeforeAnythingIsDisabled(t *testing.T) {
	s := fakeSys(t)
	dir := t.TempDir()
	boot := filepath.Join(dir, "nftables.conf")
	if err := os.WriteFile(boot, []byte("NEW CONFIG"), 0o644); err != nil {
		t.Fatal(err)
	}
	snap := Snapshot{
		Units:       units(),
		Nft:         "table inet filter {\n}",
		Iptables:    map[string]string{"iptables": "*filter\nCOMMIT"},
		BootConf:    boot,
		BootData:    []byte("OLD CONFIG"),
		BootExisted: true,
	}
	_, err := Activate(Activation{Snapshot: snap, Verify: func() error { return errors.New("input chain is not default-drop") }})
	if err == nil || !strings.Contains(err.Error(), "did not come up") {
		t.Fatalf("want an activation error, got %v", err)
	}
	if s.index("ufw --force disable", 0) >= 0 || s.index("disable --now docker.service", 0) >= 0 {
		t.Fatalf("other firewalls were disabled although our rules never came up:\n%s", strings.Join(s.calls, "\n"))
	}
	if b, _ := os.ReadFile(boot); string(b) != "OLD CONFIG" {
		t.Fatalf("system nftables config was not restored: %q", b)
	}
	for _, want := range []string{
		"systemctl disable spa-firewall.service",
		"nft -f - <<flush ruleset",
		"iptables-restore  <<*filter",
	} {
		if s.index(want, 0) < 0 {
			t.Fatalf("rollback lacks %q:\n%s", want, strings.Join(s.calls, "\n"))
		}
	}
}

// The others were already disabled when our ruleset was wiped: everything must
// be put back, services are started last.
func TestActivateFailureAfterDisablingRestoresServices(t *testing.T) {
	s := fakeSys(t)
	n := 0
	snap := Snapshot{Units: units(), Nft: "table inet filter {\n}"}
	_, err := Activate(Activation{Snapshot: snap, Verify: func() error {
		n++
		if n == 2 {
			return errors.New("table spa is gone")
		}
		return nil
	}})
	if err == nil || !strings.Contains(err.Error(), "did not survive") {
		t.Fatalf("got %v", err)
	}
	off := s.index("systemctl disable --now docker.service", 0)
	if off < 0 {
		t.Fatal("the test needs the services to have been disabled first")
	}
	restoreNft := s.index("nft -f - <<flush ruleset", off)
	enable := s.index("systemctl enable ufw.service", off)
	start := s.index("systemctl start ufw.service", off)
	startDocker := s.index("systemctl start docker.service", off)
	if restoreNft < 0 || enable < 0 || start < 0 || startDocker < 0 {
		t.Fatalf("incomplete rollback:\n%s", strings.Join(s.calls, "\n"))
	}
	if !(restoreNft < start && restoreNft < startDocker) {
		t.Fatalf("services must be started after the ruleset is restored:\n%s", strings.Join(s.calls, "\n"))
	}
	// nftables.service was only enabled, not running: re-enabled but not started
	if s.index("systemctl start nftables.service", 0) >= 0 {
		t.Fatalf("a service that was not running was started:\n%s", strings.Join(s.calls, "\n"))
	}
	if s.index("systemctl enable nftables.service", 0) < 0 {
		t.Fatalf("a service that was enabled was not re-enabled:\n%s", strings.Join(s.calls, "\n"))
	}
}

// A failing `restart spa-firewall` is an activation failure too.
func TestActivateFailsWhenFirewallUnitFails(t *testing.T) {
	s := fakeSys(t)
	s.fail["systemctl restart spa-firewall.service"] = 0
	if _, err := Activate(Activation{Snapshot: Snapshot{Units: units()}}); err == nil {
		t.Fatal("expected an error")
	}
	if s.index("ufw --force disable", 0) >= 0 {
		t.Fatal("others were disabled although our unit failed")
	}
}

// A re-run of init must stop the old daemon first; one that is not running is left alone.
func TestStopDaemon(t *testing.T) {
	s := fakeSys(t)
	if err := StopDaemon(); err != nil || s.index("systemctl stop", 0) >= 0 {
		t.Fatalf("inactive daemon: err=%v calls=%v", err, s.calls)
	}
	// make is-active report "active"
	sh = func(name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		s.calls = append(s.calls, line)
		if line == "systemctl is-active spa-server.service" {
			return "active", nil
		}
		return "", nil
	}
	if err := StopDaemon(); err != nil || s.index("systemctl stop spa-server.service", 0) < 0 {
		t.Fatalf("active daemon was not stopped: err=%v calls=%v", err, s.calls)
	}
}

func TestTakeSnapshotKeepsCopies(t *testing.T) {
	fakeSys(t)
	dir := t.TempDir()
	boot := filepath.Join(dir, "nftables.conf")
	os.WriteFile(boot, []byte("old"), 0o644)
	// the fake sh returns "" for every command: nothing to copy but the boot config
	s, err := TakeSnapshot(dir, boot, units())
	if err != nil || !s.BootExisted || string(s.BootData) != "old" {
		t.Fatalf("%v %+v", err, s)
	}
	if _, err := TakeSnapshot(dir, filepath.Join(dir, "missing.conf"), nil); err != nil {
		t.Fatalf("a missing boot config is fine: %v", err)
	}
}
