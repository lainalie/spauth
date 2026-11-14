package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Snapshot is the state of the host before init changed anything. It is kept in
// memory to restore it if activation fails, and written to Dir for the administrator.
type Snapshot struct {
	Dir         string            // where the copies for the administrator were written ("" if none)
	Nft         string            // `nft list ruleset` before init
	Iptables    map[string]string // tool -> `<tool>-save` before init
	BootConf    string            // path of the system nftables config
	BootData    []byte            // its content before init
	BootExisted bool
	Units       []Finding // firewall services that were running or enabled
}

// TakeSnapshot records everything that init is about to change. Nothing on the
// host is modified except the copies written below dir.
func TakeSnapshot(dir, bootConf string, found []Finding) (Snapshot, error) {
	s := Snapshot{BootConf: bootConf, Units: found, Iptables: map[string]string{}}
	if data, err := os.ReadFile(bootConf); err == nil {
		s.BootData, s.BootExisted = data, true
	} else if !os.IsNotExist(err) {
		return s, err
	}
	if _, err := lookPath("nft"); err == nil {
		if out, err := sh("nft", "list", "ruleset"); err == nil {
			s.Nft = out
		}
	}
	for _, t := range iptablesTools {
		if _, err := lookPath(t); err != nil {
			continue
		}
		if out, err := sh(t + "-save"); err == nil && strings.TrimSpace(out) != "" {
			s.Iptables[t] = out
		}
	}

	files := map[string]string{}
	if s.Nft != "" {
		files["ruleset.nft"] = "flush ruleset\n" + s.Nft + "\n"
	}
	for t, rules := range s.Iptables {
		files[t+"-save.rules"] = rules + "\n"
	}
	if s.BootExisted {
		files[bootFile] = string(s.BootData)
	}
	if len(files) == 0 {
		return s, nil
	}
	s.Dir = filepath.Join(dir, fmt.Sprintf("backup-%d", time.Now().Unix()))
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return s, err
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(s.Dir, name), []byte(content), 0o600); err != nil {
			return s, err
		}
	}
	return s, nil
}

// StopDaemon stops a running spa-server.service (a re-run of init). It must
// happen BEFORE the new key and the empty client list are written, and the
// daemon's own final snapshot happens during the stop. A daemon that keeps
// running with the old key would keep saving its old client list over the new one.
func StopDaemon() error {
	if !IsActive("spa-server.service") {
		return nil
	}
	return Systemctl("stop", "spa-server.service")
}

// Activation switches the host to our firewall.
type Activation struct {
	Snapshot Snapshot
	Verify   func() error // checks that our table is loaded and default-drop
}

func (a Activation) apply() error {
	// restart, not start: the unit is a oneshot with RemainAfterExit, so on a
	// re-run `start` would do nothing. The unit loads the system config, whose
	// first line is `flush ruleset`: old rules are replaced with ours in ONE
	// atomic nft transaction, there is no moment without a filter.
	if err := Systemctl("restart", "spa-firewall.service"); err != nil {
		return err
	}
	if a.Verify != nil {
		return a.Verify()
	}
	return nil
}

// Activate puts our firewall in place in a safe order:
//
//  1. enable our units and load our ruleset (atomic replacement), verify it;
//  2. only then stop/disable the other firewalls (the host is protected by us meanwhile);
//  3. load our ruleset again (a stopped service may have flushed it) and verify.
//
// If any step fails, the previous state is restored (Rollback) and an error is
// returned: the host is never left half-configured and unprotected.
func Activate(a Activation) (warnings []string, err error) {
	if err := Systemctl("enable", "spa-firewall.service", "spa-server.service"); err != nil {
		return nil, a.fail(err)
	}
	if err := a.apply(); err != nil {
		return nil, a.fail(fmt.Errorf("our firewall did not come up: %w", err))
	}
	warnings = DisableFirewalls(a.Snapshot.Units)
	if err := a.apply(); err != nil {
		return warnings, a.fail(fmt.Errorf("our firewall did not survive disabling the others: %w", err))
	}
	return warnings, nil
}

func (a Activation) fail(cause error) error {
	if problems := a.Rollback(); len(problems) > 0 {
		return fmt.Errorf("%w; the previous state was restored with problems: %s", cause, strings.Join(problems, "; "))
	}
	return fmt.Errorf("%w; the previous firewall state was restored", cause)
}

// Rollback undoes Activate: our units are disabled, the old nftables config,
// rules and firewall services come back. It returns what could not be restored.
func (a Activation) Rollback() (problems []string) {
	s := a.Snapshot
	note := func(what string, err error) {
		if err != nil {
			problems = append(problems, what+": "+err.Error())
		}
	}
	sysctl := func(args ...string) {
		if out, err := sh("systemctl", args...); err != nil {
			problems = append(problems, fmt.Sprintf("systemctl %s: %v: %s", strings.Join(args, " "), err, out))
		}
	}

	sysctl("disable", "--now", "spa-server.service")
	sysctl("disable", "spa-firewall.service")

	if s.BootConf != "" {
		if s.BootExisted {
			note("restore "+s.BootConf, os.WriteFile(s.BootConf, s.BootData, 0o644))
		} else if err := os.Remove(s.BootConf); err != nil && !os.IsNotExist(err) {
			note("remove "+s.BootConf, err)
		}
	}
	if _, err := lookPath("nft"); err == nil {
		if s.Nft != "" {
			if out, err := shIn("flush ruleset\n"+s.Nft+"\n", "nft", "-f", "-"); err != nil {
				problems = append(problems, fmt.Sprintf("restore nft ruleset: %v: %s", err, out))
			}
		} else if out, err := sh("nft", "flush", "ruleset"); err != nil {
			problems = append(problems, fmt.Sprintf("nft flush ruleset: %v: %s", err, out))
		}
	}
	for tool, rules := range s.Iptables {
		if out, err := shIn(rules+"\n", tool+"-restore"); err != nil {
			problems = append(problems, fmt.Sprintf("%s-restore: %v: %s", tool, err, out))
		}
	}
	// services last: starting them may re-apply their own rules
	for _, f := range s.Units {
		if f.unit == "" {
			continue
		}
		if f.wasEnabled {
			sysctl("enable", f.unit)
		}
		if f.wasActive {
			sysctl("start", f.unit)
		}
	}
	return problems
}
