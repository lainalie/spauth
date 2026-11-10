// Package install performs the system-level steps of `spa-server init`:
// finding and disabling other firewalls, making sure nftables is present and
// installing the systemd units. Linux + systemd only.
package install

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Finding describes something that will be disabled.
type Finding struct {
	Name   string
	Detail string
	unit   string // systemd unit to disable, "" if informational
}

// Units that apply or re-apply packet filtering rules. They are stopped and
// disabled so nothing can bring rules back after we flush them.
var firewallUnits = []string{
	"ufw.service", "firewalld.service", "nftables.service",
	"netfilter-persistent.service", "iptables.service", "ip6tables.service", "ebtables.service",
	"shorewall.service", "shorewall6.service", "csf.service", "lfd.service",
	"docker.service", "docker.socket",
}

var iptablesTools = []string{"iptables", "ip6tables", "iptables-legacy", "ip6tables-legacy"}

func sh(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

func SystemdAvailable() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

// DetectFirewalls lists active/enabled firewall services and loaded rules.
func DetectFirewalls() []Finding {
	var found []Finding
	for _, u := range firewallUnits {
		active, _ := sh("systemctl", "is-active", u)
		enabled, _ := sh("systemctl", "is-enabled", u)
		var st []string
		if active == "active" {
			st = append(st, "running")
		}
		if enabled == "enabled" {
			st = append(st, "enabled at boot")
		}
		if len(st) > 0 {
			found = append(found, Finding{Name: u, Detail: strings.Join(st, ", "), unit: u})
		}
	}
	if _, err := exec.LookPath("nft"); err == nil {
		if out, err := sh("nft", "list", "ruleset"); err == nil && strings.TrimSpace(out) != "" {
			found = append(found, Finding{Name: "nftables ruleset", Detail: fmt.Sprintf("%d lines of rules loaded", strings.Count(out, "\n")+1)})
		}
	}
	for _, t := range iptablesTools {
		if _, err := exec.LookPath(t); err != nil {
			continue
		}
		if out, err := sh(t + "-save"); err == nil {
			if n := strings.Count(out, "\n-A "); n > 0 || strings.HasPrefix(out, "-A ") {
				found = append(found, Finding{Name: t + " rules", Detail: fmt.Sprintf("%d rules loaded", n)})
			}
		}
	}
	return found
}

// DisableFirewalls stops+disables every detected firewall service and flushes
// all iptables/nftables rules. It returns non-fatal problems as warnings.
func DisableFirewalls(found []Finding) (warnings []string) {
	warn := func(f string, a ...any) { warnings = append(warnings, fmt.Sprintf(f, a...)) }
	if _, err := exec.LookPath("ufw"); err == nil {
		if out, err := sh("ufw", "--force", "disable"); err != nil {
			warn("ufw disable: %v: %s", err, out)
		}
	}
	for _, f := range found {
		if f.unit == "" {
			continue
		}
		if out, err := sh("systemctl", "disable", "--now", f.unit); err != nil {
			warn("systemctl disable --now %s: %v: %s", f.unit, err, out)
		}
	}
	for _, t := range iptablesTools {
		if _, err := exec.LookPath(t); err != nil {
			continue
		}
		for _, ch := range []string{"INPUT", "FORWARD", "OUTPUT"} {
			sh(t, "-P", ch, "ACCEPT")
		}
		sh(t, "-F")
		sh(t, "-X")
		for _, tb := range []string{"nat", "mangle", "raw"} {
			sh(t, "-t", tb, "-F")
			sh(t, "-t", tb, "-X")
		}
	}
	if _, err := exec.LookPath("nft"); err == nil {
		sh("nft", "flush", "ruleset")
	}
	return warnings
}

// EnsureNft returns the path of the nft binary, installing the package if needed.
func EnsureNft() (string, error) {
	if p, err := exec.LookPath("nft"); err == nil {
		return p, nil
	}
	type pm struct {
		bin  string
		args []string
	}
	for _, m := range []pm{
		{"apt-get", []string{"install", "-y", "nftables"}},
		{"dnf", []string{"install", "-y", "nftables"}},
		{"yum", []string{"install", "-y", "nftables"}},
		{"zypper", []string{"--non-interactive", "install", "nftables"}},
		{"pacman", []string{"-S", "--noconfirm", "nftables"}},
		{"apk", []string{"add", "nftables"}},
	} {
		if _, err := exec.LookPath(m.bin); err != nil {
			continue
		}
		if out, err := sh(m.bin, m.args...); err != nil {
			return "", fmt.Errorf("%s %s: %v\n%s", m.bin, strings.Join(m.args, " "), err, out)
		}
		if p, err := exec.LookPath("nft"); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("nftables is not installed and no supported package manager was found")
}

const BinPath = "/usr/local/bin/spa-server"

// InstallBinary copies the running executable to BinPath.
func InstallBinary() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return err
	}
	if self == BinPath {
		return nil
	}
	in, err := os.Open(self)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := BinPath + ".new"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, BinPath)
}

// WriteUnits installs spa-firewall.service (loads the ruleset very early at
// boot) and spa-server.service (the daemon).
func WriteUnits(nftBin, dir, rulesPath string) error {
	fw := fmt.Sprintf(`[Unit]
Description=SPA firewall (nftables default-deny ruleset)
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target shutdown.target
Wants=network-pre.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=%s -f %s

[Install]
WantedBy=sysinit.target
`, nftBin, rulesPath)
	srv := fmt.Sprintf(`[Unit]
Description=SPA knock daemon
After=spa-firewall.service network.target
Wants=spa-firewall.service

[Service]
ExecStart=%s serve --dir %s
Restart=always
RestartSec=2
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=%s

[Install]
WantedBy=multi-user.target
`, BinPath, dir, dir)
	if err := os.WriteFile("/etc/systemd/system/spa-firewall.service", []byte(fw), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile("/etc/systemd/system/spa-server.service", []byte(srv), 0o644); err != nil {
		return err
	}
	_, err := sh("systemctl", "daemon-reload")
	return err
}

// Systemctl runs systemctl and returns its combined output as an error on failure.
func Systemctl(args ...string) error {
	if out, err := sh("systemctl", args...); err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return nil
}
