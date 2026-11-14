package install

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"spa-prototype/internal/firewall"
)

// Paths are the places Uninstall removes things from (parameters, so that a
// test never touches the real /usr/local/bin or /etc/systemd).
type Paths struct {
	Dir     string // /etc/spa
	Bin     string // /usr/local/bin/spa-server
	UnitDir string // /etc/systemd/system
}

// DefaultPaths are the real locations.
func DefaultPaths(dir string) Paths { return Paths{Dir: dir, Bin: BinPath, UnitDir: UnitDir} }

// Uninstall puts the host back as it was and removes the utility.
//
//  1. The previous state is restored (the same code that undoes a failed init):
//     our units and daemon are disabled, /etc/nftables.conf, nft and iptables
//     rules come back, the services that were running or enabled are enabled
//     and started again.
//  2. Only if that fully worked: the unit files, the binary (it was in PATH)
//     and, unless keepFiles, the configuration directory (key, config, copies) are removed.
//
// If anything could not be restored, nothing is removed and the problems are
// returned: the tool and its copies stay, so the command can be run again.
func Uninstall(snap Snapshot, p Paths, keepFiles bool) (problems []string) {
	problems = Activation{Snapshot: snap}.Rollback()

	// our table must be gone from the running firewall
	if _, err := lookPath("nft"); err == nil {
		if _, err := sh("nft", "list", "table", firewall.Family, firewall.Table); err == nil {
			problems = append(problems, "our table "+firewall.Family+" "+firewall.Table+" is still loaded")
		}
	}
	if len(problems) > 0 {
		return problems
	}

	for _, u := range []string{"spa-firewall.service", "spa-server.service"} {
		if err := os.Remove(filepath.Join(p.UnitDir, u)); err != nil && !os.IsNotExist(err) {
			problems = append(problems, "remove "+u+": "+err.Error())
		}
	}
	if out, err := sh("systemctl", "daemon-reload"); err != nil {
		problems = append(problems, "systemctl daemon-reload: "+err.Error()+": "+out)
	}
	if err := os.Remove(p.Bin); err != nil && !os.IsNotExist(err) {
		problems = append(problems, "remove "+p.Bin+": "+err.Error())
	}
	if !keepFiles && len(problems) == 0 {
		if err := os.RemoveAll(p.Dir); err != nil {
			problems = append(problems, "remove "+p.Dir+": "+err.Error())
		}
	}
	return problems
}

// Describe lists what Uninstall is going to restore, for the confirmation text.
func (s Snapshot) Describe() []string {
	var out []string
	if s.Nft != "" {
		out = append(out, "nftables rules from before the installation")
	} else {
		out = append(out, "nftables: no rules (there were none before the installation)")
	}
	tools := make([]string, 0, len(s.Iptables))
	for t := range s.Iptables {
		tools = append(tools, t)
	}
	sort.Strings(tools)
	if len(tools) > 0 {
		out = append(out, "iptables rules ("+strings.Join(tools, ", ")+")")
	}
	if s.BootExisted {
		out = append(out, s.BootConf+" with its previous content")
	} else {
		out = append(out, s.BootConf+" will be deleted (it did not exist before)")
	}
	for _, f := range s.Units {
		if f.wasActive || f.wasEnabled {
			var st []string
			if f.wasEnabled {
				st = append(st, "enabled at boot")
			}
			if f.wasActive {
				st = append(st, "started")
			}
			out = append(out, fmt.Sprintf("%s: %s", f.Name, strings.Join(st, ", ")))
		}
	}
	return out
}
