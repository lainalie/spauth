package install

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"spa-prototype/internal/config"
)

// StateFile is written by `spa-server init` BEFORE it changes anything, and is
// read by `spa-server uninstall` to put the host back as it was.
const StateFile = "restore.json"

// UnitDir is where our two systemd units live.
const UnitDir = "/etc/systemd/system"

// State is the part of Snapshot that must survive on disk: what the host looked
// like before the first `init`. The rules themselves are in BackupDir.
type State struct {
	Version     int         `json:"version"`
	BackupDir   string      `json:"backup_dir"`
	BootConf    string      `json:"boot_conf"`
	BootExisted bool        `json:"boot_existed"` // /etc/nftables.conf was there before init
	NftSaved    bool        `json:"nft_saved"`    // ruleset.nft in BackupDir holds the old nft rules
	Iptables    []string    `json:"iptables"`     // tools whose <tool>-save.rules are in BackupDir
	Units       []UnitState `json:"units"`
}

type UnitState struct {
	Name       string `json:"name"`
	WasActive  bool   `json:"was_active"`
	WasEnabled bool   `json:"was_enabled"`
}

// Where the restore information came from.
type Source int

const (
	SourceNone   Source = iota // nothing found: the old state cannot be restored
	SourceLegacy               // an older init: copies of the rules, but no list of services
	SourceState                // restore.json: everything is known
)

const (
	rulesetFile = "ruleset.nft"
	bootFile    = "boot.conf"
)

// StatePath is the location of restore.json.
func StatePath(dir string) string { return filepath.Join(dir, StateFile) }

// StateExists reports whether a restore.json was already written.
func StateExists(dir string) bool {
	_, err := os.Stat(StatePath(dir))
	return err == nil
}

// SaveState records s on disk (mode 0600). Call it before touching the system.
func SaveState(dir string, s Snapshot) error {
	st := State{Version: 1, BackupDir: s.Dir, BootConf: s.BootConf, BootExisted: s.BootExisted, NftSaved: s.Nft != ""}
	for t := range s.Iptables {
		st.Iptables = append(st.Iptables, t)
	}
	sort.Strings(st.Iptables)
	for _, f := range s.Units {
		if f.unit != "" {
			st.Units = append(st.Units, UnitState{Name: f.unit, WasActive: f.wasActive, WasEnabled: f.wasEnabled})
		}
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return config.WriteFileAtomic(StatePath(dir), append(b, '\n'), 0o600)
}

// RemoveState deletes restore.json (init failed and rolled back: nothing to restore later).
func RemoveState(dir string) { os.Remove(StatePath(dir)) }

// LoadSnapshot reads what init saved. bootConf is the system nftables config
// (used when only an older init's copies exist). Every file the state refers to
// must be readable: otherwise an error is returned BEFORE anything is changed,
// so a missing copy can never turn into "restore an empty ruleset".
func LoadSnapshot(dir, bootConf string) (Snapshot, Source, error) {
	raw, err := os.ReadFile(StatePath(dir))
	if os.IsNotExist(err) {
		return loadLegacy(dir, bootConf)
	}
	if err != nil {
		return Snapshot{}, SourceNone, err
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return Snapshot{}, SourceNone, fmt.Errorf("%s: %w", StatePath(dir), err)
	}
	snap := Snapshot{Dir: st.BackupDir, BootConf: st.BootConf, BootExisted: st.BootExisted, Iptables: map[string]string{}}
	if snap.BootConf == "" {
		snap.BootConf = bootConf
	}
	for _, u := range st.Units {
		snap.Units = append(snap.Units, Finding{Name: u.Name, unit: u.Name, wasActive: u.WasActive, wasEnabled: u.WasEnabled})
	}
	read := func(name string) (string, error) {
		b, err := os.ReadFile(filepath.Join(st.BackupDir, name))
		return string(b), err
	}
	if st.NftSaved {
		t, err := read(rulesetFile)
		if err != nil {
			return Snapshot{}, SourceNone, fmt.Errorf("the saved nftables rules are missing: %w", err)
		}
		snap.Nft = strings.TrimPrefix(t, "flush ruleset\n")
	}
	for _, tool := range st.Iptables {
		t, err := read(tool + "-save.rules")
		if err != nil {
			return Snapshot{}, SourceNone, fmt.Errorf("the saved %s rules are missing: %w", tool, err)
		}
		snap.Iptables[tool] = t
	}
	if st.BootExisted {
		t, err := read(bootFile)
		if err != nil {
			return Snapshot{}, SourceNone, fmt.Errorf("the saved %s is missing: %w", st.BootConf, err)
		}
		snap.BootData = []byte(t)
	}
	return snap, SourceState, nil
}

// loadLegacy handles a host set up by an older init: it left copies of the rules
// in backup-<time>/ and of a foreign /etc/nftables.conf as nftables.conf.orig,
// but not the list of services it had disabled. The EARLIEST backup is the
// state before the first init.
func loadLegacy(dir, bootConf string) (Snapshot, Source, error) {
	snap := Snapshot{BootConf: bootConf, Iptables: map[string]string{}}
	dirs, _ := filepath.Glob(filepath.Join(dir, "backup-*"))
	sort.Strings(dirs) // backup-<unix time>: same width, so lexical order is time order
	found := false
	if len(dirs) > 0 {
		snap.Dir, found = dirs[0], true
		if b, err := os.ReadFile(filepath.Join(dirs[0], rulesetFile)); err == nil {
			snap.Nft = strings.TrimPrefix(string(b), "flush ruleset\n")
		}
		for _, tool := range iptablesTools {
			if b, err := os.ReadFile(filepath.Join(dirs[0], tool+"-save.rules")); err == nil {
				snap.Iptables[tool] = string(b)
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, filepath.Base(bootConf)+".orig")); err == nil {
		snap.BootData, snap.BootExisted, found = b, true, true
	}
	if !found {
		return snap, SourceNone, nil
	}
	return snap, SourceLegacy, nil
}
