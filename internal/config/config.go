// Package config holds the small on-disk configuration of the daemon.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	DefaultDir = "/etc/spa"
	// NftablesConf is the system-wide nftables config: the one a distribution's
	// nftables.service (and our spa-firewall.service) loads. init overwrites it
	// with "flush ruleset" plus includes of our own files from DefaultDir.
	NftablesConf = "/etc/nftables.conf"
	// MaxRetentionMinutes is one year. 0 means "never expire".
	MaxRetentionMinutes = 525600
)

type Config struct {
	Port             uint16 `json:"port"`
	RetentionMinutes int    `json:"retention_minutes"` // 0 = keep allowed IPs forever
	Telegram         bool   `json:"telegram,omitempty"` // allow Telegram address ranges
}

func (c Config) Retention() time.Duration { return time.Duration(c.RetentionMinutes) * time.Minute }

func (c Config) Validate() error {
	if c.Port == 0 {
		return errors.New("invalid port")
	}
	if c.RetentionMinutes < 0 || c.RetentionMinutes > MaxRetentionMinutes {
		return fmt.Errorf("retention must be 0 (forever) or 1..%d minutes", MaxRetentionMinutes)
	}
	return nil
}

func ConfigPath(dir string) string { return filepath.Join(dir, "config.json") }
func KeyPath(dir string) string    { return filepath.Join(dir, "key") }

// RulesPath is our own nft file: the `inet spa` table (rules + allowed set),
// included by NftablesConf. The daemon keeps it in sync with the live table.
func RulesPath(dir string) string { return filepath.Join(dir, "spa.nft") }

// TelegramPath holds the Telegram address ranges (nft `define`), included
// before RulesPath, only if the administrator chose to allow Telegram.
func TelegramPath(dir string) string { return filepath.Join(dir, "telegram.nft") }

func Save(dir string, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return WriteFileAtomic(ConfigPath(dir), append(b, '\n'), 0o600)
}

func Load(dir string) (Config, error) {
	var c Config
	b, err := os.ReadFile(ConfigPath(dir))
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", ConfigPath(dir), err)
	}
	return c, c.Validate()
}

// WriteFileAtomic writes via a temp file + rename so a crash never leaves a
// half-written file (important for the firewall ruleset loaded at boot).
//
//   - The temp file is unique, so concurrent writers never share one.
//   - The data is fsynced BEFORE the rename: otherwise, after a power loss, the
//     new name may point to an empty file, and an empty ruleset loaded at boot
//     leaves the host open.
//   - The directory is fsynced afterwards so the rename itself survives.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	committed := false
	defer func() {
		if !committed {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(perm); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	committed = true
	if d, err := os.Open(dir); err == nil { // best effort: not supported everywhere
		d.Sync()
		d.Close()
	}
	return nil
}
