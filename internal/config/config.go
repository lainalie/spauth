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
	// MaxRetentionMinutes is one year. 0 means "never expire".
	MaxRetentionMinutes = 525600
)

type Config struct {
	Port             uint16 `json:"port"`
	RetentionMinutes int    `json:"retention_minutes"` // 0 = keep allowed IPs forever
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
func RulesPath(dir string) string  { return filepath.Join(dir, "nftables.conf") }

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
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
