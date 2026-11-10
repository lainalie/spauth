// Package crypto derives protocol keys from the shared password.
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	// ProtocolSalt is NOT a salt in the security sense. The product requirement
	// is "password only, no salt", but Argon2id's API needs a salt parameter, so
	// a public constant is used. It only domain-separates SPA from other uses of
	// Argon2id. Changing it changes every key: bump it together with the protocol.
	ProtocolSalt = "SPA-v03-Argon2id"

	KeySize     = 32
	MemoryKiB   = 64 * 1024
	Iterations  = 3
	Parallelism = 1
)

// Keys are the two directional keys. Using separate keys for request and
// response means a captured request can never be reflected back to the client
// as a valid "OK".
type Keys struct {
	ClientToServer []byte
	ServerToClient []byte
}

// DeriveMaster stretches the password into a 32-byte master key (slow, by design).
func DeriveMaster(password []byte) []byte {
	return argon2.IDKey(password, []byte(ProtocolSalt), Iterations, MemoryKiB, Parallelism, KeySize)
}

// SubKeys expands the master key into per-direction keys (HKDF-SHA256).
func SubKeys(master []byte) (Keys, error) {
	if len(master) != KeySize {
		return Keys{}, errors.New("master key must be 32 bytes")
	}
	c2s, err := expand(master, "spa v3 client->server")
	if err != nil {
		return Keys{}, err
	}
	s2c, err := expand(master, "spa v3 server->client")
	if err != nil {
		return Keys{}, err
	}
	return Keys{ClientToServer: c2s, ServerToClient: s2c}, nil
}

func expand(master []byte, info string) ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, master, nil, []byte(info)), k); err != nil {
		return nil, err
	}
	return k, nil
}

// SaveMasterKey stores the derived key (not the password) so the daemon can
// start unattended. The file is created 0600; it is as sensitive as the password
// for the purposes of this protocol.
func SaveMasterKey(path string, master []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(hex.EncodeToString(master) + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadMasterKey reads the key file and refuses group/world-accessible files.
func LoadMasterKey(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s has mode %o: must not be accessible by group/others (chmod 600)", path, st.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != KeySize {
		return nil, fmt.Errorf("%s: invalid key file", path)
	}
	return key, nil
}

const (
	PasswordLen      = 20
	passwordAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

// GeneratePassword returns a random PasswordLen-character password over
// a-zA-Z0-9 (about 119 bits of entropy). Characters are drawn uniformly
// (rand.Int does rejection sampling, so there is no modulo bias).
func GeneratePassword() (string, error) {
	max := big.NewInt(int64(len(passwordAlphabet)))
	out := make([]byte, PasswordLen)
	for i := range out {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = passwordAlphabet[n.Int64()]
	}
	return string(out), nil
}
