//go:build !linux

package firewall

// The server part runs on Linux only; on other systems (development, tests)
// the in-process mutex in WithLock is enough.
func lockFile(string) (func(), error) { return func() {}, nil }
