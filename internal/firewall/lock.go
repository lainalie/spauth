package firewall

import "sync"

// persistMu serialises writers inside one process (the daemon's periodic save
// and the knock handler run in different goroutines).
var persistMu sync.Mutex

// WithLock runs fn while holding an exclusive lock on path+".lock": across
// goroutines AND across processes (the daemon, `spa-server delete/save/init`).
//
// Taking the nft snapshot and publishing it must happen under this lock.
// Otherwise a writer that took its snapshot earlier can publish it after one
// taken later, and the older ruleset (with an already revoked IP) wins.
func WithLock(path string, fn func() error) error {
	persistMu.Lock()
	defer persistMu.Unlock()
	unlock, err := lockFile(path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}
