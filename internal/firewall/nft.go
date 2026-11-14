// Package firewall drives nftables. There is no database of its own: the
// nftables set `inet spa allowed` IS the whitelist, each element carrying a
// comment "id=<N> added=<RFC3339>" (N = 1, 2, 3, ... for convenient display and
// deletion) and, if retention is configured, a native
// nftables timeout. The table is snapshotted to our own file (RulesPath), which
// the system nftables config (BootConf, /etc/nftables.conf) includes at boot.
package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"spa-prototype/internal/config"
)

var (
	ErrNotFound = errors.New("no matching entry")
	ErrBadKey   = errors.New("not an IPv4 address or a numeric id")
	// ErrNotSaved: the change was applied to the running firewall, but writing
	// the snapshot that is loaded at boot failed.
	ErrNotSaved = errors.New("applied to the running firewall but NOT saved to disk")
)

// Runner executes nft: optional stdin, arguments, returns stdout.
type Runner func(stdin string, args ...string) ([]byte, error)

type Nft struct {
	Run       Runner
	RulesPath string        // snapshot of the `inet spa` table (our own .nft file)
	BootConf  string        // system config loaded at boot; includes RulesPath
	Retention time.Duration // 0 = forever
	Now       func() time.Time
}

func New(bin, rulesPath, bootConf string, retention time.Duration) *Nft {
	return &Nft{Run: execRunner(bin), RulesPath: rulesPath, BootConf: bootConf, Retention: retention, Now: time.Now}
}

func execRunner(bin string) Runner {
	return func(stdin string, args ...string) ([]byte, error) {
		cmd := exec.Command(bin, args...)
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Run(); err != nil {
			return out.Bytes(), fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
		}
		return out.Bytes(), nil
	}
}

// Entry is one whitelisted address.
type Entry struct {
	IP        netip.Addr
	ID        int    // 1..N; 0 for entries added by hand with nft
	Added     string // RFC3339 or ""
	Permanent bool
	Expires   time.Duration // time left, if !Permanent
}

// Allow whitelists ip and returns its number. An address that is already
// present keeps its number (its timeout is refreshed); a new address gets
// max+1. The change is ONE atomic nft transaction.
func (n *Nft) Allow(ip netip.Addr) (int, error) {
	ip = ip.Unmap()
	if !ip.Is4() {
		return 0, errors.New("only IPv4 is supported")
	}
	entries, err := n.List()
	if err != nil {
		return 0, err
	}
	id := nextID(entries, ip)
	attrs := ""
	if n.Retention > 0 {
		attrs = fmt.Sprintf(" timeout %ds", int64(n.Retention/time.Second))
	}
	comment := fmt.Sprintf("id=%d added=%s", id, n.Now().UTC().Format(time.RFC3339))
	script := fmt.Sprintf(
		"add element %[1]s %[2]s %[3]s { %[4]s }\n"+
			"delete element %[1]s %[2]s %[3]s { %[4]s }\n"+
			"add element %[1]s %[2]s %[3]s { %[4]s%[5]s comment \"%[6]s\" }\n",
		Family, Table, Set, ip, attrs, comment)
	if _, err := n.Run(script, "-f", "-"); err != nil {
		return 0, err
	}
	if err := n.Persist(); err != nil {
		log.Printf("PERSIST_ERROR err=%q (access is granted but will not survive a reboot until the next successful save)", err)
	}
	return id, nil
}

// nextID: an address already in the set keeps its number, a new one gets max+1.
// Numbers of deleted clients are not reused while a higher number still exists.
func nextID(entries []Entry, ip netip.Addr) int {
	max := 0
	for _, e := range entries {
		if e.IP == ip && e.ID > 0 {
			return e.ID
		}
		if e.ID > max {
			max = e.ID
		}
	}
	return max + 1
}

// List returns the current whitelist, sorted by address.
func (n *Nft) List() ([]Entry, error) {
	out, err := n.Run("", "-j", "list", "set", Family, Table, Set)
	if err != nil {
		return nil, err
	}
	return parseSet(out)
}

// Delete removes entries matching key: an IPv4 address or a number from List.
func (n *Nft) Delete(key string) ([]Entry, error) {
	addr, addrErr := netip.ParseAddr(key)
	id := 0
	if addrErr != nil {
		v, err := strconv.Atoi(key)
		if err != nil || v < 1 {
			return nil, ErrBadKey
		}
		id = v
	}
	all, err := n.List()
	if err != nil {
		return nil, err
	}
	var hit []Entry
	for _, e := range all {
		if (addrErr == nil && e.IP == addr.Unmap()) || (addrErr != nil && e.ID == id) {
			hit = append(hit, e)
		}
	}
	if len(hit) == 0 {
		return nil, ErrNotFound
	}
	var script strings.Builder
	for _, e := range hit {
		fmt.Fprintf(&script, "delete element %s %s %s { %s }\n", Family, Table, Set, e.IP)
	}
	if _, err := n.Run(script.String(), "-f", "-"); err != nil {
		return nil, err
	}
	if err := n.Persist(); err != nil {
		// The IP is already gone from the live set, but the snapshot loaded at
		// boot may still contain it. Do not report plain success.
		log.Printf("PERSIST_ERROR err=%q (the removal is not saved; an old snapshot could restore access after a reboot)", err)
		return hit, fmt.Errorf("%w: %v", ErrNotSaved, err)
	}
	return hit, nil
}

// VerifyLocked checks that our table is active and its input chain is default-drop.
func (n *Nft) VerifyLocked() error {
	out, err := n.Run("", "list", "chain", Family, Table, "input")
	if err != nil {
		return fmt.Errorf("firewall table %s %s is not active: %w", Family, Table, err)
	}
	if !strings.Contains(string(out), "policy drop") {
		return errors.New("the input chain is not default-drop")
	}
	return nil
}

// Persist snapshots the live `inet spa` table (rules and allowed set) to
// RulesPath (atomic, mode 0600). Elements keep their remaining time. Only our
// own table is saved: if it is missing (someone flushed the ruleset), Persist
// fails and the previous good snapshot stays untouched.
//
// Taking the snapshot and publishing it is ONE critical section (WithLock,
// shared with the other processes): a writer that listed the table earlier can
// never publish after one that listed it later, so a stale snapshot cannot
// bring back an IP that was revoked in between.
func (n *Nft) Persist() error {
	return WithLock(n.RulesPath, func() error {
		out, err := n.Run("", "list", "table", Family, Table)
		if err != nil {
			return err
		}
		if !strings.Contains(string(out), "policy drop") {
			return errors.New("the live spa table is not default-drop: snapshot not overwritten")
		}
		data := ManagedMarker + " Snapshot of the live " + Family + " " + Table +
			" table, included by " + n.BootConf + ".\n" + string(out)
		return config.WriteFileAtomic(n.RulesPath, []byte(data), 0o600)
	})
}

// PersistLoop refreshes the snapshot periodically so that, after a reboot,
// timed entries do not get back time that already elapsed.
func (n *Nft) PersistLoop(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := n.Persist(); err != nil {
				log.Printf("PERSIST_ERROR err=%q", err)
			}
		}
	}
}

// EnsureLoaded loads the system config (which includes our table) if our table
// is not active (safety net; normally spa-firewall.service has already done it
// at boot).
func (n *Nft) EnsureLoaded() (loaded bool, err error) {
	if _, err := n.Run("", "list", "table", Family, Table); err == nil {
		return false, nil
	}
	_, err = n.Run("", "-f", n.BootConf)
	return err == nil, err
}

// Check validates a ruleset file without applying it.
func (n *Nft) Check(path string) error {
	_, err := n.Run("", "-c", "-f", path)
	return err
}

type setDoc struct {
	Nftables []struct {
		Set *struct {
			Elem []json.RawMessage `json:"elem"`
		} `json:"set"`
	} `json:"nftables"`
}

type elemObj struct {
	Elem struct {
		Val     string `json:"val"`
		Timeout *int64 `json:"timeout"`
		Expires *int64 `json:"expires"`
		Comment string `json:"comment"`
	} `json:"elem"`
}

func parseSet(raw []byte) ([]Entry, error) {
	var doc setDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse nft json: %w", err)
	}
	var out []Entry
	for _, item := range doc.Nftables {
		if item.Set == nil {
			continue
		}
		for _, r := range item.Set.Elem {
			var e Entry
			var plain string
			if json.Unmarshal(r, &plain) == nil { // bare address, no attributes
				a, err := netip.ParseAddr(plain)
				if err != nil {
					continue
				}
				e.IP, e.Permanent = a, true
			} else {
				var o elemObj
				if err := json.Unmarshal(r, &o); err != nil {
					continue
				}
				a, err := netip.ParseAddr(o.Elem.Val)
				if err != nil {
					continue
				}
				e.IP = a
				e.Permanent = o.Elem.Timeout == nil
				if o.Elem.Expires != nil {
					e.Expires = time.Duration(*o.Elem.Expires) * time.Second
				}
				for _, f := range strings.Fields(o.Elem.Comment) {
					switch {
					case strings.HasPrefix(f, "id="):
						e.ID, _ = strconv.Atoi(strings.TrimPrefix(f, "id="))
					case strings.HasPrefix(f, "added="):
						e.Added = strings.TrimPrefix(f, "added=")
					}
				}
			}
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP.Less(out[j].IP) })
	return out, nil
}
