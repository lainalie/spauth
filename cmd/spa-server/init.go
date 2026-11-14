//go:build linux

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"spa-prototype/internal/config"
	"spa-prototype/internal/crypto"
	"spa-prototype/internal/firewall"
	"spa-prototype/internal/install"
)

func prompt(in *bufio.Reader, msg string) string {
	fmt.Print(msg)
	line, err := in.ReadString('\n')
	if err != nil && err != io.EOF {
		log.Fatal(err)
	}
	if err == io.EOF && line == "" {
		log.Fatal("input closed; nothing was changed")
	}
	return strings.TrimSpace(line)
}

// validatePort checks range and that nothing uses the port. own is the port of
// our own running daemon (a re-run of init), which is of course allowed.
func validatePort(p int, own uint16) error {
	if err := install.CheckPortRange(p); err != nil {
		return err
	}
	if own != 0 && uint16(p) == own {
		return nil
	}
	return install.PortFree(uint16(p))
}

func choosePort(in *bufio.Reader, flagPort int, own uint16, yes bool) uint16 {
	if flagPort != 0 {
		if err := validatePort(flagPort, own); err != nil {
			log.Fatal(err)
		}
		return uint16(flagPort)
	}
	if yes {
		log.Fatal("--port is required together with --yes")
	}
	for {
		s := prompt(in, fmt.Sprintf("\nChoose the UDP port for the knock service (%d-65535).\n"+
			"Pick one yourself; do not reuse a well-known number: ", install.MinPort))
		p, err := strconv.Atoi(s)
		if err != nil {
			fmt.Println("Please enter a number.")
			continue
		}
		if err := validatePort(p, own); err != nil {
			fmt.Println(red("Rejected: ") + err.Error())
			continue
		}
		if lo, hi, ok := install.EphemeralRange(); ok && p >= lo && p <= hi {
			fmt.Printf("Note: %d lies in the system's outgoing-connection range (%d-%d). It works, but a port below %d\n"+
				"cannot ever be grabbed by an outgoing connection at boot.\n", p, lo, hi, lo)
		}
		return uint16(p)
	}
}

func askRetention(in *bufio.Reader) int {
	for {
		s := prompt(in, "\nHow long should an allowed IP stay whitelisted?\n"+
			"Enter minutes, or press Enter for unlimited [default: unlimited]: ")
		if s == "" || s == "0" {
			return 0
		}
		n, err := strconv.Atoi(s)
		if err == nil && n >= 1 && n <= config.MaxRetentionMinutes {
			return n
		}
		fmt.Printf("Please enter a whole number of minutes between 1 and %d, or press Enter.\n", config.MaxRetentionMinutes)
	}
}

// askTelegram asks whether the Telegram address ranges may reach this host.
// The default (Enter) is no.
func askTelegram(in *bufio.Reader) bool {
	for {
		switch strings.ToLower(prompt(in, "\nAllow the Telegram address ranges ("+strconv.Itoa(len(firewall.TelegramCIDRs))+
			" subnets) through the firewall without a knock? [yes/no, default: no]: ")) {
		case "", "n", "no":
			return false
		case "y", "yes":
			return true
		}
		fmt.Println("Please answer yes or no.")
	}
}

// backupForeignConf copies path into dir if it exists and was not written by us,
// so that overwriting the system nftables config never destroys someone's rules.
func backupForeignConf(path, dir string) (string, error) {
	old, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(string(old), firewall.ManagedMarker) {
		return "", nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	backup := filepath.Join(dir, filepath.Base(path)+".orig")
	for i := 1; ; i++ { // never overwrite an earlier backup
		if _, err := os.Stat(backup); os.IsNotExist(err) {
			break
		}
		backup = filepath.Join(dir, fmt.Sprintf("%s.orig.%d", filepath.Base(path), i))
	}
	return backup, os.WriteFile(backup, old, 0o600)
}

func printWarning(found []install.Finding, existing bool) {
	fmt.Println()
	fmt.Println(red("WARNING - READ CAREFULLY"))
	fmt.Println()
	fmt.Println(red("  * ALL incoming traffic to this host will be blocked: every port and every protocol,"))
	fmt.Println(red("    IPv4 and IPv6, except one UDP \"knock\" port that you will choose in a moment."))
	fmt.Println(red("  * This includes SSH. Your CURRENT SSH SESSION and other incoming connections MAY BE DROPPED"))
	fmt.Println(red("    as soon as the firewall is applied. Do not count on the session surviving."))
	fmt.Println(red("  * " + config.NftablesConf + " will be OVERWRITTEN (a copy of someone else's file is saved in " + config.DefaultDir + "):"))
	fmt.Println(red("    it will only clear the ruleset and include the files of this tool."))
	fmt.Println(red("  * Every other firewall will be stopped, disabled and flushed:"))
	if len(found) == 0 {
		fmt.Println("      (none detected)")
	}
	for _, f := range found {
		fmt.Printf("      - %s (%s)\n", f.Name, f.Detail)
	}
	if existing {
		fmt.Println(red("  * This host is already initialised. A NEW password will be created, the old one stops"))
		fmt.Println(red("    working, and all currently allowed clients are removed."))
	}
	fmt.Println("  * Outgoing traffic stays unrestricted.")
	fmt.Println("  * To get in afterwards, run on your computer:")
	fmt.Println("        spa-cli --host <this-server> --port <the port you choose>")
	fmt.Println("    and then connect as usual (e.g. ssh) from the same IP address.")
	fmt.Println("    If you are not sure you can do that, cancel now and use the server console.")
	fmt.Println()
}

func initCmd(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", config.DefaultDir, "configuration directory")
	port := fs.Int("port", 0, "UDP port of the knock service; asked interactively if omitted")
	retention := fs.Int("retention", -1, "minutes an allowed IP is kept (0 = unlimited); asked interactively if omitted")
	yes := fs.Bool("yes", false, "do not ask for confirmation (automation)")
	telegram := fs.Bool("telegram", false, "allow the Telegram address ranges; asked interactively if the flag is omitted (no with --yes)")
	nftConf := fs.String("nftables-conf", config.NftablesConf, "system nftables config to overwrite")
	filesOnly := fs.Bool("files-only", false, "development: only create key/config/ruleset files; do not touch the system")
	_ = fs.Parse(args)
	telegramSet := false
	fs.Visit(func(f *flag.Flag) { telegramSet = telegramSet || f.Name == "telegram" })
	if *filesOnly && *nftConf == config.NftablesConf {
		*nftConf = filepath.Join(*dir, "nftables.conf") // development: never touch /etc/nftables.conf
	}

	if *port != 0 {
		if err := install.CheckPortRange(*port); err != nil {
			log.Fatal(err)
		}
	}
	if !*filesOnly {
		requireRoot()
		if !install.SystemdAvailable() {
			log.Fatal("systemd is required")
		}
	}
	in := bufio.NewReader(os.Stdin)

	_, keyErr := os.Stat(config.KeyPath(*dir))
	existing := keyErr == nil
	var ownPort uint16
	if cfg, err := config.Load(*dir); err == nil && !*filesOnly && install.IsActive("spa-server.service") {
		ownPort = cfg.Port
	}

	// 1. warning + consent
	var found []install.Finding
	if !*filesOnly {
		found = install.DetectFirewalls()
		printWarning(found, existing)
		if !*yes && prompt(in, "Type 'yes' to continue: ") != "yes" {
			fmt.Println("Aborted. Nothing was changed.")
			return
		}
	}

	// 2. questions, asked only after consent
	cfg := config.Config{Port: choosePort(in, *port, ownPort, *yes)}
	cfg.RetentionMinutes = *retention
	if cfg.RetentionMinutes < 0 {
		cfg.RetentionMinutes = 0
		if !*yes {
			cfg.RetentionMinutes = askRetention(in)
		}
	}
	cfg.Telegram = *telegram
	if !telegramSet && !*yes {
		cfg.Telegram = askTelegram(in)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}

	var nftBin string
	if *filesOnly {
		nftBin, _ = exec.LookPath("nft")
	} else {
		fmt.Println("\nChecking nftables...")
		var err error
		if nftBin, err = install.EnsureNft(); err != nil {
			log.Fatal(err)
		}
	}

	pw, err := crypto.GeneratePassword()
	if err != nil {
		log.Fatal(err)
	}
	master := crypto.DeriveMaster([]byte(pw))

	bar := strings.Repeat("=", 74)
	fmt.Printf("\n%s\n  Your access password (shown ONLY ONCE - save it in a password manager):\n\n      %s\n\n"+
		"  The server stores only a derived key, never this text. If you lose the\n"+
		"  password, run `spa-server init` again to create a new one.\n%s\n", bar, lime(pw), bar)
	if !*yes {
		prompt(in, "\nPress Enter after you have saved the password... ")
	}

	rules, tgPath, boot := config.RulesPath(*dir), config.TelegramPath(*dir), *nftConf

	// Nothing on the host has been changed yet. Remember the current state NOW:
	// if activation fails below, it is put back (rules, services, nftables config).
	var snap install.Snapshot
	if !*filesOnly {
		var err error
		if snap, err = install.TakeSnapshot(*dir, boot, found); err != nil {
			log.Fatalf("cannot record the current firewall state, nothing was changed: %v", err)
		}
		if snap.Dir != "" {
			fmt.Println("A copy of the current firewall rules was saved in", snap.Dir)
		}
		// A re-run of init: the old daemon still holds the old key and keeps
		// saving its old client list. It is stopped BEFORE the new key and the
		// empty client list are written, so it cannot put the old state back.
		if err := install.StopDaemon(); err != nil {
			log.Fatalf("cannot stop the running daemon, nothing was changed: %v", err)
		}
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		log.Fatal(err)
	}

	// Everything is prepared BEFORE the lockdown, so a mistake cannot leave a half-configured host.
	// The files are written under the same lock as the snapshots of the running daemon and of
	// `spa-server save/delete`, so none of them can interleave with this.
	err = firewall.WithLock(rules, func() error {
		return writeInitFiles(*dir, cfg, master, nftBin, boot, rules, tgPath)
	})
	if err != nil {
		if !*filesOnly {
			err = fmt.Errorf("%w (the old daemon was stopped; the firewall that was active is still active; run init again)", err)
		}
		log.Fatal(err)
	}
	if *filesOnly {
		fmt.Printf("Files written to %s (development mode: the system was not touched).\n", *dir)
		return
	}

	act := install.Activation{
		Snapshot: snap,
		Verify:   firewall.New(nftBin, rules, boot, 0).VerifyLocked,
	}
	prepared := func() error {
		if err := install.InstallBinary(); err != nil {
			return err
		}
		return install.WriteUnits(nftBin, *dir, boot)
	}
	if err := prepared(); err != nil {
		if problems := act.Rollback(); len(problems) > 0 {
			fmt.Println(red("could not fully restore the previous state: " + strings.Join(problems, "; ")))
		}
		log.Fatalf("nothing was activated: %v", err)
	}

	// From here the connection we are typing over may die: keep going anyway.
	signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)
	fmt.Println("\nApplying the firewall now. Your SSH session MAY be dropped.")
	// Our ruleset is loaded and verified first; only then are the other firewalls disabled.
	warnings, err := install.Activate(act)
	for _, w := range warnings {
		fmt.Println("warning:", w)
	}
	if err != nil {
		fmt.Println(red("ACTIVATION FAILED: " + err.Error()))
		os.Exit(1)
	}
	if err := install.Systemctl("restart", "spa-server.service"); err != nil {
		fmt.Println(red("the firewall is active but the daemon did not start: " + err.Error()))
		os.Exit(1)
	}
	fmt.Println("Done. The host is closed; knock with: spa-cli --host <this-server> --port", cfg.Port)
	fmt.Println("Check the state any time with: sudo spa-server status")
}

// writeInitFiles writes key, config, our nft files and the system nftables
// config. The caller holds the snapshot lock. The system config is validated as
// a whole (nft -c follows the includes) BEFORE it replaces the old one.
func writeInitFiles(dir string, cfg config.Config, master []byte, nftBin, boot, rules, tgPath string) error {
	if err := crypto.SaveMasterKey(config.KeyPath(dir), master); err != nil {
		return err
	}
	if err := config.Save(dir, cfg); err != nil {
		return err
	}
	if err := config.WriteFileAtomic(rules, []byte(firewall.Baseline(cfg.Port, cfg.Telegram)), 0o600); err != nil {
		return err
	}
	if cfg.Telegram {
		if err := config.WriteFileAtomic(tgPath, []byte(firewall.TelegramFile()), 0o600); err != nil {
			return err
		}
	} else if err := os.Remove(tgPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	newBoot := boot + ".spa-new"
	if err := config.WriteFileAtomic(newBoot, []byte(firewall.MainConf(tgPath, rules, cfg.Telegram)), 0o644); err != nil {
		return err
	}
	if nftBin != "" {
		if err := firewall.New(nftBin, rules, boot, 0).Check(newBoot); err != nil {
			os.Remove(newBoot)
			return fmt.Errorf("generated ruleset failed validation: %w", err)
		}
	}
	backup, err := backupForeignConf(boot, dir)
	if err != nil {
		os.Remove(newBoot)
		return fmt.Errorf("cannot back up %s: %w", boot, err)
	}
	if backup != "" {
		fmt.Printf("The previous %s was saved as %s\n", boot, backup)
	}
	if err := os.Rename(newBoot, boot); err != nil {
		os.Remove(newBoot)
		return err
	}
	return nil
}
