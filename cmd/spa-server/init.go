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

func printWarning(found []install.Finding, existing bool) {
	fmt.Println()
	fmt.Println(red("WARNING - READ CAREFULLY"))
	fmt.Println()
	fmt.Println(red("  * ALL incoming traffic to this host will be blocked: every port and every protocol,"))
	fmt.Println(red("    IPv4 and IPv6, except one UDP \"knock\" port that you will choose in a moment."))
	fmt.Println(red("  * This includes SSH. Your CURRENT SSH SESSION and other incoming connections MAY BE DROPPED"))
	fmt.Println(red("    as soon as the firewall is applied. Do not count on the session surviving."))
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
	filesOnly := fs.Bool("files-only", false, "development: only create key/config/ruleset files; do not touch the system")
	_ = fs.Parse(args)

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

	// Everything is prepared BEFORE the lockdown, so a mistake cannot leave a half-configured host.
	if err := crypto.SaveMasterKey(config.KeyPath(*dir), master); err != nil {
		log.Fatal(err)
	}
	if err := config.Save(*dir, cfg); err != nil {
		log.Fatal(err)
	}
	rules := config.RulesPath(*dir)
	if err := config.WriteFileAtomic(rules, []byte(firewall.Baseline(cfg.Port)), 0o600); err != nil {
		log.Fatal(err)
	}
	if nftBin != "" {
		if err := firewall.New(nftBin, rules, 0).Check(rules); err != nil {
			log.Fatalf("generated ruleset failed validation, nothing was changed: %v", err)
		}
	}
	if *filesOnly {
		fmt.Printf("Files written to %s (development mode: the system was not touched).\n", *dir)
		return
	}
	if err := install.InstallBinary(); err != nil {
		log.Fatal(err)
	}
	if err := install.WriteUnits(nftBin, *dir, rules); err != nil {
		log.Fatal(err)
	}

	// From here the connection we are typing over may die: keep going anyway.
	signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)
	for _, w := range install.DisableFirewalls(found) {
		fmt.Println("warning:", w)
	}
	if err := install.Systemctl("enable", "spa-firewall.service", "spa-server.service"); err != nil {
		log.Fatal(err)
	}

	fmt.Println("\nApplying the firewall now. Your SSH session MAY be dropped.")
	// restart, not start: the unit is a oneshot with RemainAfterExit, so on a
	// re-run `start` would do nothing and leave the host open after the flush above.
	if err := install.Systemctl("restart", "spa-firewall.service"); err != nil {
		fmt.Println(red("FIREWALL WAS NOT APPLIED - this host is currently OPEN: " + err.Error()))
		os.Exit(1)
	}
	if err := firewall.New(nftBin, rules, 0).VerifyLocked(); err != nil {
		fmt.Println(red("FIREWALL CHECK FAILED - this host may be OPEN: " + err.Error()))
		os.Exit(1)
	}
	if err := install.Systemctl("restart", "spa-server.service"); err != nil {
		fmt.Println(red("the firewall is active but the daemon did not start: " + err.Error()))
		os.Exit(1)
	}
	fmt.Println("Done. The host is closed; knock with: spa-cli --host <this-server> --port", cfg.Port)
	fmt.Println("Check the state any time with: sudo spa-server status")
}
