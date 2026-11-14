//go:build linux

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"spa-prototype/internal/config"
	"spa-prototype/internal/install"
)

func printUninstallWarning(snap install.Snapshot, src install.Source, p install.Paths, keepFiles bool) {
	fmt.Println()
	fmt.Println(red("WARNING - READ CAREFULLY"))
	fmt.Println()
	fmt.Println(red("  * The SPA protection of this host is REMOVED. The knock service stops and spa-cli no longer works."))
	fmt.Println(red("  * The firewall is put back as it was before `spa-server init`; whatever it allowed or"))
	fmt.Println(red("    blocked then is in force again. If it allowed everything, this host is OPEN to the Internet."))
	fmt.Println(red("  * Your current SSH session MAY be dropped if the old rules do not allow it."))
	fmt.Println(red("  * The list of allowed clients and the password are deleted. A later `init` creates a new password."))
	fmt.Println()
	switch src {
	case install.SourceState:
		fmt.Println("What will be restored:")
		for _, line := range snap.Describe() {
			fmt.Println("      - " + line)
		}
	case install.SourceLegacy:
		fmt.Println("What will be restored (this host was set up by an older version of spa-server):")
		for _, line := range snap.Describe() {
			fmt.Println("      - " + line)
		}
		fmt.Println(red("  * The services that init stopped (ufw, firewalld, docker, ...) were NOT recorded by that version."))
		fmt.Println(red("    Their rules come back, but start the services yourself afterwards, e.g. `systemctl enable --now ufw`."))
	default:
		fmt.Println(red("  * NO record of the previous state was found. Nothing can be restored: after the removal this host"))
		fmt.Println(red("    has NO firewall rules from this tool and none from before - it is OPEN."))
		fmt.Println(red("    Enable your own firewall right after this (e.g. `ufw enable`, `systemctl enable --now nftables`)."))
	}
	fmt.Println()
	fmt.Println("What will be removed:")
	fmt.Printf("      - the daemon and the units spa-server.service, spa-firewall.service (autostart) in %s\n", p.UnitDir)
	fmt.Printf("      - the program %s (it is in PATH)\n", p.Bin)
	if keepFiles {
		fmt.Printf("      - NOT removed (--keep-files): %s\n", p.Dir)
	} else {
		fmt.Printf("      - the directory %s: key, configuration and copies of the old rules\n", p.Dir)
	}
	fmt.Println()
}

func uninstallCmd(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	dir := fs.String("dir", config.DefaultDir, "configuration directory")
	yes := fs.Bool("yes", false, "do not ask for confirmation (automation)")
	keep := fs.Bool("keep-files", false, "keep the configuration directory (key, config, copies of the old rules)")
	_ = fs.Parse(args)
	requireRoot()
	if !install.SystemdAvailable() {
		log.Fatal("systemd is required")
	}

	snap, src, err := install.LoadSnapshot(*dir, config.NftablesConf)
	if err != nil {
		log.Fatalf("cannot read the saved state, nothing was changed: %v", err)
	}
	p := install.DefaultPaths(*dir)
	printUninstallWarning(snap, src, p, *keep)

	if !*yes {
		in := bufio.NewReader(os.Stdin)
		if prompt(in, "Type 'yes' to uninstall: ") != "yes" {
			fmt.Println("Aborted. Nothing was changed.")
			return
		}
		if src == install.SourceNone && prompt(in, "No firewall will remain. Type 'open' to confirm: ") != "open" {
			fmt.Println("Aborted. Nothing was changed.")
			return
		}
	}

	// From here the connection we are typing over may die: keep going anyway.
	signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)
	if problems := install.Uninstall(snap, p, *keep); len(problems) > 0 {
		fmt.Println(red("UNINSTALL DID NOT COMPLETE. Nothing was removed, so the command can be run again:"))
		for _, pr := range problems {
			fmt.Println("  - " + pr)
		}
		fmt.Printf("Copies of the old rules: %s\n", snap.Dir)
		os.Exit(1)
	}
	fmt.Println("Done. The previous firewall state is restored and spa-server is removed.")
	if self, err := os.Executable(); err == nil {
		if self, err = filepath.EvalSymlinks(self); err == nil && self != p.Bin && !strings.HasPrefix(self, "/proc/") {
			fmt.Printf("The copy you ran from is still there, delete it yourself: %s\n", self)
		}
	}
}
