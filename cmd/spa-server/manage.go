//go:build linux

package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"text/tabwriter"
	"time"

	"spa-prototype/internal/config"
	"spa-prototype/internal/firewall"
	"spa-prototype/internal/install"
)

func requireRoot() {
	if os.Geteuid() != 0 {
		log.Fatal("this command must run as root")
	}
}

func fmtLeft(e firewall.Entry) string {
	if e.Permanent {
		return "never"
	}
	d := e.Expires.Round(time.Second)
	if d >= time.Hour {
		return fmt.Sprintf("%dh %02dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dm %02ds", int(d.Minutes()), int(d.Seconds())%60)
}

func listCmd(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	dir := fs.String("dir", config.DefaultDir, "configuration directory")
	_ = fs.Parse(args)
	requireRoot()

	nft, _ := openFirewall(*dir)
	entries, err := nft.List()
	if err != nil {
		log.Fatalf("cannot read the allowed set (is the firewall active?): %v", err)
	}
	if len(entries) == 0 {
		fmt.Println("No clients are currently allowed.")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tIP\tADDED (UTC)\tEXPIRES IN")
	for _, e := range entries {
		id, added := "-", "(added manually)"
		if e.ID > 0 {
			id, added = fmt.Sprint(e.ID), e.Added
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", id, e.IP, added, fmtLeft(e))
	}
	w.Flush()
}

func deleteCmd(args []string) {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	dir := fs.String("dir", config.DefaultDir, "configuration directory")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: spa-server delete <id|ip>")
		os.Exit(2)
	}
	requireRoot()

	nft, _ := openFirewall(*dir)
	removed, err := nft.Delete(fs.Arg(0))
	if errors.Is(err, firewall.ErrBadKey) {
		log.Fatalf("%q is neither an IPv4 address nor a number from `spa-server list`", fs.Arg(0))
	}
	if errors.Is(err, firewall.ErrNotFound) {
		log.Fatalf("no allowed client matches %q (see `spa-server list`)", fs.Arg(0))
	}
	if errors.Is(err, firewall.ErrNotSaved) {
		for _, e := range removed {
			fmt.Printf("Removed #%s %s from the running firewall.\n", orDash(e.ID), e.IP)
		}
		log.Fatalf("WARNING: the removal is NOT saved to disk (%v).\n"+
			"After a reboot or a crash the old snapshot may let this IP in again.\n"+
			"Fix the cause (disk full? read-only filesystem?) and run `spa-server save`.", err)
	}
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range removed {
		fmt.Printf("Removed #%s %s. Its connections are cut; it must knock again to get back in.\n", orDash(e.ID), e.IP)
	}
}

func saveCmd(args []string) {
	fs := flag.NewFlagSet("save", flag.ExitOnError)
	dir := fs.String("dir", config.DefaultDir, "configuration directory")
	_ = fs.Parse(args)
	requireRoot()
	nft, _ := openFirewall(*dir)
	if err := nft.Persist(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Ruleset saved to", config.RulesPath(*dir))
}

func orDash(id int) string {
	if id == 0 {
		return "-"
	}
	return fmt.Sprint(id)
}

func statusCmd(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	dir := fs.String("dir", config.DefaultDir, "configuration directory")
	_ = fs.Parse(args)
	requireRoot()

	nft, cfg := openFirewall(*dir)
	ret := "unlimited"
	if cfg.RetentionMinutes > 0 {
		ret = fmt.Sprintf("%d minutes", cfg.RetentionMinutes)
	}
	fmt.Printf("Knock port:       udp/%d\n", cfg.Port)
	fmt.Printf("Retention:        %s\n", ret)
	if cfg.Telegram {
		fmt.Println("Telegram ranges:  allowed without a knock")
	} else {
		fmt.Println("Telegram ranges:  not allowed")
	}
	if err := nft.VerifyLocked(); err != nil {
		fmt.Println("Firewall:         " + red("NOT LOCKED - this host is OPEN ("+err.Error()+")"))
	} else {
		fmt.Println("Firewall:         active, incoming traffic is default-deny")
	}
	if install.IsActive("spa-server.service") {
		fmt.Println("Daemon:           running")
	} else {
		fmt.Println("Daemon:           " + red("NOT running"))
	}
	if es, err := nft.List(); err == nil {
		fmt.Printf("Allowed clients:  %d (a scan from one of these addresses sees an ordinary open host)\n", len(es))
	}
}
