//go:build linux

package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"spa-prototype/internal/config"
	"spa-prototype/internal/crypto"
	"spa-prototype/internal/firewall"
	"spa-prototype/internal/server"
)

// openFirewall builds the nftables driver from the saved configuration.
func openFirewall(dir string) (*firewall.Nft, config.Config) {
	cfg, err := config.Load(dir)
	if err != nil {
		log.Fatalf("cannot read configuration (run `spa-server init` first): %v", err)
	}
	bin, err := exec.LookPath("nft")
	if err != nil {
		log.Fatal("nft binary not found")
	}
	return firewall.New(bin, config.RulesPath(dir), cfg.Retention()), cfg
}

func serveCmd(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dir := fs.String("dir", config.DefaultDir, "configuration directory")
	_ = fs.Parse(args)

	master, err := crypto.LoadMasterKey(config.KeyPath(*dir))
	if err != nil {
		log.Fatal(err)
	}
	keys, err := crypto.SubKeys(master)
	if err != nil {
		log.Fatal(err)
	}
	nft, cfg := openFirewall(*dir)

	// Normally spa-firewall.service has loaded the ruleset at boot already.
	loaded, err := nft.EnsureLoaded()
	if err != nil {
		log.Fatalf("firewall table is not active and could not be loaded: %v", err)
	}
	if loaded {
		log.Printf("FIREWALL_LOADED rules restored from %s", config.RulesPath(*dir))
	}

	if err := nft.VerifyLocked(); err != nil {
		log.Printf("FIREWALL_NOT_LOCKED err=%q (this host is OPEN; check `spa-server status`)", err)
	} else {
		log.Printf("FIREWALL_ACTIVE incoming traffic is default-deny")
	}

	addr := netip.AddrPortFrom(netip.IPv4Unspecified(), cfg.Port)
	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(addr))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cfg.RetentionMinutes > 0 {
		go nft.PersistLoop(ctx, time.Minute)
	}

	log.Printf("SERVER_STARTED listen=%s protocol=v3 retention_minutes=%d", addr, cfg.RetentionMinutes)
	if err := server.New(keys, nft).Run(ctx, conn); err != nil {
		log.Fatal(err)
	}
	if err := nft.Persist(); err != nil {
		log.Printf("PERSIST_ERROR err=%q", err)
	}
	log.Printf("SERVER_STOPPED")
}
