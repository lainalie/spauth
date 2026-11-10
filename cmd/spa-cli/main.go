// spa-cli: the client. Builds for Linux, Windows, macOS.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"spa-prototype/internal/client"
	spacrypto "spa-prototype/internal/crypto"
	"spa-prototype/internal/passwd"
)

func main() {
	host := flag.String("host", "", "server IPv4 address or hostname")
	port := flag.Int("port", 0, "server UDP port (required)")
	timeout := flag.Duration("timeout", 30*time.Second, "how long to keep retrying")
	stdin := flag.Bool("password-stdin", false, "read the password from stdin")
	flag.Parse()

	if *host == "" || *port == 0 {
		fmt.Fprintln(os.Stderr, "usage: spa-cli --host SERVER --port PORT [--timeout 30s] [--password-stdin]")
		os.Exit(2)
	}
	if *port < 1 || *port > 65535 {
		log.Fatal("invalid port")
	}
	addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(*host, fmt.Sprint(*port)))
	if err != nil {
		log.Fatal(err)
	}

	pw, err := passwd.Read("Password: ", *stdin)
	if err != nil {
		log.Fatal(err)
	}
	if len(pw) == 0 {
		log.Fatal("empty password")
	}
	keys, err := spacrypto.SubKeys(spacrypto.DeriveMaster(pw))
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	res, err := client.Open(ctx, client.Options{
		Server:  addr.AddrPort(),
		Keys:    keys,
		Timeout: *timeout,
		OnSend: func(step string, n int) {
			if n == 1 {
				fmt.Fprintln(os.Stderr, "knocking...")
			}
		},
	})
	if errors.Is(err, client.ErrNoResponse) {
		fmt.Fprintln(os.Stderr, "No confirmation from the server. The server stays silent on any failure, so the cause cannot be told:")
		fmt.Fprintln(os.Stderr, "wrong password, UDP blocked on the way, wrong host/port, or the server is down.")
		os.Exit(1)
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("OK: access granted to %s (confirmed after %d datagram(s), %s)\n",
		res.Opened, res.Attempts, res.Elapsed.Round(time.Millisecond))
}
