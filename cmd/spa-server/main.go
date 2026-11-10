//go:build linux

// spa-server: the server part runs on Linux only.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "init":
		initCmd(args)
	case "serve":
		serveCmd(args)
	case "list":
		listCmd(args)
	case "delete":
		deleteCmd(args)
	case "status":
		statusCmd(args)
	case "save":
		saveCmd(args)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  spa-server init   [--port N] [--retention MINUTES] [--yes]   set up the host (as root)
  spa-server serve                                             run the daemon (done by systemd)
  spa-server status                                            firewall / daemon / port overview
  spa-server list                                              show allowed clients
  spa-server delete <number|ip>                                  remove an allowed client
  spa-server save                                              snapshot the live ruleset to disk`)
}
