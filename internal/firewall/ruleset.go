package firewall

import "fmt"

const (
	Family = "inet" // IPv4 + IPv6 in one table
	Table  = "spa"
	Set    = "allowed"
)

// Baseline renders the complete default-deny ruleset.
//
//   - Inbound: everything is dropped (all protocols, IPv4 and IPv6) except
//     loopback, replies to connections WE opened, the SPA UDP port, DHCP
//     replies and addresses in the "allowed" set.
//   - `ct direction reply` is what cuts every inbound-initiated connection
//     (including an existing SSH session) while keeping our own outbound traffic working.
//   - Outbound: unrestricted, except ICMP "destination unreachable", so that the
//     host never emits "port closed" messages that would reveal it is alive.
//   - DHCP replies are allowed, otherwise a DHCP-configured VM loses its address
//     at boot/renewal. The output rule above keeps even that port silent.
//   - IPv6 is simply closed: the table is `inet` and nothing admits IPv6 traffic.
func Baseline(port uint16) string {
	return fmt.Sprintf(`# Managed by spa-server. Loaded at boot by spa-firewall.service.
flush ruleset

table %[1]s %[2]s {
	set %[3]s {
		type ipv4_addr
		flags timeout
	}

	chain input {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept
		ct state established ct direction reply accept
		ct state related accept
		ip saddr @%[3]s accept
		udp sport 67 udp dport 68 accept
		udp dport %[4]d accept
	}

	chain output {
		type filter hook output priority filter; policy accept;
		oifname != "lo" icmp type destination-unreachable drop
	}
}
`, Family, Table, Set, port)
}
