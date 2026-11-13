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
//     loopback, replies to connections WE opened, the SPA UDP port (IPv4 only),
//     DHCP replies (IPv4 only) and addresses in the "allowed" set.
//   - `ct direction reply` is what cuts every inbound-initiated connection
//     (including an existing SSH session) while keeping our own outbound traffic working.
//   - The UDP exceptions are pinned to IPv4 (`meta nfproto ipv4`): the daemon
//     listens on udp4 only, so an IPv6 packet to the knock port must not pass
//     the filter and be answered by the kernel with ICMPv6 port-unreachable.
//   - Outbound: unrestricted, except the ICMP/ICMPv6 error messages the kernel
//     itself generates (destination-unreachable, time-exceeded, parameter-problem),
//     so that the host never emits "port closed" and similar replies that would
//     reveal it is alive. The kernel answers some malformed packets (for example
//     with bad IP options, or incomplete fragments) with such errors before or
//     independently of the input chain; they still have to pass the output hook.
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
		meta nfproto ipv4 udp sport 67 udp dport 68 accept
		meta nfproto ipv4 udp dport %[4]d accept
	}

	chain output {
		type filter hook output priority filter; policy accept;
		oifname != "lo" icmp type { destination-unreachable, time-exceeded, parameter-problem } drop
		oifname != "lo" icmpv6 type { destination-unreachable, time-exceeded, parameter-problem } drop
	}
}
`, Family, Table, Set, port)
}
