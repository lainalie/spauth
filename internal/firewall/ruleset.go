package firewall

import (
	"fmt"
	"strings"
)

const (
	Family = "inet" // IPv4 + IPv6 in one table
	Table  = "spa"
	Set    = "allowed"
)

// TelegramCIDRs are the address ranges of Telegram that may be allowed through
// the firewall (opt-in at init).
var TelegramCIDRs = []string{
	"91.108.56.0/22",
	"91.108.4.0/22",
	"91.108.8.0/22",
	"91.108.16.0/22",
	"91.108.12.0/22",
	"149.154.160.0/20",
	"91.105.192.0/23",
	"91.108.20.0/22",
	"185.76.151.0/24",
}

// TelegramVar is the nft variable that telegram.nft defines.
const TelegramVar = "TELEGRAM_CIDRS"

// ManagedMarker starts the first line of every file we write, so that init can
// tell a file of ours from one written by someone else (which is backed up).
const ManagedMarker = "# Managed by spa-server."

// TelegramFile renders telegram.nft: only a variable, no rules. The rule that
// uses it lives in the spa table (see Baseline).
func TelegramFile() string {
	return fmt.Sprintf("%s Telegram address ranges, allowed to reach this host.\ndefine %s = { %s }\n",
		ManagedMarker, TelegramVar, strings.Join(TelegramCIDRs, ", "))
}

// MainConf renders the system nftables config (/etc/nftables.conf). It does
// not contain rules itself: it clears whatever was loaded before and includes
// our files, so any loader (spa-firewall.service, nftables.service) ends up
// with exactly the same result. telegramPath is included only if telegram is true.
func MainConf(telegramPath, rulesPath string, telegram bool) string {
	var b strings.Builder
	b.WriteString(ManagedMarker + " Loaded at boot by spa-firewall.service.\n")
	b.WriteString("# Do not add rules here: init overwrites this file. The rules of the spa table live in\n")
	b.WriteString("# " + rulesPath + " (kept in sync with the running daemon).\n")
	b.WriteString("flush ruleset\n")
	if telegram {
		fmt.Fprintf(&b, "include %q\n", telegramPath)
	}
	fmt.Fprintf(&b, "include %q\n", rulesPath)
	return b.String()
}

// Baseline renders the `inet spa` table with the default-deny ruleset
// (without "flush ruleset": that is MainConf's job). If telegram is true the
// table also accepts the addresses of the $TELEGRAM_CIDRS variable, which
// telegram.nft defines and which must be included first.
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
func Baseline(port uint16, telegram bool) string {
	tg := ""
	if telegram {
		tg = "\t\tip saddr $" + TelegramVar + " accept\n"
	}
	return fmt.Sprintf(`# Managed by spa-server. Included by /etc/nftables.conf.
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
%[5]s		meta nfproto ipv4 udp sport 67 udp dport 68 accept
		meta nfproto ipv4 udp dport %[4]d accept
	}

	chain output {
		type filter hook output priority filter; policy accept;
		oifname != "lo" icmp type { destination-unreachable, time-exceeded, parameter-problem } drop
		oifname != "lo" icmpv6 type { destination-unreachable, time-exceeded, parameter-problem } drop
	}
}
`, Family, Table, Set, port, tg)
}
