package install

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// MinPort: ports below 1024 belong to system services; the knock port must not collide with them.
const MinPort = 1024

// CheckPortRange validates the number only.
func CheckPortRange(port int) error {
	if port < MinPort || port > 65535 {
		return fmt.Errorf("port must be between %d and 65535", MinPort)
	}
	return nil
}

// PortFree reports whether anything on this host already uses the port, over
// UDP or TCP, IPv4 or IPv6, by actually trying to bind it.
func PortFree(port uint16) error {
	addr := fmt.Sprintf(":%d", port)
	for _, network := range []string{"udp4", "udp6", "tcp4", "tcp6"} {
		var err error
		if strings.HasPrefix(network, "udp") {
			var pc net.PacketConn
			if pc, err = net.ListenPacket(network, addr); err == nil {
				pc.Close()
			}
		} else {
			var l net.Listener
			if l, err = net.Listen(network, addr); err == nil {
				l.Close()
			}
		}
		switch {
		case err == nil:
		case errors.Is(err, syscall.EADDRINUSE):
			return fmt.Errorf("port %d is already in use on this host (%s)", port, network)
		case network == "udp4":
			return fmt.Errorf("cannot use port %d: %v", port, err)
		}
		// other errors on the IPv6 families just mean IPv6 is unavailable here
	}
	return nil
}

// EphemeralRange returns the range the kernel uses for outgoing connections.
func EphemeralRange() (lo, hi int, ok bool) {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return 0, 0, false
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return 0, 0, false
	}
	lo, e1 := strconv.Atoi(f[0])
	hi, e2 := strconv.Atoi(f[1])
	return lo, hi, e1 == nil && e2 == nil
}

// IsActive reports whether a systemd unit is running.
func IsActive(unit string) bool {
	out, _ := sh("systemctl", "is-active", unit)
	return out == "active"
}
