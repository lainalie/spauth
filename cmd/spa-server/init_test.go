//go:build linux

package main

import (
	"bufio"
	"io"
	"net"
	"os"
	"spa-prototype/internal/install"
	"strconv"
	"strings"
	"testing"
)

// Bad input is rejected and asked again; a port in use is refused; the first valid free port wins.
func TestChoosePortRejectsBadAndBusy(t *testing.T) {
	busy, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	busyPort := busy.LocalAddr().(*net.UDPAddr).Port

	free, _ := net.ListenPacket("udp4", ":0")
	freePort := free.LocalAddr().(*net.UDPAddr).Port
	free.Close()

	input := strings.Join([]string{"abc", "", "22", "70000", strconv.Itoa(busyPort), strconv.Itoa(freePort)}, "\n") + "\n"
	got := choosePort(bufio.NewReader(strings.NewReader(input)), 0, 0, false)
	if int(got) != freePort {
		t.Fatalf("got %d, want %d", got, freePort)
	}
}

// Re-running init: the port of our own running daemon is accepted.
func TestChoosePortAllowsOwnPort(t *testing.T) {
	own, _ := net.ListenPacket("udp4", ":0")
	defer own.Close()
	p := own.LocalAddr().(*net.UDPAddr).Port
	if err := validatePort(p, uint16(p)); err != nil {
		t.Fatalf("own port rejected: %v", err)
	}
	if validatePort(p, 0) == nil {
		t.Fatal("busy port accepted when it is not ours")
	}
}

func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	f()
	w.Close()
	os.Stdout = old
	b, _ := io.ReadAll(r)
	return string(b)
}

func TestWarningTextAndColors(t *testing.T) {
	useColor = true
	defer func() { useColor = false }()
	out := captureStdout(t, func() {
		printWarning([]install.Finding{{Name: "ufw.service", Detail: "running"}}, true)
	})
	if strings.Contains(out, "40123") {
		t.Fatal("the warning must not mention any port number")
	}
	for _, must := range []string{"ALL incoming traffic", "MAY BE DROPPED", "already initialised", "ufw.service"} {
		if !strings.Contains(out, must) {
			t.Errorf("warning lacks %q", must)
		}
	}
	// the three important warnings are red
	red := "\033[1;31m"
	for _, line := range []string{"ALL incoming traffic", "MAY BE DROPPED", "stopped, disabled and flushed", "NEW password"} {
		i := strings.Index(out, line)
		if i < 0 || !strings.Contains(out[strings.LastIndex(out[:i], "\n")+1:i], red) {
			t.Errorf("line with %q is not red", line)
		}
	}
	if strings.Contains(out, "will always") || strings.Contains(out, "WILL BE DROPPED") {
		t.Fatal("must not promise that the session is always dropped")
	}
}
