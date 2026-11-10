package install

import (
	"net"
	"testing"
)

func TestCheckPortRange(t *testing.T) {
	for _, p := range []int{-1, 0, 22, 1023, 65536, 99999} {
		if CheckPortRange(p) == nil {
			t.Errorf("%d accepted", p)
		}
	}
	for _, p := range []int{1024, 40123, 65535} {
		if err := CheckPortRange(p); err != nil {
			t.Errorf("%d rejected: %v", p, err)
		}
	}
}

func TestPortFreeDetectsUDPAndTCP(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0") // bound on a specific address
	if err != nil {
		t.Fatal(err)
	}
	udpPort := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	if PortFree(udpPort) == nil {
		t.Fatal("UDP port in use was reported free")
	}
	pc.Close()
	if err := PortFree(udpPort); err != nil {
		t.Fatalf("released UDP port reported busy: %v", err)
	}

	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpPort := uint16(l.Addr().(*net.TCPAddr).Port)
	if PortFree(tcpPort) == nil {
		t.Fatal("TCP port in use was reported free")
	}
	l.Close()
}
