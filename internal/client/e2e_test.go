package client

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"spa-prototype/internal/crypto"
	"spa-prototype/internal/server"
)

var keys = crypto.Keys{
	ClientToServer: bytes.Repeat([]byte{1}, 32),
	ServerToClient: bytes.Repeat([]byte{2}, 32),
}

type fw struct{ n atomic.Int32 }

func (f *fw) Allow(netip.Addr) (int, error) { return int(f.n.Add(1)), nil }

func listen(t *testing.T) *net.UDPConn {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func startServer(t *testing.T, k crypto.Keys, f server.Firewall) netip.AddrPort {
	conn := listen(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go server.New(k, f).Run(ctx, conn)
	return conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

// lossyRelay drops the first dropUp client datagrams and first dropDown server datagrams.
func lossyRelay(t *testing.T, srv netip.AddrPort, dropUp, dropDown int32) netip.AddrPort {
	front := listen(t)
	back, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(srv))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { front.Close(); back.Close() })
	var clientAddr atomic.Pointer[net.UDPAddr]
	var up, down int32
	go func() {
		buf := make([]byte, 2048)
		for {
			n, a, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			clientAddr.Store(a)
			if atomic.AddInt32(&up, 1) <= dropUp {
				continue
			}
			back.Write(buf[:n])
		}
	}()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := back.Read(buf)
			if err != nil {
				return
			}
			if atomic.AddInt32(&down, 1) <= dropDown {
				continue
			}
			if a := clientAddr.Load(); a != nil {
				front.WriteToUDP(buf[:n], a)
			}
		}
	}()
	return front.LocalAddr().(*net.UDPAddr).AddrPort()
}

func opts(addr netip.AddrPort) Options {
	return Options{Server: addr, Keys: keys, Timeout: 20 * time.Second}
}

func TestOpenSimple(t *testing.T) {
	f := &fw{}
	res, err := Open(context.Background(), opts(startServer(t, keys, f)))
	if err != nil {
		t.Fatal(err)
	}
	if res.Opened != netip.MustParseAddr("127.0.0.1") || res.Attempts != 2 || f.n.Load() != 1 {
		t.Fatalf("%+v fw=%d", res, f.n.Load())
	}
}

// Lose 2 HELLOs, then 2 CHALLENGEs, then (in the open step) more: it must still converge,
// and the firewall action must happen exactly once.
func TestSurvivesLossInBothDirections(t *testing.T) {
	f := &fw{}
	relay := lossyRelay(t, startServer(t, keys, f), 2, 3)
	res, err := Open(context.Background(), opts(relay))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("confirmed after %d datagrams in %s", res.Attempts, res.Elapsed)
	if res.Attempts < 5 || f.n.Load() != 1 {
		t.Fatalf("attempts=%d fw=%d", res.Attempts, f.n.Load())
	}
}

func TestWrongPasswordGetsNothing(t *testing.T) {
	f := &fw{}
	o := opts(startServer(t, keys, f))
	o.Keys = crypto.Keys{ClientToServer: bytes.Repeat([]byte{5}, 32), ServerToClient: bytes.Repeat([]byte{6}, 32)}
	o.Timeout = 2 * time.Second
	if _, err := Open(context.Background(), o); err != ErrNoResponse || f.n.Load() != 0 {
		t.Fatalf("err=%v fw=%d", err, f.n.Load())
	}
}

func TestForgedAnswersIgnored(t *testing.T) {
	fake := listen(t)
	defer fake.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			_, a, err := fake.ReadFromUDP(buf)
			if err != nil {
				return
			}
			fake.WriteToUDP(bytes.Repeat([]byte{0xAA}, 66), a)
			fake.WriteToUDP([]byte("OK"), a)
		}
	}()
	o := opts(fake.LocalAddr().(*net.UDPAddr).AddrPort())
	o.Timeout = 2 * time.Second
	if _, err := Open(context.Background(), o); err != ErrNoResponse {
		t.Fatalf("forged answer accepted: %v", err)
	}
}
