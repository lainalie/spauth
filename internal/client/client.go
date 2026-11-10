// Package client performs the two-step SPA exchange (HELLO -> CHALLENGE,
// OPEN -> OK), retransmitting each step until the authentic answer arrives.
package client

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"spa-prototype/internal/crypto"
	"spa-prototype/internal/protocol"
)

var ErrNoResponse = errors.New("no confirmation from server")

type Options struct {
	Server  netip.AddrPort // resolved once, so all retransmissions go to one address
	Keys    crypto.Keys
	Timeout time.Duration                  // total time for both steps (default 30s)
	OnSend  func(step string, attempt int) // optional progress callback
}

type Result struct {
	Opened   netip.Addr // the address the server whitelisted (your public IP as it sees it)
	Attempts int        // datagrams sent in total
	Elapsed  time.Duration
}

func Open(ctx context.Context, o Options) (Result, error) {
	if o.Timeout <= 0 {
		o.Timeout = 30 * time.Second
	}
	start := time.Now()
	deadline := start.Add(o.Timeout)

	token, err := protocol.NewToken()
	if err != nil {
		return Result{}, err
	}
	hello, err := protocol.Seal(o.Keys.ClientToServer, protocol.Frame{Type: protocol.TypeHello, Token: token})
	if err != nil {
		return Result{}, err
	}

	// A connected UDP socket: the kernel discards datagrams from any other
	// source, so forged replies from third parties are never even read.
	conn, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(o.Server))
	if err != nil {
		return Result{}, err
	}
	defer conn.Close()

	attempts := 0
	ex := func(step string, packet []byte, accept func(protocol.Frame) bool) error {
		return exchange(ctx, conn, packet, deadline, &attempts, func(n int) {
			if o.OnSend != nil {
				o.OnSend(step, n)
			}
		}, func(b []byte) bool {
			f, err := protocol.Open(o.Keys.ServerToClient, b)
			return err == nil && accept(f)
		})
	}

	var ch protocol.Frame
	if err := ex("hello", hello, func(f protocol.Frame) bool {
		ok := f.Type == protocol.TypeChallenge && f.Token == token
		if ok {
			ch = f
		}
		return ok
	}); err != nil {
		return Result{Attempts: attempts, Elapsed: time.Since(start)}, err
	}

	open, err := protocol.Seal(o.Keys.ClientToServer, protocol.Frame{
		Type: protocol.TypeOpen, IP: ch.IP, Token: token, Challenge: ch.Challenge})
	if err != nil {
		return Result{}, err
	}
	var ok protocol.Frame
	if err := ex("open", open, func(f protocol.Frame) bool {
		good := f.Type == protocol.TypeOK && f.Token == token && f.Challenge == ch.Challenge
		if good {
			ok = f
		}
		return good
	}); err != nil {
		return Result{Attempts: attempts, Elapsed: time.Since(start)}, err
	}
	return Result{Opened: netip.AddrFrom4(ok.IP), Attempts: attempts, Elapsed: time.Since(start)}, nil
}

// exchange sends the SAME packet on a backoff schedule until accept() approves
// an incoming datagram or the deadline passes. Anything else received is ignored.
func exchange(ctx context.Context, conn *net.UDPConn, packet []byte, deadline time.Time,
	attempts *int, onSend func(int), accept func([]byte) bool) error {

	buf := make([]byte, 2048)
	wait := 400 * time.Millisecond
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		*attempts++
		onSend(*attempts)
		if _, err := conn.Write(packet); err != nil {
			return err
		}
		until := time.Now().Add(wait)
		if until.After(deadline) {
			until = deadline
		}
		_ = conn.SetReadDeadline(until)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				var ne net.Error
				if !(errors.As(err, &ne) && ne.Timeout()) {
					time.Sleep(time.Until(until)) // e.g. a surfaced ICMP error: wait out the interval
				}
				break
			}
			if accept(buf[:n]) {
				return nil
			}
		}
		if wait = wait * 8 / 5; wait > 5*time.Second {
			wait = 5 * time.Second
		}
	}
	return ErrNoResponse
}
