// Package server is the SPA daemon logic (protocol v3, challenge-response).
//
// Rule: the server sends a datagram only in reply to a packet that decrypts
// with the correct key AND fits the protocol state. In every other case it stays
// completely silent. Time is used only for the server's own short-lived session
// table (monotonic, local); no timestamp is ever read from a packet.
package server

import (
	"context"
	"crypto/rand"
	"errors"
	"log"
	"net"
	"net/netip"
	"time"

	"spa-prototype/internal/crypto"
	"spa-prototype/internal/protocol"
)

// Firewall is what the server needs from the firewall layer.
type Firewall interface {
	// Allow whitelists ip and returns the client number shown by `spa-server list`.
	Allow(ip netip.Addr) (int, error)
}

const (
	sessionTTL  = 2 * time.Minute // how long a challenge stays usable
	maxSessions = 4096
	maxResends  = 20 // answers per session to retransmitted packets (bounds reflection abuse)
)

type session struct {
	src       netip.Addr
	token     [16]byte
	challenge [16]byte
	id        int // client number, set once granted
	created   time.Time
	granted   bool
	resends   int
}

type Server struct {
	keys crypto.Keys
	fw   Firewall

	byToken map[[16]byte]*session
	byChal  map[[16]byte]*session
	swept   time.Time

	invalidCount uint64
	lastInvalid  time.Time
}

func New(keys crypto.Keys, fw Firewall) *Server {
	return &Server{keys: keys, fw: fw, byToken: map[[16]byte]*session{}, byChal: map[[16]byte]*session{}}
}

// Run reads datagrams until ctx is cancelled. Single-threaded on purpose:
// session state and firewall changes are then trivially race-free.
func (s *Server) Run(ctx context.Context, conn *net.UDPConn) error {
	go func() { <-ctx.Done(); conn.Close() }()
	buf := make([]byte, 2048)
	for {
		n, src, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("READ_ERROR err=%q", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if reply := s.Handle(buf[:n], src, time.Now()); reply != nil {
			if _, err := conn.WriteToUDPAddrPort(reply, src); err != nil {
				log.Printf("WRITE_ERROR src=%s err=%q", src.Addr(), err)
			}
		}
	}
}

// Handle processes one datagram and returns the reply, or nil for silence.
// now is only used to expire sessions. Not safe for concurrent use.
func (s *Server) Handle(pkt []byte, src netip.AddrPort, now time.Time) []byte {
	ip := src.Addr().Unmap()
	if !ip.Is4() {
		return nil
	}
	f, err := protocol.Open(s.keys.ClientToServer, pkt)
	if err != nil {
		s.invalid(ip, len(pkt), "not a valid packet")
		return nil
	}
	s.sweep(now)
	switch f.Type {
	case protocol.TypeHello:
		return s.hello(f, ip, now)
	case protocol.TypeOpen:
		return s.open(f, ip, now)
	}
	s.invalid(ip, len(pkt), "unexpected message type")
	return nil
}

func (s *Server) hello(f protocol.Frame, ip netip.Addr, now time.Time) []byte {
	sess := s.byToken[f.Token]
	switch {
	case sess == nil:
		if len(s.byToken) >= maxSessions {
			log.Printf("SESSIONS_FULL src=%s", ip)
			return nil
		}
		sess = &session{src: ip, token: f.Token, created: now}
		if _, err := rand.Read(sess.challenge[:]); err != nil {
			return nil
		}
		s.byToken[sess.token] = sess
		s.byChal[sess.challenge] = sess
	case sess.src != ip: // the same HELLO replayed from another address
		log.Printf("REPLAY_DROPPED src=%s", ip)
		return nil
	case sess.resends >= maxResends:
		return nil
	default: // retransmission: same challenge again
		sess.resends++
	}
	return s.seal(protocol.Frame{Type: protocol.TypeChallenge, IP: ip.As4(), Token: sess.token, Challenge: sess.challenge})
}

func (s *Server) open(f protocol.Frame, ip netip.Addr, now time.Time) []byte {
	sess := s.byChal[f.Challenge]
	if sess == nil {
		s.invalid(ip, protocol.PacketSize, "unknown or expired challenge")
		return nil
	}
	if sess.src != ip || sess.token != f.Token || f.IP != ip.As4() {
		log.Printf("REPLAY_DROPPED src=%s", ip) // OPEN used from a different address
		return nil
	}
	if !sess.granted {
		id, err := s.fw.Allow(ip)
		if err != nil {
			// Not granted, so do not say OK; the client's retransmission retries.
			log.Printf("FIREWALL_ERROR src=%s err=%q", ip, err)
			return nil
		}
		sess.granted, sess.id = true, id
		log.Printf("AUTH_SUCCESS src=%s id=%d", ip, id)
	} else {
		if sess.resends >= maxResends {
			return nil
		}
		sess.resends++
		log.Printf("DUPLICATE_RESEND src=%s id=%d", ip, sess.id)
	}
	return s.seal(protocol.Frame{Type: protocol.TypeOK, IP: ip.As4(), Token: sess.token, Challenge: sess.challenge})
}

func (s *Server) seal(f protocol.Frame) []byte {
	p, err := protocol.Seal(s.keys.ServerToClient, f)
	if err != nil {
		log.Printf("SEAL_ERROR err=%q", err)
		return nil
	}
	return p
}

func (s *Server) sweep(now time.Time) {
	if now.Sub(s.swept) < 5*time.Second {
		return
	}
	s.swept = now
	for k, sess := range s.byToken {
		if now.Sub(sess.created) > sessionTTL {
			delete(s.byToken, k)
			delete(s.byChal, sess.challenge)
		}
	}
}

// invalid logs rejected packets, throttled so a flood cannot fill the disk.
func (s *Server) invalid(src netip.Addr, size int, reason string) {
	s.invalidCount++
	if time.Since(s.lastInvalid) < 5*time.Second {
		return
	}
	log.Printf("DROPPED src=%s size=%d reason=%q (+%d since last log)", src, size, reason, s.invalidCount-1)
	s.lastInvalid, s.invalidCount = time.Now(), 0
}
