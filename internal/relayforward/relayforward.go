// Package relayforward carries WireGuard packets between the local kernel and a relay.
//
// On Linux the data plane is the kernel's, and a kernel WireGuard socket cannot be
// intercepted the way a userspace implementation can — where Tailscale hands wireguard-go a
// fake endpoint and catches the packets in process, there is no equivalent. So a relayed peer
// is given an endpoint the kernel is willing to send to: a loopback socket this package owns
// (ADR-0016).
//
// One socket per relayed peer, and it serves both directions:
//
//	outbound  kernel -> 127.0.0.1:Px -> read here -> relay
//	inbound   relay -> read here -> written FROM 127.0.0.1:Px to the WireGuard port
//
// The inbound direction is the subtle half. The packet must arrive at the kernel's WireGuard
// port with a source address of exactly the endpoint configured for that peer, or the kernel
// will not associate it with the peer. Writing from the same socket the kernel sends to is
// what makes that true, and it is why there is a socket per peer rather than one shared one.
package relayforward

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"github.com/meshpnet/meshp/internal/logx"
	"github.com/meshpnet/meshp/internal/relayproto"
)

// Sender is the part of a relay client this package needs.
//
// An interface so the forwarder can be handed a different connection when a client
// reconnects, and so tests can drive it without one.
type Sender interface {
	Send(peer relayproto.Key, payload []byte) error
}

// Forwarder owns the loopback sockets serving relayed peers.
type Forwarder struct {
	log *slog.Logger

	mu sync.Mutex
	// wgAddr is the local WireGuard listen port, where inbound packets are delivered.
	//
	// Not known when a device has just joined: the interface asks the kernel for any port
	// and the kernel's answer is what the peers will be told about, so it arrives after the
	// first convergence rather than before. Guarded because the reconciler sets it from one
	// goroutine while the relay's receive loop reads it from another.
	wgAddr  netip.AddrPort
	peers   map[relayproto.Key]*peerSocket
	sender  Sender
	stopped bool
	stats   Stats
}

// Stats are what an operator asks about when relaying is not working.
//
// DroppedNoRelay in particular: packets going nowhere because there is no relay connection is
// a completely different problem from packets a relay rejected, and without a number the two
// look identical from outside.
type Stats struct {
	Peers          int
	Relayed        uint64
	Delivered      uint64
	DroppedNoRelay uint64
	DroppedNoPeer  uint64
	DroppedNoPort  uint64
	SendFailed     uint64
}

// Stats returns a snapshot.
func (f *Forwarder) Stats() Stats {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.stats
	out.Peers = len(f.peers)
	return out
}

type peerSocket struct {
	key  relayproto.Key
	conn *net.UDPConn
	addr netip.AddrPort // the loopback address the kernel is told to use
	done chan struct{}
}

// New returns a Forwarder delivering inbound packets to a WireGuard listen port.
//
// A port of zero means it is not known yet, which is the normal state of a device that has
// just joined: the interface asks the kernel for any port, and the kernel's choice is only
// available once the interface exists. Inbound packets are dropped and counted until
// SetWireGuardPort says where they go — visibly, because a forwarder that silently
// discarded them would look like a relay problem from every angle.
func New(wgPort int, sender Sender, log *slog.Logger) (*Forwarder, error) {
	if wgPort < 0 {
		return nil, fmt.Errorf("relayforward: %d is not a WireGuard listen port", wgPort)
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	f := &Forwarder{
		log:    log,
		peers:  make(map[relayproto.Key]*peerSocket),
		sender: sender,
	}
	if wgPort > 0 {
		f.wgAddr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(wgPort))
	}
	return f, nil
}

// SetWireGuardPort records where inbound packets go.
//
// Called after the interface converges, because until then the port is the kernel's to
// choose. Changing it is not: the peers have been told about the sockets this owns, and the
// interface keeps its port across reconciles.
func (f *Forwarder) SetWireGuardPort(port int) {
	if port <= 0 {
		return
	}
	addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(port))

	f.mu.Lock()
	changed := f.wgAddr != addr
	f.wgAddr = addr
	f.mu.Unlock()

	if changed {
		f.log.Debug("delivering relayed packets to the WireGuard port", "port", port)
	}
}

// SetSender swaps the relay connection, for when a client reconnects.
//
// The sockets are untouched: their addresses are what the kernel has been told, and changing
// them because a relay connection was replaced would mean rewriting every peer.
func (f *Forwarder) SetSender(s Sender) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sender = s
}

// Endpoint returns the loopback address serving a peer, opening a socket if this is the first
// time that peer has been asked for.
//
// The address is stable for as long as the peer is relayed, because it is what the kernel has
// been configured with — a new port would mean the kernel keeps sending to a socket nobody
// reads.
func (f *Forwarder) Endpoint(peer relayproto.Key) (netip.AddrPort, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.stopped {
		return netip.AddrPort{}, errors.New("relayforward: stopped")
	}
	if existing, ok := f.peers[peer]; ok {
		return existing.addr, nil
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("relayforward: opening a socket for a relayed peer: %w", err)
	}
	local, ok := netip.AddrFromSlice(conn.LocalAddr().(*net.UDPAddr).IP)
	if !ok {
		_ = conn.Close()
		return netip.AddrPort{}, errors.New("relayforward: the socket has no usable address")
	}
	ps := &peerSocket{
		key:  peer,
		conn: conn,
		addr: netip.AddrPortFrom(local.Unmap(), uint16(conn.LocalAddr().(*net.UDPAddr).Port)),
		done: make(chan struct{}),
	}
	f.peers[peer] = ps
	go f.outbound(ps)

	f.log.Debug("serving a relayed peer", "endpoint", ps.addr.String())
	return ps.addr, nil
}

// Forget stops serving a peer.
//
// Only safe once the kernel no longer points at that socket. wgctrl cannot clear an endpoint,
// so the caller must have written a different one first — closing a socket the kernel still
// sends to produces a peer that looks configured and goes nowhere (ADR-0016, and the reason
// wgplan refuses to un-relay a peer with nothing to replace its endpoint).
func (f *Forwarder) Forget(peer relayproto.Key) {
	f.mu.Lock()
	ps, ok := f.peers[peer]
	if ok {
		delete(f.peers, peer)
	}
	f.mu.Unlock()

	if ok {
		_ = ps.conn.Close()
		<-ps.done
	}
}

// Peers reports which peers are being served, for status and tests.
func (f *Forwarder) Peers() []relayproto.Key {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]relayproto.Key, 0, len(f.peers))
	for key := range f.peers {
		out = append(out, key)
	}
	return out
}

// Deliver writes a packet received from the relay into the kernel, as though it had arrived
// from the peer's configured endpoint.
//
// From the peer's own socket, which is the whole reason each peer has one: the kernel accepts
// a packet as belonging to a peer only when its source matches that peer's endpoint.
func (f *Forwarder) Deliver(peer relayproto.Key, payload []byte) error {
	f.mu.Lock()
	ps, ok := f.peers[peer]
	wgAddr := f.wgAddr
	f.mu.Unlock()

	if !wgAddr.IsValid() {
		// The interface has not come up yet, so there is nowhere to deliver. Counted rather
		// than logged per packet: it is normal for the first moments after a join and a
		// standing problem after that, and the number is what tells those apart.
		f.count(func(st *Stats) { st.DroppedNoPort++ })
		return errors.New("relayforward: the WireGuard listen port is not known yet")
	}
	if !ok {
		// A packet for a peer we are not serving. Not alarming on its own — a relay may
		// still be flushing traffic for a peer that has just moved to a direct path — but
		// worth counting, because a lot of it means the two ends disagree.
		f.count(func(st *Stats) { st.DroppedNoPeer++ })
		return fmt.Errorf("relayforward: no socket serving %s", truncate(peer))
	}
	if _, err := ps.conn.WriteToUDPAddrPort(payload, wgAddr); err != nil {
		return fmt.Errorf("relayforward: delivering to the local WireGuard port: %w", err)
	}
	f.count(func(st *Stats) { st.Delivered++ })
	return nil
}

// outbound carries what the kernel sends to a peer's socket on to the relay.
func (f *Forwarder) outbound(ps *peerSocket) {
	defer close(ps.done)

	buf := make([]byte, relayproto.MaxPayload)
	for {
		n, err := ps.conn.Read(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				f.log.Debug("relayed peer socket closed",
					"endpoint", ps.addr.String(), "error", logx.SafeError(err))
			}
			return
		}

		f.mu.Lock()
		sender := f.sender
		f.mu.Unlock()
		if sender == nil {
			// Not connected to a relay at the moment. Dropping is right: WireGuard will
			// retransmit, and queueing packets for a connection that may never come back
			// would deliver them long after they stopped meaning anything.
			f.count(func(st *Stats) { st.DroppedNoRelay++ })
			continue
		}

		if err := sender.Send(ps.key, buf[:n]); err != nil {
			f.count(func(st *Stats) { st.SendFailed++ })
			f.log.Debug("could not relay a packet",
				"peer", truncate(ps.key), "error", logx.SafeError(err))
			continue
		}
		f.count(func(st *Stats) { st.Relayed++ })
	}
}

// Close stops every socket.
func (f *Forwarder) Close() error {
	f.mu.Lock()
	if f.stopped {
		f.mu.Unlock()
		return nil
	}
	f.stopped = true
	sockets := make([]*peerSocket, 0, len(f.peers))
	for key, ps := range f.peers {
		sockets = append(sockets, ps)
		delete(f.peers, key)
	}
	f.mu.Unlock()

	for _, ps := range sockets {
		_ = ps.conn.Close()
		<-ps.done
	}
	return nil
}

func (f *Forwarder) count(fn func(*Stats)) {
	f.mu.Lock()
	fn(&f.stats)
	f.mu.Unlock()
}

func truncate(key relayproto.Key) string {
	s := fmt.Sprintf("%x", key[:])
	return s[:12] + "…"
}
