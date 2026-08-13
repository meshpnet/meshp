// Command meshp-relay forwards encrypted packets between peers that cannot reach each other
// directly.
//
// It is deliberately dumb. It authenticates that a sender may use it, then forwards opaque
// bytes to a destination public key. It never holds a WireGuard key for a user's tunnel and
// never needs to decrypt a payload (Invariant 3) — which is what makes it safe for a customer
// to run their own relay next to their users, and what keeps the blast radius of a compromised
// relay small.
//
// meshp is relay-first: a session starts on a relay and upgrades to a direct path only if one
// can be found (ADR-0002), so connectivity never depends on NAT traversal succeeding.
//
// It listens on several UDP ports, because one is not enough. UDP 443 looks like the
// friendliest choice and is the one most likely to be filtered, since it carries QUIC and
// networks that want to inspect HTTP block it to force a fallback — measured on a real
// network, where 443 was dropped and 3478 passed. So the default set leads with 3478 and the
// agent is expected to try each in turn.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/meshpnet/meshp/internal/clock"
	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/internal/logx"
	"github.com/meshpnet/meshp/internal/relay"
	"github.com/meshpnet/meshp/internal/relayproto"
	"github.com/meshpnet/meshp/internal/relaytoken"
	"github.com/meshpnet/meshp/internal/version"
)

// defaultListen leads with 3478 deliberately. See the package comment.
const defaultListen = ":3478,:443,:51820"

// sweepInterval is how often sessions nothing has been heard from are forgotten. Frequent
// enough that a relay's memory reflects who is connected, rare enough not to walk the table
// on the hot path.
const sweepInterval = 30 * time.Second

func main() {
	var (
		showVersion = flag.Bool("version", false, "print build information and exit")
		listen      = flag.String("listen", envOr("MESHP_RELAY_LISTEN", defaultListen),
			"comma-separated UDP addresses to listen on; the agent tries them in order")
		adminAddr = flag.String("admin-listen", envOr("MESHP_RELAY_ADMIN_ADDR", "127.0.0.1:9090"),
			"HTTP address for health and statistics; loopback by default because it is not authenticated")
		issuerKey = flag.String("issuer-key", os.Getenv("MESHP_RELAY_ISSUER_KEY"),
			"base64 Ed25519 public key of the control plane that issues relay tokens")
		idle     = flag.Duration("idle", envDuration("MESHP_RELAY_IDLE", relay.DefaultIdle), "how long a session survives unheard from")
		logLevel = flag.String("log-level", envOr("MESHP_LOG_LEVEL", "info"), "debug, info, warn or error")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String("meshp-relay"))
		return
	}

	log := newLogger(*logLevel)

	public, err := parseIssuerKey(*issuerKey)
	if err != nil {
		// Refusing to start is right: a relay with no issuer key could only either forward
		// for anyone or for no one, and the first is an open proxy.
		log.Error("cannot start without the control plane's public key",
			"error", err,
			"hint", "set MESHP_RELAY_ISSUER_KEY to the base64 Ed25519 public key the control plane signs relay tokens with")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, log, config{
		listen:    *listen,
		adminAddr: *adminAddr,
		issuer:    public,
		idle:      *idle,
	}); err != nil {
		log.Error("meshp-relay exited with error", "error", err)
		os.Exit(1)
	}
	log.Info("meshp-relay stopped cleanly")
}

type config struct {
	listen    string
	adminAddr string
	issuer    ed25519.PublicKey
	idle      time.Duration
}

// issuerAuth verifies tokens against the control plane's public key.
//
// The relay can check a signature and cannot produce one, so a compromised relay cannot grant
// access to a network it was never given (ADR-0016).
type issuerAuth struct {
	public ed25519.PublicKey
	clk    clock.Clock
}

func (a issuerAuth) Authenticate(token []byte) (relayproto.Key, string, error) {
	grant, err := relaytoken.Verify(a.public, token, a.clk.Now())
	if err != nil {
		return relayproto.Key{}, "", err
	}
	return grant.Key, grant.Network(), nil
}

func run(ctx context.Context, log *slog.Logger, cfg config) error {
	selfKey, err := relayIdentity()
	if err != nil {
		return err
	}

	srv, err := relay.New(relay.Config{
		Auth:    issuerAuth{public: cfg.issuer, clk: clock.System{}},
		SelfKey: selfKey,
		Idle:    cfg.idle,
		Clock:   clock.System{},
		Log:     log,
	})
	if err != nil {
		return err
	}

	h, err := listenAll(cfg.listen)
	if err != nil {
		return err
	}
	defer func() {
		for _, c := range h.conns {
			_ = c.Close()
		}
	}()
	for i, c := range h.conns {
		log.Info("listening for relayed traffic", "socket", i, "addr", c.LocalAddr().String())
	}

	wg := serve(ctx, log, srv, h)

	admin := adminServer(cfg.adminAddr, log, srv)
	errc := make(chan error, 1)
	go func() {
		if err := admin.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
			return
		}
		errc <- nil
	}()
	log.Info("admin endpoint listening", "addr", cfg.adminAddr)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Info("shutdown signal received")
	}

	// Closing the sockets is what unblocks the read loops; a context alone cannot interrupt
	// a blocking ReadFromUDPAddrPort.
	for _, c := range h.conns {
		_ = c.Close()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = admin.Shutdown(shutdownCtx)
	wg.Wait()
	log.Info("final statistics", "stats", srv.Stats().String())
	return err
}

// serve starts a read loop per socket and the session sweeper, and returns something to wait
// on. Separate from run so a test can drive a relay on ephemeral ports.
func serve(ctx context.Context, log *slog.Logger, srv *relay.Server, h *host) *sync.WaitGroup {
	var wg sync.WaitGroup
	for i, c := range h.conns {
		wg.Add(1)
		go func(via int, conn *net.UDPConn) {
			defer wg.Done()
			forward(ctx, log, srv, h, via, conn)
		}(i, c)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		sweep(ctx, log, srv)
	}()
	return &wg
}

// forward is the hot path: read a datagram, ask the server what to do, write the answers.
//
// One goroutine and one buffer per socket, so nothing is shared and nothing is allocated per
// packet. Everything interesting is decided in internal/relay, which is why this is short
// enough to read in one go.
func forward(ctx context.Context, log *slog.Logger, srv *relay.Server, h *host, via int, conn *net.UDPConn) {
	// Room for the largest frame, plus a little, so an oversized datagram is read and then
	// rejected rather than silently truncated into something that looks valid.
	in := make([]byte, relayproto.HeaderLen+relayproto.MaxPayload+64)
	out := make([]byte, relayproto.HeaderLen+relayproto.MaxPayload)

	for {
		n, from, err := conn.ReadFromUDPAddrPort(in)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Warn("read failed", "socket", via, "error", logx.SafeError(err))
			continue
		}

		for _, o := range srv.Handle(via, from, in[:n]) {
			written, err := o.Frame.Encode(out)
			if err != nil {
				// A frame the server produced that will not encode is a bug here, not bad
				// input, so it is worth an error rather than a dropped packet.
				log.Error("could not encode a reply", "error", err, "type", o.Frame.Type.String())
				continue
			}
			// Out of the socket the destination is talking to, which may not be this one.
			if err := h.write(o, out[:written]); err != nil {
				log.Debug("write failed", "to", o.To, "socket", o.Via, "error", logx.SafeError(err))
			}
		}
	}
}

// host owns the listening sockets, so a reply can leave by the one its destination is using.
//
// The set is fixed once listening has started, so no lock is needed to read it — and a struct
// rather than a package-level variable because two runs in one process (a test) must not share
// sockets.
type host struct {
	conns []*net.UDPConn
}

func (h *host) write(o relay.Out, datagram []byte) error {
	if o.Via < 0 || o.Via >= len(h.conns) {
		return fmt.Errorf("relay: no socket %d", o.Via)
	}
	_, err := h.conns[o.Via].WriteToUDPAddrPort(datagram, o.To)
	return err
}

func sweep(ctx context.Context, log *slog.Logger, srv *relay.Server) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if gone := srv.Expire(); gone > 0 {
				log.Debug("forgot idle sessions", "count", gone)
			}
		}
	}
}

// listenAll opens every address in a comma-separated list.
//
// All or nothing: a relay that came up on two of its three ports would advertise a port that
// silently does not work, and the agent would spend its retries on it.
func listenAll(spec string) (*host, error) {
	var conns []*net.UDPConn
	closeAll := func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}

	for _, addr := range strings.Split(spec, ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("relay: %q is not a UDP address: %w", addr, err)
		}
		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("relay: listening on %s: %w", addr, err)
		}
		conns = append(conns, conn)
	}
	if len(conns) == 0 {
		return nil, errors.New("relay: no addresses to listen on")
	}

	return &host{conns: conns}, nil
}

func adminServer(addr string, log *slog.Logger, srv *relay.Server) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, log, http.StatusOK, map[string]string{
			"status":  "ok",
			"version": version.Version(),
		})
	})
	// Every counter here is a question someone asks when a relay is not working: whether
	// anyone connected, whether tokens are being refused, whether packets are being dropped
	// and for which reason.
	mux.HandleFunc("GET /stats", func(w http.ResponseWriter, _ *http.Request) {
		st := srv.Stats()
		httpx.WriteJSON(w, log, http.StatusOK, map[string]any{
			"sessions":            st.Sessions,
			"hello_accepted":      st.HelloAccepted,
			"hello_refused":       st.HelloRefused,
			"forwarded":           st.Forwarded,
			"dropped_no_session":  st.DroppedNoSession,
			"dropped_no_peer":     st.DroppedNoPeer,
			"dropped_other_net":   st.DroppedOtherNet,
			"dropped_undecodable": st.DroppedUndecodable,
			"expired":             st.Expired,
		})
	})
	return &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
}

// relayIdentity is the key this relay puts in the frames it originates.
//
// Generated per start rather than configured, because nothing verifies it yet: it exists so
// that an agent talking to two relays can tell their replies apart, and so a log line can say
// which relay answered.
func relayIdentity() (relayproto.Key, error) {
	var key relayproto.Key
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		return key, fmt.Errorf("relay: generating an identity: %w", err)
	}
	copy(key[:], pub)
	return key, nil
}

func parseIssuerKey(s string) (ed25519.PublicKey, error) {
	if strings.TrimSpace(s) == "" {
		return nil, errors.New("no issuer key given")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("not base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "meshp-relay: %s=%q is not a duration; using %s\n", key, v, fallback)
		return fallback
	}
	return d
}
