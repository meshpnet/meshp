package api

import (
	"net"
	"net/http"
	"sync"

	"github.com/meshpnet/meshp/internal/clock"
)

// The enrolment endpoints are reachable without any credential — the token is the
// credential, and it is presented in the body. That is unavoidable: a device with
// nothing yet cannot authenticate. It does mean anyone who can reach the control
// plane can make it verify signatures and query the database, so there is a limiter
// in front.
//
// This is a first line, not a solution. It is per-process, so several replicas
// multiply the effective rate, and it keys on the remote address, which a
// distributed source defeats. What it does buy is that a single host cannot trivially
// saturate the connection pool, and that is worth forty lines. Real protection is a
// job for whatever sits in front in production.
type limiter struct {
	clk     clock.Clock
	rate    float64 // tokens added per second
	burst   float64
	maxKeys int

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens   float64
	lastSeen int64 // unix nanoseconds
}

func newLimiter(rate, burst float64, maxKeys int, clk clock.Clock) *limiter {
	if clk == nil {
		clk = clock.System{}
	}
	return &limiter{
		clk:     clk,
		rate:    rate,
		burst:   burst,
		maxKeys: maxKeys,
		buckets: make(map[string]*bucket),
	}
}

// allow reports whether a request from key may proceed, consuming a token if so.
func (l *limiter) allow(key string) bool {
	now := l.clk.Now().UnixNano()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		// Bounded memory matters more than perfect accounting: without a cap, the
		// limiter is itself the memory-exhaustion vector it was added to prevent.
		if len(l.buckets) >= l.maxKeys {
			l.evictLocked(now)
		}
		b = &bucket{tokens: l.burst, lastSeen: now}
		l.buckets[key] = b
	}

	elapsed := float64(now-b.lastSeen) / 1e9
	if elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
	}
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// evictLocked drops buckets that have refilled, since a full bucket is
// indistinguishable from one that never existed. If none have, it clears the map
// wholesale rather than growing without bound — briefly forgiving, never unbounded.
func (l *limiter) evictLocked(now int64) {
	for key, b := range l.buckets {
		elapsed := float64(now-b.lastSeen) / 1e9
		if b.tokens+elapsed*l.rate >= l.burst {
			delete(l.buckets, key)
		}
	}
	if len(l.buckets) >= l.maxKeys {
		l.buckets = make(map[string]*bucket)
	}
}

// clientKey identifies the caller for rate-limiting purposes.
//
// Deliberately the transport's remote address and never a forwarded header: a
// client that can set X-Forwarded-For can mint a fresh identity per request and
// bypass the limiter entirely. A proxy in front is expected to do its own limiting,
// and if this ever needs to trust a header it must be told which proxies to trust
// rather than believing whatever arrives.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
