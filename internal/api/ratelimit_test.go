package api

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/meshpnet/meshp/internal/clock"
)

func TestLimiterAllowsBurstThenRefuses(t *testing.T) {
	clk := clock.NewFake()
	l := newLimiter(1, 3, 100, clk)

	for i := range 3 {
		if !l.allow("1.2.3.4") {
			t.Fatalf("request %d of the burst was refused", i+1)
		}
	}
	if l.allow("1.2.3.4") {
		t.Error("the burst was exceeded without being refused")
	}
}

func TestLimiterRefillsOverTime(t *testing.T) {
	clk := clock.NewFake()
	l := newLimiter(2, 2, 100, clk) // two per second

	l.allow("k")
	l.allow("k")
	if l.allow("k") {
		t.Fatal("bucket was not empty")
	}

	// Refill is proportional to elapsed time, not to the number of attempts, so a
	// caller cannot hammer its way to a token.
	clk.Advance(400 * time.Millisecond) // 0.8 tokens
	if l.allow("k") {
		t.Error("allowed a request on 0.8 of a token")
	}
	clk.Advance(200 * time.Millisecond) // now 1.2
	if !l.allow("k") {
		t.Error("refused a request with a full token available")
	}
}

func TestLimiterIsPerKey(t *testing.T) {
	clk := clock.NewFake()
	l := newLimiter(1, 1, 100, clk)

	if !l.allow("first") {
		t.Fatal("first caller refused")
	}
	// One noisy source must not lock everyone else out.
	if !l.allow("second") {
		t.Error("a second caller was refused because of the first")
	}
	if l.allow("first") {
		t.Error("the first caller got a second token")
	}
}

// The limiter must not become the memory-exhaustion vector it was added to prevent.
func TestLimiterMemoryIsBounded(t *testing.T) {
	clk := clock.NewFake()
	const maxKeys = 64
	l := newLimiter(1, 1, maxKeys, clk)

	for i := range maxKeys * 20 {
		l.allow(fmt.Sprintf("10.0.%d.%d", i/256, i%256))
	}

	l.mu.Lock()
	tracked := len(l.buckets)
	l.mu.Unlock()

	if tracked > maxKeys {
		t.Errorf("tracking %d keys, cap is %d", tracked, maxKeys)
	}
}

func TestLimiterEvictsIdleKeysFirst(t *testing.T) {
	clk := clock.NewFake()
	l := newLimiter(1, 1, 4, clk)

	// Four idle callers, then time enough for all of them to refill.
	for i := range 4 {
		l.allow(fmt.Sprintf("idle-%d", i))
	}
	clk.Advance(10 * time.Second)

	// A fifth arrival should reclaim the refilled ones rather than clear everything.
	l.allow("new")
	l.mu.Lock()
	tracked := len(l.buckets)
	l.mu.Unlock()
	if tracked > 4 {
		t.Errorf("tracking %d keys after eviction, cap is 4", tracked)
	}
}

// The key must come from the transport, never from a header a client controls: a
// caller able to set X-Forwarded-For could otherwise mint a fresh identity per
// request and bypass the limiter entirely.
func TestClientKeyIgnoresForwardedHeaders(t *testing.T) {
	r, err := http.NewRequest(http.MethodPost, "http://example.test/api/v1/enroll", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.RemoteAddr = "203.0.113.7:54321"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	r.Header.Set("X-Real-IP", "198.51.100.2")

	if got := clientKey(r); got != "203.0.113.7" {
		t.Errorf("clientKey = %q, want the transport address 203.0.113.7", got)
	}
}

func TestClientKeyHandlesAnAddressWithoutAPort(t *testing.T) {
	r, _ := http.NewRequest(http.MethodPost, "http://example.test/", nil)
	r.RemoteAddr = "unix"
	if got := clientKey(r); got != "unix" {
		t.Errorf("clientKey = %q, want it to fall back to the raw address", got)
	}
}

func TestRateLimitedHandlerAnswers429(t *testing.T) {
	h := newHarness(t)

	// A server whose limiter is exhausted after one request.
	challenger, _ := newTestChallengerFor(t, h)
	tight := New(h.store, challenger, nil, Config{
		AdminToken:         testAdminToken,
		Clock:              h.clk,
		EnrolRatePerSecond: 0.001,
		EnrolBurst:         1,
	})
	mux := http.NewServeMux()
	tight.Routes(mux)

	server := newTestServer(t, mux)
	body := `{"token":"meshp_tok_bad","identity_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`

	first, err := http.Post(server+"/api/v1/enroll/challenge", "application/json", stringReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Body.Close()
	if first.StatusCode == http.StatusTooManyRequests {
		t.Fatal("the very first request was throttled")
	}

	second, err := http.Post(server+"/api/v1/enroll/challenge", "application/json", stringReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Body.Close() }()
	if second.StatusCode != http.StatusTooManyRequests {
		t.Errorf("second request status = %d, want 429", second.StatusCode)
	}
	// Retry-After lets a well-behaved client back off correctly instead of guessing.
	if second.Header.Get("Retry-After") == "" {
		t.Error("a 429 with no Retry-After leaves the client guessing")
	}
}

// --- logging user input -----------------------------------------------------

// The claim that slog escapes hostile values is asserted rather than trusted,
// because it is the whole reason CodeQL's log-injection finding is a false positive
// here. If a future change swaps the handler, this fails.
func TestSlogEscapesHostileValues(t *testing.T) {
	hostile := "/api/v1/enroll\nlevel=ERROR msg=\"forged\" admin=true\r\x1b[31m"

	for _, tc := range []struct {
		name    string
		handler func(*bytes.Buffer) slog.Handler
	}{
		{"text", func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) }},
		{"json", func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			slog.New(tc.handler(&buf)).Info("probe", "path", hostile)

			out := buf.String()
			// One line out means no forged entry got in.
			if lines := strings.Count(strings.TrimRight(out, "\n"), "\n"); lines != 0 {
				t.Errorf("a hostile value produced %d extra lines:\n%s", lines, out)
			}
			if strings.Contains(out, "\x1b") {
				t.Error("a raw ANSI escape reached the log")
			}
		})
	}
}

func TestForLogBoundsLength(t *testing.T) {
	// Unbounded logging of a request path is a cheap way to fill a disk, whatever the
	// handler does about escaping.
	long := strings.Repeat("a", 4096)
	got := forLog(long)
	if len(got) > 200 {
		t.Errorf("forLog returned %d bytes for a 4096-byte input", len(got))
	}
	if !strings.Contains(got, "truncated") {
		t.Error("truncation is not announced, so a reader cannot tell the value was cut")
	}
}

func TestForLogRemovesControlCharacters(t *testing.T) {
	got := forLog("ok\nthen\rmore\x00and\x1b[31m")
	for _, bad := range []string{"\n", "\r", "\x00", "\x1b"} {
		if strings.Contains(got, bad) {
			t.Errorf("forLog kept %q", bad)
		}
	}
	if !strings.Contains(got, "ok") || !strings.Contains(got, "more") {
		t.Errorf("forLog discarded the readable parts: %q", got)
	}
}

func TestForLogKeepsValidUTF8(t *testing.T) {
	// Truncating by bytes would split a multi-byte rune and put invalid UTF-8 into the
	// log, which some log pipelines reject outright.
	got := forLog(strings.Repeat("日本語テスト", 100))
	if !utf8.ValidString(got) {
		t.Error("forLog produced invalid UTF-8")
	}
}
