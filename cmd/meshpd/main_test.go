package main

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/agentapi"
	"github.com/meshpnet/meshp/internal/agentstate"
)

// Where the daemon keeps its keys is a platform decision, and an operator's is final.
//
// Absolute is the part worth asserting rather than the exact string: meshpd is started by
// systemd or launchd, whose working directory is not the one whoever wrote the unit had in
// mind, and a relative state directory would put a device's identity somewhere nobody can
// find it — and somewhere a second start might not find either.
func TestTheStateDirectoryIsAbsoluteAndTheEnvironmentWins(t *testing.T) {
	t.Setenv("MESHP_STATE_DIR", "")
	if dir := defaultStateDir(); !filepath.IsAbs(dir) {
		t.Errorf("the default state directory is %q, which is relative to wherever the "+
			"service manager happened to start this process", dir)
	}

	chosen := filepath.Join(t.TempDir(), "elsewhere")
	t.Setenv("MESHP_STATE_DIR", chosen)
	if dir := defaultStateDir(); dir != chosen {
		t.Errorf("the environment did not win: got %q, want %q", dir, chosen)
	}
}

// The daemon and the CLI have to agree about where the socket is, or `meshp status` reports
// nothing on a device that is working perfectly.
//
// Nothing joins these two: meshpd computes a default per platform and meshp takes
// agentapi.DefaultSocketPath. They agree today everywhere meshp runs, and this is what says
// so out loud.
//
// Windows is the exception and is deliberately not asserted. meshpd puts the socket under
// C:\ProgramData\meshp and the CLI would still ask for the unix path, which is a real
// disagreement — and not yet a bug, because Windows has no data plane at all (#144). Whoever
// takes that issue has to teach cmd/meshp the same rule.
func TestTheDaemonAndTheCLIAgreeOnWhereTheSocketIs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("meshp has no Windows data plane yet; see #144")
	}
	t.Setenv("MESHP_SOCKET", "")

	if got := defaultSocketPath(); got != agentapi.DefaultSocketPath {
		t.Errorf("meshpd listens on %q and meshp asks for %q; a working device would report "+
			"nothing", got, agentapi.DefaultSocketPath)
	}

	t.Setenv("MESHP_SOCKET", "/tmp/somewhere.sock")
	if got := defaultSocketPath(); got != "/tmp/somewhere.sock" {
		t.Errorf("the environment did not win: got %q", got)
	}
}

// A cosmetic mistake in a unit file must not keep a device offline.
//
// The interval only decides how often a converged interface is re-checked. Refusing to start
// over an unparseable one would take a machine off the network to complain about a typo, so
// it falls back and says so on stderr.
func TestAMalformedIntervalDoesNotKeepADeviceOffline(t *testing.T) {
	const fallback = 90 * time.Second

	for _, tc := range []struct {
		name, value string
		want        time.Duration
	}{
		{"unset", "", fallback},
		{"a duration", "15s", 15 * time.Second},
		{"nonsense", "every so often", fallback},
		{"a bare number, which Go does not accept", "60", fallback},
		{"switched off deliberately", "0s", 0},
	} {
		t.Setenv("MESHP_TEST_INTERVAL", tc.value)
		if got := envDuration("MESHP_TEST_INTERVAL", fallback); got != tc.want {
			t.Errorf("%s: envDuration(%q) = %s, want %s", tc.name, tc.value, got, tc.want)
		}
	}
}

// The same argument for the log level: an unreadable one still logs.
//
// A daemon that exited over `MESHP_LOG_LEVEL=verbose` would be a device off the network
// because somebody guessed a word.
func TestAnUnreadableLogLevelStillLogs(t *testing.T) {
	ctx := context.Background()

	fallback := newLogger("verbose")
	if !fallback.Enabled(ctx, slog.LevelInfo) {
		t.Error("an unreadable log level left the daemon silent at info")
	}
	if fallback.Enabled(ctx, slog.LevelDebug) {
		t.Error("an unreadable log level was taken as a request for debug logging")
	}

	// And a readable one is honoured, or the fallback above would be the only behaviour.
	if !newLogger("debug").Enabled(ctx, slog.LevelDebug) {
		t.Error("debug was asked for and not enabled")
	}
	if newLogger("error").Enabled(ctx, slog.LevelWarn) {
		t.Error("error was asked for and warnings were logged anyway")
	}
}

// "There is no state" and "the state cannot be read" have to stay different questions.
//
// The first is normal: the agent is installed before anyone has a token and must stay up so
// that `meshp join` has something to talk to. The second must never be treated as start
// fresh — that abandons the device's identity and leaves a registered device nobody can
// revoke by name.
func TestOnlyAnAbsentStateFileCountsAsNotEnrolled(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"never enrolled", agentstate.ErrNotEnrolled, true},
		{"no file", fs.ErrNotExist, true},
		{"wrapped on the way up", fmt.Errorf("loading: %w", agentstate.ErrNotEnrolled), true},

		{"readable by more than its owner", agentstate.ErrPermissive, false},
		{"there and unparseable", fmt.Errorf("state.json is not valid state: unexpected end of JSON input"), false},
		{"the disk is failing", fs.ErrPermission, false},
	} {
		if got := isNotEnrolled(tc.err); got != tc.want {
			t.Errorf("%s: isNotEnrolled(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}
