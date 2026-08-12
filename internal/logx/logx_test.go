package logx

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"unicode/utf8"
)

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
	got := Safe(long)
	if len(got) > 200 {
		t.Errorf("forLog returned %d bytes for a 4096-byte input", len(got))
	}
	if !strings.Contains(got, "truncated") {
		t.Error("truncation is not announced, so a reader cannot tell the value was cut")
	}
}

func TestForLogRemovesControlCharacters(t *testing.T) {
	got := Safe("ok\nthen\rmore\x00and\x1b[31m")
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
	got := Safe(strings.Repeat("日本語テスト", 100))
	if !utf8.ValidString(got) {
		t.Error("forLog produced invalid UTF-8")
	}
}

func TestSafeErrorHandlesNil(t *testing.T) {
	if got := SafeError(nil); got != "" {
		t.Errorf("SafeError(nil) = %q, want empty", got)
	}
}

func TestSafeErrorBoundsAndSanitises(t *testing.T) {
	// Error text is the commonest way something from outside reaches a log: it arrives
	// wrapped in several layers of our own message, so it is easy to forget the innermost
	// part was written by somebody else.
	err := errors.New("upstream said: " + strings.Repeat("x", 4096) + "\nlevel=ERROR msg=forged")
	got := SafeError(err)

	if len(got) > 200 {
		t.Errorf("SafeError returned %d bytes", len(got))
	}
	if strings.Contains(got, "\n") {
		t.Error("SafeError kept a newline")
	}
	if !strings.Contains(got, "upstream said") {
		t.Errorf("SafeError discarded the useful part: %q", got)
	}
}

func TestSafeLeavesOrdinaryValuesAlone(t *testing.T) {
	// The common case must survive untouched, or every log line becomes harder to read
	// for the sake of the rare hostile one.
	for _, s := range []string{
		"/api/v1/enroll",
		"that enrolment token has already been used",
		"100.90.0.1",
		"日本語のホスト名",
	} {
		if got := Safe(s); got != s {
			t.Errorf("Safe(%q) = %q, want it unchanged", s, got)
		}
	}
}
