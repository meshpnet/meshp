// Package logx holds the small amount of care needed when logging values that came
// from somewhere else.
//
// It exists because the need turned up twice — once for request paths in the HTTP API,
// once for control-plane error text in the agent's local API — and a security-relevant
// helper that has been copied is one that will be fixed in one place and not the other.
package logx

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxValueBytes is how much of an untrusted value reaches a log.
//
// Generous enough that a real path or error message survives intact, small enough that
// nobody can make the log interesting by volume.
const MaxValueBytes = 128

// Safe prepares a value that came from outside for logging.
//
// The injection half of this problem is already handled by slog: its text handler quotes
// values and escapes newlines, carriage returns and ANSI escapes, and its JSON handler
// encodes them, so a value carrying "\nlevel=ERROR msg=forged" comes out inside one
// quoted field rather than as a second log line. There is a test asserting that for both
// handlers, because the claim is the whole reason CodeQL's log-injection findings against
// this codebase are false positives, and an assertion beats a belief.
//
// What slog does not bound is length. Without a limit, anyone who can reach an endpoint —
// or any control plane an agent is pointed at — can put kilobytes into the log on every
// failed request, which is a cheap way to fill a disk or a log bill. So values are
// bounded here, truncation is announced so a reader can tell, and control characters are
// replaced as well: belt and braces, so this stays correct if a handler other than slog's
// is ever substituted.
func Safe(s string) string {
	var b strings.Builder
	b.Grow(min(len(s), MaxValueBytes))

	count := 0
	for _, r := range s {
		if count >= MaxValueBytes {
			b.WriteString("…(truncated)")
			break
		}
		// Ranging over a string yields runes, so this cannot split one in half and emit
		// invalid UTF-8 — which some log pipelines reject outright.
		if r == utf8.RuneError || unicode.IsControl(r) {
			b.WriteRune('�')
		} else {
			b.WriteRune(r)
		}
		count++
	}
	return b.String()
}

// SafeError renders an error for logging, bounded and sanitised.
//
// Error text is the most common way something from outside reaches a log: it arrives
// wrapped in several layers of our own message, which makes it easy to forget that the
// innermost part was written by somebody else.
func SafeError(err error) string {
	if err == nil {
		return ""
	}
	return Safe(err.Error())
}
