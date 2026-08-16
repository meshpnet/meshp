package dns

import (
	"strconv"
	"strings"
)

// MaxLabel is the longest a DNS label may be.
const MaxLabel = maxLabel

// ValidLabel reports whether s is a label DNS can carry: lowercase letters, digits and
// hyphens, not starting or ending with one, at most 63 bytes.
//
// The same rule the database enforces, so a label that gets past one gets past the other.
// Two expressions of one rule is a drift risk and the alternative — asking the database
// every time — is a round trip to answer a question about a string.
func ValidLabel(s string) bool {
	if s == "" || len(s) > MaxLabel {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' && i != 0 && i != len(s)-1:
		default:
			return false
		}
	}
	return true
}

// Label turns a display name into a DNS label, or returns "" when nothing usable is left.
//
// Lowercase; anything that is not a letter or digit becomes a hyphen; runs collapse; leading
// and trailing hyphens go. `Dave's laptop (spare)` becomes `dave-s-laptop-spare`, which is
// guessable — and being guessable is the point, because somebody has to type it.
//
// This mangles where the agent's own check refuses, and the difference is deliberate. Here
// the result is stored, shown to an operator and changeable; at query time it would be an
// invisible rewrite of what somebody typed.
func Label(display string) string {
	var b strings.Builder
	b.Grow(len(display))

	lastHyphen := true // leading hyphens are dropped
	for _, r := range strings.ToLower(display) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastHyphen = false
		default:
			if !lastHyphen {
				b.WriteByte('-')
				lastHyphen = true
			}
		}
	}

	out := strings.Trim(b.String(), "-")
	if len(out) > MaxLabel {
		out = strings.TrimRight(out[:MaxLabel], "-")
	}
	return out
}

// Suffixed returns base with n appended, kept inside the label limit.
//
// Truncating the base rather than letting the result overrun: a 63-byte name that collided
// must still produce a valid label, and a label the database rejects would turn a rename
// into a failed enrolment.
func Suffixed(base string, n int) string {
	suffix := "-" + strconv.Itoa(n)
	if len(base)+len(suffix) <= MaxLabel {
		return base + suffix
	}
	return strings.TrimRight(base[:MaxLabel-len(suffix)], "-") + suffix
}
