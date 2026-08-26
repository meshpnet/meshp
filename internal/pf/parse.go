package pf

import (
	"regexp"
	"strings"
)

// tokenPattern finds the reference `pfctl -E` hands back.
//
// pfctl prints "Token : 1234567890" on a line of its own, alongside other chatter that
// differs between a first enable and a redundant one. Matched rather than parsed positionally
// for that reason.
var tokenPattern = regexp.MustCompile(`(?m)^\s*Token\s*:\s*(\d+)\s*$`)

// tokenIn reads the reference out of what `pfctl -E` printed, or returns "" when there is
// none to read.
func tokenIn(output string) string {
	if match := tokenPattern.FindStringSubmatch(output); match != nil {
		return match[1]
	}
	return ""
}

// anchorPointIn reports whether a printed ruleset still evaluates what is nested under
// Apple's anchor.
//
// This is the check ADR-0026 turns on, so it is worth being exact about what it accepts and
// why. Two kinds of near-miss would let a device believe it fails closed when it does not,
// and both are ordinary text a substring search would swallow:
//
//   - `nat-anchor "com.apple/*"`, and the scrub, rdr and dummynet anchors beside it in the
//     shipped /etc/pf.conf. Those are anchor points for entirely different rulesets — address
//     translation, normalisation — and none of them evaluates a filter rule. There are four
//     of them in the file and only one `anchor` line, so a search for the quoted name finds
//     the wrong thing four times out of five.
//   - `anchor "com.apple"` without the wildcard, which loads Apple's own rules and evaluates
//     nothing nested beneath them. meshp's anchor would be loaded, findable, and never
//     reached.
//
// So the first field must be exactly `anchor` and the second exactly the wildcard name.
// Fields rather than a whole-line match because pfctl prints a rule with the qualifiers it
// was loaded with, and `anchor "com.apple/*" all` is the same anchor point.
func anchorPointIn(rules string) bool {
	for _, line := range strings.Split(rules, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "anchor" {
			continue
		}
		if strings.Trim(fields[1], `"`) == anchorPoint {
			return true
		}
	}
	return false
}

// statusEnabledIn reports whether `pfctl -s info` says the packet filter is running.
//
// Asked rather than inferred from meshp holding a reference, because a reference is not the
// same as pf being on. `pfctl -d` disables the filter outright and ignores the count, and a
// token file could outlive the enable it names if /var/run were ever kept across a boot.
// Either way the failure is the same and it is the bad one: rules loaded, pf off, and a
// device reporting that it fails closed while everything leaves in the clear.
//
// pfctl puts the answer first on the line and other columns after it — "Status: Enabled for
// 0 days 00:03:20    Debug: Urgent" — so the word immediately after the label is the whole
// of it.
func statusEnabledIn(info string) bool {
	for _, line := range strings.Split(info, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "Status:" {
			return fields[1] == "Enabled"
		}
	}
	return false
}
