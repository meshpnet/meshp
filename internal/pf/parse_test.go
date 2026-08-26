package pf

import "testing"

// The check ADR-0026 turns on, tested against the near-misses that would let it pass on a
// machine where meshp's rules are loaded and never evaluated.
//
// Worth being blunt about the stakes: this returning true when it should not is a device
// that reports it fails closed while every packet leaves in the clear. That is the one
// failure the record says is worse than having no lock at all.
func TestOnlyAFilterAnchorPointWithAWildcardCounts(t *testing.T) {
	// What macOS ships. Four of the five lines name the same anchor, and only one of them
	// evaluates a filter rule — so a substring search for the name finds the wrong thing
	// four times out of five.
	const shipped = `scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"`

	for _, tc := range []struct {
		name  string
		rules string
		want  bool
	}{
		{"what macOS ships", shipped, true},
		{"as pfctl prints it back", `anchor "com.apple/*" all`, true},
		{"unquoted, should pfctl ever print it that way", "anchor com.apple/* all", true},

		{"translation anchors only", `nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"`, false},
		{"no wildcard, so nothing nested is reached", `anchor "com.apple"`, false},
		{"somebody else's namespace", `anchor "meshp/*"`, false},
		{"a rule that merely mentions it", `block return out quick to any # com.apple/*`, false},
		{"nothing at all", "", false},
	} {
		if got := anchorPointIn(tc.rules); got != tc.want {
			t.Errorf("%s: anchorPointIn = %v, want %v\n%s", tc.name, got, tc.want, tc.rules)
		}
	}
}

// The reference on pf being enabled, which is what stops meshp turning the packet filter off
// underneath the application firewall.
func TestTheEnableTokenIsReadOutOfWhatPfctlPrints(t *testing.T) {
	for _, tc := range []struct{ name, output, want string }{
		{"a first enable", "pf enabled\nToken : 12285919162907929896\n", "12285919162907929896"},
		{"pf was already on", "pfctl: pf already enabled\nToken : 4155744211\n", "4155744211"},
		{"indented, as pfctl has been known to", "  Token : 17\n", "17"},
		{"no token to read", "pf enabled\n", ""},
		{"the word without the number", "Token : none\n", ""},
		{"mentioned in prose rather than reported", "the Token : 5 was not printed alone", ""},
	} {
		if got := tokenIn(tc.output); got != tc.want {
			t.Errorf("%s: tokenIn = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Whether the packet filter is actually running, which is not the same question as whether
// meshp holds a reference saying it should be.
//
// The wrong answer here in the optimistic direction is the failure ADR-0026 cares about:
// rules loaded, pf off, and a device reporting that it fails closed.
func TestPfIsOnlyRunningWhenPfctlSaysItIs(t *testing.T) {
	for _, tc := range []struct {
		name string
		info string
		want bool
	}{
		{"running", "Status: Enabled for 0 days 00:03:20           Debug: Urgent", true},
		{"not running", "Status: Disabled                              Debug: Urgent", false},
		{"the word appears further down the report", `Status: Disabled
State Table                          Total             Rate
  Enabled                                0`, false},
		{"nothing to read", "", false},
	} {
		if got := statusEnabledIn(tc.info); got != tc.want {
			t.Errorf("%s: statusEnabledIn = %v, want %v\n%s", tc.name, got, tc.want, tc.info)
		}
	}
}
