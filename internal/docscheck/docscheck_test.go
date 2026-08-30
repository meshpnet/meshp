package docscheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The page that says what each platform can do says what the code does.
//
// This is the check. Not a search for sentences that might have gone stale — that would be a
// guard nobody trusts, and a guard nobody trusts gets silenced. The table is derived from the
// build tags on the stubs, which the compiler already forces to be right, and this asserts
// that what is written down is what came out.
func TestThePlatformPageMatchesTheCode(t *testing.T) {
	const page = "../../docs/platforms.md"

	raw, err := os.ReadFile(page)
	if err != nil {
		t.Fatalf("reading %s: %v", page, err)
	}
	written, err := BlockIn(string(raw))
	if err != nil {
		t.Fatalf("%v — if the page was restructured, the markers have to move with it "+
			"rather than be deleted", err)
	}

	want, err := Table("../..")
	if err != nil {
		t.Fatal(err)
	}
	if written != strings.TrimSpace(want) {
		t.Errorf("docs/platforms.md is out of date. Replace what is between the markers with:\n\n%s",
			want)
	}
}

// Every capability names a stub that exists and says something.
//
// The table is only as good as the files it reads. A stub that was renamed or lost its build
// tag would make a capability read as present everywhere, which is the direction that lies.
func TestEveryCapabilityHasAStubThatSaysSomething(t *testing.T) {
	for _, c := range Capabilities {
		if _, err := os.Stat(filepath.Join("../..", c.Stub)); err != nil {
			t.Errorf("%s names %s, which is not there: %v", c.Name, c.Stub, err)
			continue
		}
		if _, err := buildTag(filepath.Join("../..", c.Stub)); err != nil {
			t.Errorf("%s: %v", c.Name, err)
		}
	}
}

// A capability nothing has anywhere, or everything has everywhere, is a row worth a second
// look rather than a row that is wrong — but the detection is what this rests on, so it is
// checked against a case known to differ.
//
// The packet filter is Linux-only and the tunnel is not. If those ever agree, this test is
// reading something other than the build tags.
func TestTheDetectionDistinguishesPlatforms(t *testing.T) {
	var filter, tunnel Capability
	for _, c := range Capabilities {
		switch c.Name {
		case "A packet filter":
			filter = c
		case "A tunnel":
			tunnel = c
		}
	}

	filterOnMac, err := Has("../..", filter, "darwin")
	if err != nil {
		t.Fatal(err)
	}
	tunnelOnMac, err := Has("../..", tunnel, "darwin")
	if err != nil {
		t.Fatal(err)
	}
	if filterOnMac {
		t.Error("macOS is reported as able to enforce a packet filter, which it is not")
	}
	if !tunnelOnMac {
		t.Error("macOS is reported as having no tunnel, so this is not reading the build tags")
	}

	nothingOnIOS, err := Has("../..", tunnel, "ios")
	if err != nil {
		t.Fatal(err)
	}
	if nothingOnIOS {
		t.Error("iOS is reported as having a tunnel; the stub's build tag excludes it and " +
			"this should have seen that")
	}
}
