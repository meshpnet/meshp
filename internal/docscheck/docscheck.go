// Package docscheck keeps the documentation's claims about platforms true.
//
// It exists because they kept not being. Five documents said what each platform could do, and
// every slice that changed one made all five wrong at once — four times in a day after #175,
// #178, #180 and #182, and once for two days after #169, when the same change updated three
// of them and missed the fourth (#185).
//
// # Where the truth is
//
// Not in a list somebody maintains. Every capability here is a package with an
// implementation per platform and one stub for everywhere else, and that stub's build tag
// says which platforms have it:
//
//	//go:build !linux && !darwin && !windows
//
// That line cannot go stale, because a platform whose implementation exists and is not
// excluded there does not compile — the tag has to be edited in the same change that adds
// the implementation. It is the one statement of what a platform can do that the compiler
// already checks.
//
// So the table is derived from those tags and the documentation is checked against it. The
// facts are also stated once rather than five times, which is the other half of the fix: a
// claim repeated in five places goes stale in five places.
package docscheck

import (
	"fmt"
	"go/build/constraint"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Capability is one thing a platform can or cannot do, and the stub that says which.
type Capability struct {
	// Name is how the documentation refers to it.
	Name string

	// Stub is the file whose build tag excludes every platform that has an implementation.
	Stub string

	// Why is the one-line reason a reader might want, kept beside the fact so the table can
	// carry it without anybody writing it twice.
	Why string
}

// Capabilities is everything the documentation claims, in the order it is presented.
//
// Adding one means adding a row here and a package with a stub. Nothing else: the table
// renders itself and the test compares it against what is written down.
var Capabilities = []Capability{
	{"A tunnel", "internal/wglink/wglink_other.go",
		"carries traffic at all"},
	{"Names", "internal/resolved/unsupported.go",
		"mesh names resolve, and only mesh names (ADR-0021)"},
	{"A full-tunnel route", "internal/wglink/egress_other.go",
		"everything can be sent through the tunnel"},
	{"Fail-closed egress", "internal/egresslock/egresslock_other.go",
		"traffic is refused when the tunnel drops (ADR-0011)"},
	{"A packet filter", "internal/nftables/apply_other.go",
		"a network's policy is enforced on the device (ADR-0007)"},
	{"Prompt recovery", "internal/netwatch/watch_other.go",
		"a change of network is noticed rather than waited out (#172)"},
}

// Platforms is what the documentation talks about, in the order it presents them.
//
// The mobile platforms are here because their absence is a claim too, and one people ask
// about: ADR-0015 says meshp has to move packets on five platforms and two of them still do
// not.
var Platforms = []struct{ GOOS, Name string }{
	{"linux", "Linux"},
	{"darwin", "macOS"},
	{"windows", "Windows"},
	{"android", "Android"},
	{"ios", "iOS"},
}

// Has reports whether a platform has a capability, by asking the stub's build tag.
//
// The stub applies exactly where there is no implementation, so a platform has the
// capability when the tag excludes it.
func Has(root string, c Capability, goos string) (bool, error) {
	tag, err := buildTag(filepath.Join(root, c.Stub))
	if err != nil {
		return false, err
	}
	expr, err := constraint.Parse(tag)
	if err != nil {
		return false, fmt.Errorf("docscheck: %s has an unreadable build tag %q: %w", c.Stub, tag, err)
	}
	// Eval answers whether the stub is built for this platform. Architecture tags are not
	// consulted: none of these stubs has one, and a capability that existed on some
	// architectures and not others would be a different kind of claim than this table makes.
	stubApplies := expr.Eval(func(name string) bool { return name == goos })
	return !stubApplies, nil
}

// buildTag reads the //go:build line from a file.
func buildTag(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("docscheck: reading %s: %w", path, err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if constraint.IsGoBuild(line) {
			return line, nil
		}
		if strings.HasPrefix(line, "package ") {
			break
		}
	}
	return "", fmt.Errorf("docscheck: %s has no //go:build line, so it cannot say which "+
		"platforms lack this capability", path)
}

// Table renders what every platform can do, as the documentation carries it.
func Table(root string) (string, error) {
	var b strings.Builder
	b.WriteString("|  |")
	for _, p := range Platforms {
		fmt.Fprintf(&b, " %s |", p.Name)
	}
	b.WriteString("\n|---|")
	for range Platforms {
		b.WriteString("---|")
	}
	b.WriteString("\n")

	for _, c := range Capabilities {
		fmt.Fprintf(&b, "| **%s** — %s |", c.Name, c.Why)
		for _, p := range Platforms {
			has, err := Has(root, c, p.GOOS)
			if err != nil {
				return "", err
			}
			if has {
				b.WriteString(" yes |")
			} else {
				b.WriteString(" no |")
			}
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}

// MarkedBlock is what the documentation wraps the table in, so a check can find it and a
// reader can see that it is not written by hand.
const (
	BlockStart = "<!-- BEGIN platform-table: derived from the build tags, see internal/docscheck -->"
	BlockEnd   = "<!-- END platform-table -->"
)

// BlockIn returns what a document currently has between the markers.
func BlockIn(document string) (string, error) {
	start := strings.Index(document, BlockStart)
	end := strings.Index(document, BlockEnd)
	if start < 0 || end < 0 || end < start {
		return "", fmt.Errorf("docscheck: no platform table between %q and %q", BlockStart, BlockEnd)
	}
	return strings.TrimSpace(document[start+len(BlockStart) : end]), nil
}

// SortedGOOS is every platform this table covers, for callers that want to iterate.
func SortedGOOS() []string {
	out := make([]string, 0, len(Platforms))
	for _, p := range Platforms {
		out = append(out, p.GOOS)
	}
	sort.Strings(out)
	return out
}
