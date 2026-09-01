//go:build darwin || windows

package wglink

import (
	"net/netip"
	"testing"
)

// The egress router's routes are not the interface plan's to withdraw.
//
// #202: wgplan owns the interface and removes anything on it that it did not plan, which is
// what lets it clean up after itself on platforms with no protocol number to filter on. The
// egress claim installs two halves onto the same interface, so every pass wgplan withdrew them
// and the egress router put them back — twice a second, at about five percent of a CPU, for as
// long as a full tunnel was claimed.
func TestTheEgressRoutersRoutesAreNotThePlannersToRemove(t *testing.T) {
	claim := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
		netip.MustParsePrefix("::/1"),
		netip.MustParsePrefix("8000::/1"),
		netip.MustParsePrefix("168.144.85.34/32"),
	}

	for _, owned := range claim {
		if !egressOwned(claim, owned) {
			t.Errorf("%s was installed by the egress router and the planner would withdraw it", owned)
		}
	}

	// And the peer routes stay the planner's, or it stops managing the interface at all.
	for _, planned := range []netip.Prefix{
		netip.MustParsePrefix("100.80.0.1/32"),
		netip.MustParsePrefix("100.80.0.2/32"),
		netip.MustParsePrefix("fd7c:6d65:7368:80::1/128"),
		netip.MustParsePrefix("10.0.0.0/24"),
	} {
		if egressOwned(claim, planned) {
			t.Errorf("%s is the interface plan's and was taken for the egress router's", planned)
		}
	}
}

// Matched exactly, not by containment — and this is the part that would be catastrophic
// rather than merely wasteful.
//
// The halves are 0.0.0.0/1 and 128.0.0.0/1, which between them contain very nearly every
// address a peer can have. A containment test would hide every peer route from the planner the
// moment a full tunnel was claimed, so the interface would stop being reconciled: a peer that
// went away would keep its route, and a new one would never get one.
func TestOwnershipIsExactAndNotContainment(t *testing.T) {
	halves := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
	}

	for _, peer := range []netip.Prefix{
		netip.MustParsePrefix("100.80.0.1/32"),  // inside 0.0.0.0/1
		netip.MustParsePrefix("192.168.0.0/24"), // inside 128.0.0.0/1
	} {
		if egressOwned(halves, peer) {
			t.Errorf("%s is merely inside a half and was taken for the egress router's; "+
				"the planner would stop managing the interface entirely", peer)
		}
	}
}

// Nothing claimed means nothing is excluded, which is the state of every device that is not
// carrying a full tunnel — that is to say, most of them.
func TestWithNoClaimTheInterfacePlanOwnsEverything(t *testing.T) {
	for _, prefix := range []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("100.80.0.1/32"),
	} {
		if egressOwned(nil, prefix) {
			t.Errorf("%s was excluded with no claim recorded", prefix)
		}
	}
}
