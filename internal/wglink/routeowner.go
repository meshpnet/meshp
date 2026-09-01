//go:build darwin || windows

package wglink

import "net/netip"

// Two parts of meshp write routes to the tunnel, and only one of them plans.
//
// wgplan owns the interface: it decides which peers exist and which prefixes reach them, and
// it withdraws anything on the interface it did not put there. That rule is what lets the
// agent clean up after itself on platforms with no protocol number to filter on (#193), and
// it was true right up until something else started writing to the same interface.
//
// The egress router is that something. Claiming a full tunnel installs two halves that beat
// the default route, and on these platforms they go into the same table, on the same
// interface, as everything wgplan manages. So every pass, wgplan withdrew them as strays and
// the egress router put them back: about twice a second on a laptop, at roughly five percent
// of a CPU, for as long as a full tunnel was claimed (#202).
//
// Linux does not have this, and not by luck — it claims with a firewall mark and a routing
// table of its own, so the two never share a table (docs/platforms.md). These platforms have
// no equivalent, which is why the claim is expressed as ordinary routes and why ownership has
// to be recorded rather than inferred.
//
// The record already existed. recordClaim has written exactly these prefixes since the claim
// was first implemented, because ADR-0011 requires a later process to be able to undo what an
// earlier one installed. Asking it is the difference between "meshp owns every route on this
// interface" — true, and no longer sufficient — and "this component owns these".

// egressOwned reports whether a prefix belongs to the egress router rather than to the
// interface plan.
//
// Compared exactly rather than by containment. The halves are 0.0.0.0/1 and 128.0.0.0/1,
// which contain very nearly every address a peer could have: a containment test would hide
// every peer route from the planner the moment a full tunnel was claimed, and the interface
// would stop being reconciled at all.
func egressOwned(claim []netip.Prefix, prefix netip.Prefix) bool {
	for _, owned := range claim {
		if owned == prefix {
			return true
		}
	}
	return false
}
