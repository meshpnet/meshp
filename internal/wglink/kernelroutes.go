//go:build darwin || windows

// Only these two. Linux marks a route with the protocol number that installed it, so meshp
// filters on its own and never sees the kernel's — the problem this file solves does not
// exist there, and a shared helper nothing on Linux calls is one `make lint-cross` rejects.
package wglink

import "net/netip"

// kernelOwned reports whether a prefix is one the operating system maintains itself, rather
// than one meshp could have installed.
//
// Every route on a meshp interface counts as meshp's — the rule on these two platforms,
// where there is no protocol number to filter on and the justification is that meshp created
// the interface. These are the exception, because the kernel puts them there: adding an
// IPv6 address to an interface installs the link-local prefix and the multicast prefixes
// alongside it, on macOS and on Windows both, and neither reports them as anything other than
// ordinary routes through that interface.
//
// Reporting them costs more than a wasted comparison. The planner withdraws them, the kernel
// restores them, and the route socket reports the change — which since #184 wakes the
// reconciler, so the agent runs the same four operations twice a second for as long as it is
// up. That shipped, and was found by running it on a laptop rather than by any test.
//
// Deliberately a question about the prefix rather than about the routing message: the flags
// that distinguish these differ between platforms and, for the multicast entries, do not
// distinguish them at all. What is reliable is that an address meshp hands out comes from the
// network's own range (ADR-0005) and is never link-local or multicast, so nothing excluded
// here could have been ours to install.
func kernelOwned(prefix netip.Prefix) bool {
	addr := prefix.Addr()
	return addr.IsLinkLocalUnicast() || addr.IsMulticast()
}
