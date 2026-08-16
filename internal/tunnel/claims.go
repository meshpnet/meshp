package tunnel

import (
	"net/netip"
	"sort"
	"sync"
)

// Claims is what every membership on this device says it carries.
//
// A device can hold memberships in many networks at once (ADR-0004), and two customers who
// both accepted the default their router shipped with both carry 192.168.1.0/24. One
// routing table cannot hold that prefix twice, so without this one membership's route wins
// in whatever order the table happened to be written — and a technician typing
// `ssh 192.168.1.5` reaches whichever customer that was, silently, and differently after a
// restart.
//
// ADR-0019 settled what to do: the ambiguity cannot be resolved by routing, because the
// information needed to resolve it is not in the packet. Until the prefixes are made
// distinct by addressing, a collision is reported rather than picked between. A device that
// says it cannot reach either is worse to use and better to trust than one that quietly
// reaches the wrong customer.
//
// Shared by every reconciler on the device, so it is guarded: each membership reconciles on
// its own timer and on its own state deltas.
type Claims struct {
	mu sync.Mutex
	// byOwner is what each membership last said it wants to carry, keyed by interface name
	// — which is the name a person sees in `ip route` and in the logs.
	byOwner map[string][]netip.Prefix
}

// NewClaims returns a registry for one device.
func NewClaims() *Claims {
	return &Claims{byOwner: make(map[string][]netip.Prefix)}
}

// Declare records what a membership has been assigned.
//
// What it is assigned, deliberately, rather than what it ended up carrying. If a membership
// withdrew its claim on finding a collision, the other side would stop seeing one and start
// carrying, at which point the first would see no collision either — and the two would take
// turns, each briefly routing a customer's network, which is the silent wrong answer this
// exists to prevent wearing a different hat.
func (c *Claims) Declare(owner string, prefixes []netip.Prefix) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(prefixes) == 0 {
		delete(c.byOwner, owner)
		return
	}
	c.byOwner[owner] = append([]netip.Prefix(nil), prefixes...)
}

// Forget drops a membership's claims, for a device that has left a network.
func (c *Claims) Forget(owner string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.byOwner, owner)
}

// Contested reports the other memberships claiming exactly this prefix.
//
// Exactly, and not overlapping. Two memberships claiming 192.168.1.0/24 and 192.168.1.0/25
// overlap, but longest-prefix match resolves them the same way every time and on every
// machine: the /25 wins for the addresses it covers and the /24 keeps the rest. That is
// probably not what anyone intended, and it is not ambiguous, so it is not this function's
// business. An identical prefix in two networks has no answer at all.
//
// A default route is the same story. An egress group carries 0.0.0.0/0, which overlaps
// every customer prefix on the device — and again longest match decides, so a full tunnel
// alongside a LAN route is well defined rather than contested.
func (c *Claims) Contested(owner string, prefix netip.Prefix) []string {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	var others []string
	for other, prefixes := range c.byOwner {
		if other == owner {
			continue
		}
		for _, p := range prefixes {
			if p == prefix {
				others = append(others, other)
				break
			}
		}
	}
	// Sorted so the same collision reads the same way in every log line, rather than
	// changing order with map iteration and looking like a new event each pass.
	sort.Strings(others)
	return others
}
