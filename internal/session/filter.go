package session

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/meshpnet/meshp/internal/acl"
	"github.com/meshpnet/meshp/internal/store"
	dbgen "github.com/meshpnet/meshp/internal/store/gen"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// filterFor compiles the packet filter this membership should enforce.
//
// Nil, with no error, when the network has no policy. That distinction is the one thing in
// here that must not be got wrong: no policy means nobody has written one, and a network
// that has never had a policy must keep working exactly as it did. Compiling an absent
// policy into an empty filter would arrive at every agent as "deny everything" and take
// down every deployment that upgraded.
//
// An unusable stored policy is an error rather than an absent one, for the same reason from
// the other direction: a document this build cannot read must not be silently downgraded to
// no policy at all, which would open a network that its operator believes is closed.
func (b *StateBuilder) filterFor(ctx context.Context, membership dbgen.GetMembershipForSessionRow) (*meshpv1.PacketFilter, error) {
	policy, err := b.store.ActivePolicy(ctx, membership.NetworkID)
	if errors.Is(err, store.ErrNoPolicy) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	devices, err := b.store.PolicyDevices(ctx, membership.NetworkID)
	if err != nil {
		return nil, err
	}

	self, ok := selfAmong(devices, membership)
	if !ok {
		// The device is in the network but not in the list the policy resolves against —
		// suspended, revoked, or holding no address. There is nothing to compile a filter
		// against, and sending one built from a guess would be worse than sending none.
		return nil, fmt.Errorf("session: membership %s is not among the devices its policy applies to",
			membership.MembershipID)
	}

	filter, err := acl.Compile(policy.Document, self, devices)
	if err != nil {
		return nil, fmt.Errorf("session: compiling the policy for %s: %w", membership.MembershipID, err)
	}
	return filter, nil
}

// selfAmong finds this membership in the device list.
//
// By address rather than by key, because the membership row the session holds carries
// addresses and not the WireGuard key. Matching on an address is exact here: addresses are
// allocated one per membership from the network's own pools.
func selfAmong(devices []acl.Device, membership dbgen.GetMembershipForSessionRow) (acl.Device, bool) {
	want := make(map[netip.Addr]struct{}, 2)
	for _, addr := range []*netip.Addr{membership.AddressV4, membership.AddressV6} {
		if addr != nil {
			want[addr.Unmap()] = struct{}{}
		}
	}
	if len(want) == 0 {
		return acl.Device{}, false
	}
	for _, device := range devices {
		for _, prefix := range device.Addresses {
			if _, ok := want[prefix.Addr()]; ok {
				return device, true
			}
		}
	}
	return acl.Device{}, false
}
