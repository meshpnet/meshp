package tunnel

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/meshpnet/meshp/internal/peerset"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

func egressState(version uint64) *peerset.Set {
	return stateWithRoutes(version,
		[]*meshpv1.RouteGroupAssignment{assignmentTo("exit", bobKey, "0.0.0.0/0", "::/0")},
		peer(bobKey, "100.90.0.2/32"))
}

func withEgress(t *testing.T) (*Reconciler, *fakeFilter, *fakeEgress, *[]string) {
	t.Helper()
	order := &[]string{}
	filter := &fakeFilter{order: order}
	router := &fakeEgress{order: order}
	m := membership()
	m.ControlURL = "https://198.51.100.10:8443"
	r := New(newFakeLink(), m, nil, filter, nil)
	r.egress = router
	return r, filter, router, order
}

// The ordering the whole feature rests on: the lock is installed before the route is
// claimed. The gap between them, in the other order, is a device sending the user's traffic
// in clear over whatever network it is on at the moment it believes it is protected.
func TestTheLockGoesOnBeforeTheRouteIsClaimed(t *testing.T) {
	r, _, _, order := withEgress(t)

	if _, err := r.Apply(context.Background(), egressState(1)); err != nil {
		t.Fatal(err)
	}
	// One sequence, not two, because what is under test is which came first.
	if got := strings.Join(*order, ", "); got != "lock meshp0, claim meshp0" {
		t.Errorf("order was %q, want the lock installed before the route was claimed", got)
	}
}

// And the reverse on the way out. A lock still in place with the route gone refuses
// everything and the machine has no network.
func TestTheRouteIsReleasedBeforeTheLockComesOff(t *testing.T) {
	r, _, _, order := withEgress(t)
	if _, err := r.Apply(context.Background(), egressState(1)); err != nil {
		t.Fatal(err)
	}

	// The group goes away.
	plain := stateWithRoutes(2, nil, peer(bobKey, "100.90.0.2/32"))
	if _, err := r.Apply(context.Background(), plain); err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(*order, ", "); got != "lock meshp0, claim meshp0, release, unlock" {
		t.Errorf("order was %q, want the route released before the lock came off", got)
	}
}

// A claim that cannot be made safely is not made at all. Without a control plane address
// the device would lock itself away from the one channel that could tell it to stop.
func TestAClaimIsRefusedWithoutAWayBackToTheControlPlane(t *testing.T) {
	filter := &fakeFilter{}
	router := &fakeEgress{}
	r := New(newFakeLink(), membership(), nil, filter, nil) // no ControlURL
	r.egress = router

	unapplied, err := r.Apply(context.Background(), egressState(1))
	if err != nil {
		t.Fatal(err)
	}
	if !slicesContain(unapplied, "egress") {
		t.Errorf("unapplied = %v, want egress reported", unapplied)
	}
	if len(router.events) != 0 {
		t.Errorf("a default route was claimed anyway: %v", router.events)
	}
	if len(filter.locks) != 0 {
		t.Errorf("a lock was installed with no way back: %v", filter.locks)
	}
}

// A host that cannot do one half must not do the other. Half of this feature is not a
// degraded version of it.
func TestAHostThatCannotRouteDoesNotLockItself(t *testing.T) {
	filter := &fakeFilter{}
	m := membership()
	m.ControlURL = "https://198.51.100.10:8443"
	r := New(newFakeLink(), m, nil, filter, nil) // no egress implementation

	unapplied, err := r.Apply(context.Background(), egressState(1))
	if err != nil {
		t.Fatal(err)
	}
	if !slicesContain(unapplied, "egress") {
		t.Errorf("unapplied = %v, want egress reported", unapplied)
	}
	if len(filter.locks) != 0 {
		t.Errorf("a host that cannot claim a route locked itself anyway: %v", filter.locks)
	}
}

// The safe half of a half-done claim. If the route will not go on, the lock stays: this
// device sends nothing rather than sending it the wrong way, and the next pass tries again.
func TestAFailedClaimLeavesTheLockOn(t *testing.T) {
	r, filter, router, _ := withEgress(t)
	router.claimErr = errors.New("netlink said no")

	unapplied, err := r.Apply(context.Background(), egressState(1))
	if err != nil {
		t.Fatal(err)
	}
	if !slicesContain(unapplied, "egress") {
		t.Errorf("unapplied = %v, want egress reported", unapplied)
	}
	if len(filter.locks) == 0 || filter.locks[len(filter.locks)-1] != "meshp0" {
		t.Errorf("the lock was not left in place after a failed claim: %v", filter.locks)
	}
}

// The carve-out reaches the lock. A lock that permitted nothing would refuse the control
// plane and the relay along with everything else.
func TestTheCarveoutReachesTheLock(t *testing.T) {
	r, filter, _, _ := withEgress(t)

	if _, err := r.Apply(context.Background(), egressState(1)); err != nil {
		t.Fatal(err)
	}
	if len(filter.endpoints) == 0 || len(filter.endpoints[0]) == 0 {
		t.Fatal("the lock was given no endpoints, so the control plane is unreachable")
	}
	var sawControl bool
	for _, ep := range filter.endpoints[0] {
		if ep.String() == "198.51.100.10:8443" {
			sawControl = true
		}
	}
	if !sawControl {
		t.Errorf("the control plane is not in the lock's endpoints: %v", filter.endpoints[0])
	}
	if len(filter.excluded[0]) == 0 {
		t.Error("the lock was given no excluded prefixes, so link-local traffic is refused")
	}
}
