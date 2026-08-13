package wgplan

import (
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"testing"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q): %v", s, err)
	}
	return p
}

func prefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, mustPrefix(t, s))
	}
	return out
}

// base is a valid two-peer interface, the shape the control plane sends today.
func base(t *testing.T) Interface {
	t.Helper()
	return Interface{
		Name:       "meshp0",
		PrivateKey: "private-key-of-this-device",
		ListenPort: 51820,
		MTU:        1420,
		Addresses:  prefixes(t, "100.90.0.1/32", "fd7c::1/128"),
		Peers: []Peer{
			{
				PublicKey:        "peer-bob",
				AllowedIPs:       prefixes(t, "100.90.0.2/32", "fd7c::2/128"),
				Endpoint:         "203.0.113.2:51820",
				KeepaliveSeconds: 25,
			},
			{
				PublicKey:        "peer-carol",
				AllowedIPs:       prefixes(t, "100.90.0.3/32", "fd7c::3/128"),
				KeepaliveSeconds: 25,
			},
		},
	}
}

// applied is what the platform would report after a plan was carried out. It is how the
// tests check idempotence without a real interface: plan, apply into this, plan again.
func applied(want Interface) Observed {
	obs := Observed{
		Exists:     true,
		PrivateKey: want.PrivateKey,
		ListenPort: want.ListenPort,
		MTU:        want.MTU,
		Addresses:  append([]netip.Prefix(nil), want.Addresses...),
		Peers:      append([]Peer(nil), want.Peers...),
	}
	for _, peer := range want.Peers {
		obs.Routes = append(obs.Routes, peer.AllowedIPs...)
	}
	return obs
}

func firstIndexOf(p Plan, kind OpKind) int {
	for i, op := range p.Ops {
		if op.Kind == kind {
			return i
		}
	}
	return -1
}

func TestAFreshHostGetsTheWholeInterface(t *testing.T) {
	want := base(t)
	plan, err := For(want, Observed{})
	if err != nil {
		t.Fatal(err)
	}

	if got := firstIndexOf(plan, CreateDevice); got != 0 {
		t.Errorf("create-device is at %d, want first:\n%s", got, plan)
	}
	if got := firstIndexOf(plan, BringUp); got != len(plan.Ops)-1 {
		// Half-configured and up means traffic can be sent to an interface that does not
		// yet know its peers, which fails as a black hole rather than as an error.
		t.Errorf("bring-up is at %d of %d, want last:\n%s", got, len(plan.Ops), plan)
	}

	var setPeers, addAddrs, addRoutes int
	for _, op := range plan.Ops {
		switch op.Kind {
		case SetPeer:
			setPeers++
		case AddAddress:
			addAddrs++
		case AddRoute:
			addRoutes++
		}
	}
	if setPeers != 2 {
		t.Errorf("%d set-peer operations, want 2", setPeers)
	}
	if addAddrs != 2 {
		t.Errorf("%d add-address operations, want 2 (v4 and v6)", addAddrs)
	}
	if addRoutes != 4 {
		t.Errorf("%d add-route operations, want 4 (two peers, two families)", addRoutes)
	}
}

// Invariant 18. An agent that rewrites a working interface on every tick resets every
// session it has, so "nothing changed" has to produce nothing at all.
func TestPlanningAgainstAMatchingInterfaceDoesNothing(t *testing.T) {
	want := base(t)
	plan, err := For(want, applied(want))
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Empty() {
		t.Errorf("a matching interface produced work:\n%s", plan)
	}
}

// The same, but with everything in a different order from what was asked for — which is
// how a real device reports itself, since neither the kernel nor the UAPI socket preserves
// the order anything was written in.
func TestOrderOfObservedStateDoesNotMatter(t *testing.T) {
	want := base(t)
	obs := applied(want)

	obs.Peers = []Peer{obs.Peers[1], obs.Peers[0]}
	obs.Addresses = []netip.Prefix{obs.Addresses[1], obs.Addresses[0]}
	for i := range obs.Peers {
		ips := obs.Peers[i].AllowedIPs
		obs.Peers[i].AllowedIPs = []netip.Prefix{ips[1], ips[0]}
	}
	for i, j := 0, len(obs.Routes)-1; i < j; i, j = i+1, j-1 {
		obs.Routes[i], obs.Routes[j] = obs.Routes[j], obs.Routes[i]
	}

	plan, err := For(want, obs)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Empty() {
		t.Errorf("reordering what the device reports produced work:\n%s", plan)
	}
}

// A prefix moving from one peer to another is the case that ordering exists for. Adding
// before removing would give the address to the new peer and then take it away again.
func TestAPrefixMovingBetweenPeersIsRemovedBeforeItIsAdded(t *testing.T) {
	before := base(t)
	obs := applied(before)

	// Carol is gone and Bob has taken her addresses — a re-enrolment onto the same
	// address, or a key rotation seen as one peer replacing another.
	after := base(t)
	after.Peers = []Peer{{
		PublicKey:        "peer-bob",
		AllowedIPs:       prefixes(t, "100.90.0.2/32", "fd7c::2/128", "100.90.0.3/32", "fd7c::3/128"),
		Endpoint:         "203.0.113.2:51820",
		KeepaliveSeconds: 25,
	}}

	plan, err := For(after, obs)
	if err != nil {
		t.Fatal(err)
	}

	removeCarol := -1
	setBob := -1
	for i, op := range plan.Ops {
		if op.Kind == RemovePeer && op.Peer.PublicKey == "peer-carol" {
			removeCarol = i
		}
		if op.Kind == SetPeer && op.Peer.PublicKey == "peer-bob" {
			setBob = i
		}
	}
	if removeCarol < 0 || setBob < 0 {
		t.Fatalf("expected both a removal and a set:\n%s", plan)
	}
	if removeCarol > setBob {
		t.Errorf("carol is removed at %d, after bob is set at %d — bob's claim on\n"+
			"100.90.0.3/32 would be taken back by the removal:\n%s", removeCarol, setBob, plan)
	}
}

// Two peers holding the same prefix is not something to apply half of: WireGuard would
// give it to whichever was written last and silently take it from the other.
func TestOverlappingAllowedIPsAreRefused(t *testing.T) {
	cases := []struct {
		name  string
		a, b  []string
		wants []string // substrings the error must name, so it is actionable
	}{
		{
			name:  "exactly the same prefix",
			a:     []string{"100.90.0.9/32"},
			b:     []string{"100.90.0.9/32"},
			wants: []string{"peer-a", "peer-b", "100.90.0.9/32"},
		},
		{
			name:  "a host inside another peer's wider prefix",
			a:     []string{"10.0.0.0/24"},
			b:     []string{"10.0.0.5/32"},
			wants: []string{"peer-a", "peer-b", "overlaps"},
		},
		{
			name:  "v6, where the same mistake is easier to miss",
			a:     []string{"fd7c::/64"},
			b:     []string{"fd7c::5/128"},
			wants: []string{"overlaps"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			iface := base(t)
			iface.Peers = []Peer{
				{PublicKey: "peer-a", AllowedIPs: prefixes(t, tc.a...)},
				{PublicKey: "peer-b", AllowedIPs: prefixes(t, tc.b...)},
			}
			plan, err := For(iface, Observed{})
			if err == nil {
				t.Fatalf("an overlap was accepted:\n%s", plan)
			}
			if !plan.Empty() {
				t.Error("operations were returned alongside the error")
			}
			for _, want := range tc.wants {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the error does not name %q, so it cannot be acted on: %v", want, err)
				}
			}
		})
	}
}

func TestAPeerMayNotClaimThisDevicesOwnAddress(t *testing.T) {
	iface := base(t)
	iface.Peers = []Peer{{PublicKey: "peer-a", AllowedIPs: prefixes(t, "100.90.0.1/32")}}

	if _, err := For(iface, Observed{}); err == nil {
		t.Error("a peer claiming this device's own address was accepted")
	} else if !strings.Contains(err.Error(), "own address") {
		t.Errorf("the error does not explain what is wrong: %v", err)
	}
}

// A local address wider than a host prefix creates a connected route for the whole pool,
// so traffic to an unassigned address is swallowed by the tunnel rather than failing.
func TestALocalAddressMustBeAHostPrefix(t *testing.T) {
	for _, addr := range []string{"100.90.0.1/24", "fd7c::1/64"} {
		iface := base(t)
		iface.Addresses = prefixes(t, addr)
		iface.Peers = nil
		_, err := For(iface, Observed{})
		if err == nil {
			t.Errorf("%s was accepted as a local address", addr)
			continue
		}
		if !strings.Contains(err.Error(), "host prefix") {
			t.Errorf("for %s the error does not say why: %v", addr, err)
		}
	}
}

func TestConfigurationsThatAreNotWorthApplying(t *testing.T) {
	cases := map[string]func(*Interface){
		"no name":            func(i *Interface) { i.Name = "" },
		"no private key":     func(i *Interface) { i.PrivateKey = "" },
		"no MTU":             func(i *Interface) { i.MTU = 0 },
		"negative MTU":       func(i *Interface) { i.MTU = -1 },
		"no addresses":       func(i *Interface) { i.Addresses = nil },
		"a peer with no key": func(i *Interface) { i.Peers[0].PublicKey = "" },
		"a peer with no allowed IPs": func(i *Interface) {
			i.Peers[0].AllowedIPs = nil
		},
		"the same peer twice": func(i *Interface) {
			i.Peers[1].PublicKey = i.Peers[0].PublicKey
		},
	}
	for name, break_ := range cases {
		t.Run(name, func(t *testing.T) {
			iface := base(t)
			break_(&iface)
			if _, err := For(iface, Observed{}); err == nil {
				t.Errorf("%s was accepted", name)
			}
		})
	}
}

// A key rotation reaches the device as one peer leaving and another arriving, because a
// WireGuard peer *is* its key. The old peer must go, or the interface accumulates
// unreachable peers that still hold claims on addresses.
func TestARotatedKeyReplacesThePeer(t *testing.T) {
	before := base(t)
	obs := applied(before)

	after := base(t)
	after.Peers[0].PublicKey = "peer-bob-after-rotation"

	plan, err := For(after, obs)
	if err != nil {
		t.Fatal(err)
	}

	var removedOld, addedNew bool
	for _, op := range plan.Ops {
		if op.Kind == RemovePeer && op.Peer.PublicKey == "peer-bob" {
			removedOld = true
		}
		if op.Kind == SetPeer && op.Peer.PublicKey == "peer-bob-after-rotation" {
			addedNew = true
		}
	}
	if !removedOld {
		t.Errorf("the old key was left configured:\n%s", plan)
	}
	if !addedNew {
		t.Errorf("the new key was not configured:\n%s", plan)
	}

	// And nothing else moved: the addresses are the same, so no route work.
	for _, op := range plan.Ops {
		if op.Kind == AddRoute || op.Kind == RemoveRoute {
			t.Errorf("a rotation onto the same addresses touched routes: %s", op)
		}
	}
}

// An endpoint appearing is the moment a configured-but-unreachable peer becomes
// reachable. It must rewrite that peer and nothing else.
func TestAnEndpointAppearingRewritesOnlyThatPeer(t *testing.T) {
	before := base(t)
	obs := applied(before)

	after := base(t)
	after.Peers[1].Endpoint = "198.51.100.3:51820"

	plan, err := For(after, obs)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Ops) != 1 {
		t.Fatalf("expected one operation, got:\n%s", plan)
	}
	if plan.Ops[0].Kind != SetPeer || plan.Ops[0].Peer.PublicKey != "peer-carol" {
		t.Errorf("expected carol to be rewritten, got: %s", plan.Ops[0])
	}
}

// The private key is not rewritten when it has not changed: doing so resets every session
// on the interface, which drops traffic for a tick that had nothing to do.
func TestTheDeviceIsNotRewrittenWhenNothingAboutItChanged(t *testing.T) {
	want := base(t)
	obs := applied(want)
	obs.Peers = nil // a peer changed; the device did not
	obs.Routes = nil

	plan, err := For(want, obs)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range plan.Ops {
		if op.Kind == SetDevice {
			t.Errorf("the device was rewritten although only peers changed:\n%s", plan)
		}
	}
}

func TestAChangedMTUOrPortRewritesTheDevice(t *testing.T) {
	for name, change := range map[string]func(*Interface){
		"mtu":  func(i *Interface) { i.MTU = 1280 },
		"port": func(i *Interface) { i.ListenPort = 51821 },
		"key":  func(i *Interface) { i.PrivateKey = "a-new-private-key" },
	} {
		t.Run(name, func(t *testing.T) {
			want := base(t)
			obs := applied(want)
			change(&want)

			plan, err := For(want, obs)
			if err != nil {
				t.Fatal(err)
			}
			if firstIndexOf(plan, SetDevice) < 0 {
				t.Errorf("changing the %s did not rewrite the device:\n%s", name, plan)
			}
		})
	}
}

// Invariant 20. Teardown removes what was installed, in an order that does not leave a
// route pointing at an interface that no longer exists.
func TestTeardownRemovesEverythingItInstalled(t *testing.T) {
	want := base(t)
	plan := Teardown(applied(want))

	lastRoute, firstAddress := -1, -1
	for i, op := range plan.Ops {
		if op.Kind == RemoveRoute {
			lastRoute = i
		}
		if op.Kind == RemoveAddress && firstAddress < 0 {
			firstAddress = i
		}
	}
	if lastRoute < 0 || firstAddress < 0 {
		t.Fatalf("teardown removed no routes or no addresses:\n%s", plan)
	}
	if lastRoute > firstAddress {
		t.Errorf("a route is removed at %d, after an address at %d:\n%s", lastRoute, firstAddress, plan)
	}
	if last := plan.Ops[len(plan.Ops)-1].Kind; last != DestroyDevice {
		t.Errorf("teardown ends with %s, want destroy-device", last)
	}

	// Everything installed, and only that. A route through another interface is not ours.
	removed := make(map[netip.Prefix]bool)
	for _, op := range plan.Ops {
		if op.Kind == RemoveRoute || op.Kind == RemoveAddress {
			removed[op.Prefix] = true
		}
	}
	for _, addr := range want.Addresses {
		if !removed[addr] {
			t.Errorf("teardown left the address %s behind", addr)
		}
	}
	for _, peer := range want.Peers {
		for _, ip := range peer.AllowedIPs {
			if !removed[ip] {
				t.Errorf("teardown left the route %s behind", ip)
			}
		}
	}
}

func TestTearingDownWhatIsNotThereDoesNothing(t *testing.T) {
	if plan := Teardown(Observed{}); !plan.Empty() {
		t.Errorf("tearing down a nonexistent interface produced work:\n%s", plan)
	}
}

// A route pointing at this interface that no peer justifies is withdrawn — a peer that
// left while the agent was not running, or a leftover from a previous version.
func TestARouteNoPeerJustifiesIsWithdrawn(t *testing.T) {
	want := base(t)
	obs := applied(want)
	stale := mustPrefix(t, "100.90.0.44/32")
	obs.Routes = append(obs.Routes, stale)

	plan, err := For(want, obs)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, op := range plan.Ops {
		if op.Kind == RemoveRoute && op.Prefix == stale {
			found = true
		}
	}
	if !found {
		t.Errorf("the stale route %s was left in place:\n%s", stale, plan)
	}
}

// Two plans for the same inputs must be identical. Anything derived from map iteration
// would make logs, comparisons and this test itself unstable.
func TestPlansAreDeterministic(t *testing.T) {
	want := base(t)
	want.Peers = append(want.Peers, Peer{
		PublicKey:  "peer-dave",
		AllowedIPs: prefixes(t, "100.90.0.4/32", "fd7c::4/128"),
	})

	first, err := For(want, Observed{})
	if err != nil {
		t.Fatal(err)
	}
	for range 30 {
		again, err := For(want, Observed{})
		if err != nil {
			t.Fatal(err)
		}
		if first.String() != again.String() {
			t.Fatalf("two plans for the same input differ:\n--- first ---\n%s\n--- again ---\n%s",
				first, again)
		}
	}
}

// The property that matters: whatever state a device is in, applying one plan reaches the
// desired state, and planning again finds nothing left to do. A second round that is not
// empty means the plan did not say everything, and the agent would rewrite the interface
// on every tick forever.
func TestPropertyOnePlanIsEnough(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5eed1e))

	for attempt := range 400 {
		want := randomInterface(t, rng)
		observed := randomObserved(t, rng, want)

		plan, err := For(want, observed)
		if err != nil {
			t.Fatalf("attempt %d: planning failed for a valid interface: %v", attempt, err)
		}

		reached := simulate(observed, plan)

		second, err := For(want, reached)
		if err != nil {
			t.Fatalf("attempt %d: planning against the reached state failed: %v", attempt, err)
		}
		if !second.Empty() {
			t.Fatalf("attempt %d: a second plan was not empty, so the first was incomplete.\n"+
				"--- first ---\n%s\n--- second ---\n%s", attempt, plan, second)
		}

		// And the reached state really is what was asked for, not merely stable.
		if err := sameAsWanted(want, reached); err != nil {
			t.Fatalf("attempt %d: %v\n--- plan ---\n%s", attempt, err, plan)
		}
	}
}

// simulate applies a plan to observed state the way a platform would, so the property
// test can check what a real device would end up holding.
func simulate(obs Observed, plan Plan) Observed {
	peers := indexPeers(obs.Peers)
	addrs := prefixSet(obs.Addresses)
	routes := prefixSet(obs.Routes)

	for _, op := range plan.Ops {
		switch op.Kind {
		case CreateDevice:
			obs.Exists = true
		case DestroyDevice:
			return Observed{}
		case SetDevice:
			obs.PrivateKey = op.Device.PrivateKey
			obs.ListenPort = op.Device.ListenPort
			obs.MTU = op.Device.MTU
		case SetPeer:
			peers[op.Peer.PublicKey] = op.Peer
		case RemovePeer:
			delete(peers, op.Peer.PublicKey)
		case AddAddress:
			addrs[op.Prefix] = struct{}{}
		case RemoveAddress:
			delete(addrs, op.Prefix)
		case AddRoute:
			routes[op.Prefix] = struct{}{}
		case RemoveRoute:
			delete(routes, op.Prefix)
		case BringUp:
		}
	}

	out := Observed{Exists: obs.Exists, PrivateKey: obs.PrivateKey, ListenPort: obs.ListenPort, MTU: obs.MTU}
	for _, key := range sortedKeys(peers) {
		out.Peers = append(out.Peers, peers[key])
	}
	for p := range addrs {
		out.Addresses = append(out.Addresses, p)
	}
	for p := range routes {
		out.Routes = append(out.Routes, p)
	}
	out.Addresses = sortPrefixes(out.Addresses)
	out.Routes = sortPrefixes(out.Routes)
	return out
}

func sameAsWanted(want Interface, reached Observed) error {
	if !reached.Exists {
		return fmt.Errorf("the interface does not exist after the plan")
	}
	if len(reached.Peers) != len(want.Peers) {
		return fmt.Errorf("%d peers after the plan, want %d", len(reached.Peers), len(want.Peers))
	}
	have := indexPeers(reached.Peers)
	for _, peer := range want.Peers {
		got, ok := have[peer.PublicKey]
		if !ok {
			return fmt.Errorf("peer %s is missing", peer.PublicKey)
		}
		if !samePeer(got, peer) {
			return fmt.Errorf("peer %s was not configured as asked", peer.PublicKey)
		}
	}

	wantAddrs := sortPrefixes(want.Addresses)
	gotAddrs := sortPrefixes(reached.Addresses)
	if len(wantAddrs) != len(gotAddrs) {
		return fmt.Errorf("%d addresses, want %d", len(gotAddrs), len(wantAddrs))
	}
	for i := range wantAddrs {
		if wantAddrs[i] != gotAddrs[i] {
			return fmt.Errorf("address %s, want %s", gotAddrs[i], wantAddrs[i])
		}
	}

	wantRoutesSorted := sortPrefixes(wantRoutes(want))
	gotRoutes := sortPrefixes(reached.Routes)
	if len(wantRoutesSorted) != len(gotRoutes) {
		return fmt.Errorf("%d routes, want %d", len(gotRoutes), len(wantRoutesSorted))
	}
	for i := range wantRoutesSorted {
		if wantRoutesSorted[i] != gotRoutes[i] {
			return fmt.Errorf("route %s, want %s", gotRoutes[i], wantRoutesSorted[i])
		}
	}
	return nil
}

// randomInterface builds a valid interface: distinct host addresses, so no two peers can
// overlap. Generating invalid ones here would only prove the validator rejects them,
// which the cases above already do.
func randomInterface(t *testing.T, rng *rand.Rand) Interface {
	t.Helper()
	iface := Interface{
		Name:       "meshp0",
		PrivateKey: Key(fmt.Sprintf("priv-%d", rng.Intn(3))),
		ListenPort: 51820 + rng.Intn(2),
		MTU:        []int{1280, 1420}[rng.Intn(2)],
		Addresses:  prefixes(t, "100.90.0.1/32", "fd7c::1/128"),
	}

	// Peers drawn from a pool of distinct host addresses, so validity is structural.
	used := make(map[int]bool)
	for range rng.Intn(6) {
		host := 2 + rng.Intn(40)
		if used[host] {
			continue
		}
		used[host] = true

		peer := Peer{
			PublicKey:        Key(fmt.Sprintf("peer-%02d", host)),
			AllowedIPs:       prefixes(t, fmt.Sprintf("100.90.0.%d/32", host), fmt.Sprintf("fd7c::%x/128", host)),
			KeepaliveSeconds: []int{0, 25}[rng.Intn(2)],
		}
		if rng.Intn(2) == 0 {
			peer.Endpoint = fmt.Sprintf("203.0.113.%d:51820", host)
		}
		if rng.Intn(4) == 0 {
			peer.PresharedKey = Key(fmt.Sprintf("psk-%d", host))
		}
		iface.Peers = append(iface.Peers, peer)
	}
	return iface
}

// randomObserved invents a device in some arbitrary state: absent, correct, partly
// correct, or carrying things nobody asked for.
func randomObserved(t *testing.T, rng *rand.Rand, want Interface) Observed {
	t.Helper()
	switch rng.Intn(5) {
	case 0:
		return Observed{} // nothing there at all

	case 1:
		return applied(want) // already correct

	case 2:
		// Correct, then damaged: peers dropped, addresses missing, a stale route.
		obs := applied(want)
		if len(obs.Peers) > 0 {
			obs.Peers = obs.Peers[rng.Intn(len(obs.Peers)):]
		}
		if len(obs.Addresses) > 1 && rng.Intn(2) == 0 {
			obs.Addresses = obs.Addresses[1:]
		}
		obs.Routes = append(obs.Routes, mustPrefix(t, fmt.Sprintf("100.90.9.%d/32", 1+rng.Intn(9))))
		return obs

	case 3:
		// Right peers, wrong details: the shape that must still produce a rewrite.
		obs := applied(want)
		for i := range obs.Peers {
			if rng.Intn(2) == 0 {
				obs.Peers[i].Endpoint = "192.0.2.99:1"
			}
			if rng.Intn(3) == 0 {
				obs.Peers[i].KeepaliveSeconds = 99
			}
		}
		obs.MTU = 9000
		return obs

	default:
		// An interface belonging to an older configuration: peers and routes for devices
		// that are no longer in this network at all.
		obs := Observed{Exists: true, PrivateKey: "an-old-private-key", ListenPort: 41820, MTU: 1400}
		for i := range 1 + rng.Intn(3) {
			key := Key(fmt.Sprintf("stale-peer-%d", i))
			ips := prefixes(t, fmt.Sprintf("100.90.8.%d/32", 1+i))
			obs.Peers = append(obs.Peers, Peer{PublicKey: key, AllowedIPs: ips})
			obs.Routes = append(obs.Routes, ips...)
		}
		obs.Addresses = prefixes(t, "100.90.7.1/32")
		return obs
	}
}
