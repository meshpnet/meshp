package tunnel

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/clock"
	"github.com/meshpnet/meshp/internal/pathprobe"
	"github.com/meshpnet/meshp/internal/peerset"
	"github.com/meshpnet/meshp/internal/routeprobe"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// fakeProber answers however a test says, and records what it was asked.
type fakeProber struct {
	mu sync.Mutex

	// answer decides each target. Nil means every target answers.
	answer func(netip.AddrPort) error

	// calls records one entry per Probe, holding the interface it was told to use.
	calls []probeCall
}

type probeCall struct {
	iface   string
	targets []netip.AddrPort
}

func (p *fakeProber) Probe(_ context.Context, iface string, targets []netip.AddrPort) []pathprobe.Outcome {
	p.mu.Lock()
	p.calls = append(p.calls, probeCall{iface: iface, targets: targets})
	answer := p.answer
	p.mu.Unlock()

	out := make([]pathprobe.Outcome, 0, len(targets))
	for _, t := range targets {
		var err error
		if answer != nil {
			err = answer(t)
		}
		out = append(out, pathprobe.Outcome{Target: t, RTT: 5 * time.Millisecond, Err: err})
	}
	return out
}

func (p *fakeProber) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

func (p *fakeProber) lastIface() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.calls) == 0 {
		return ""
	}
	return p.calls[len(p.calls)-1].iface
}

// probedGroup is a group with two candidates and targets to dial through them.
func probedGroup(first, second string, targets ...string) *meshpv1.RouteGroupAssignment {
	return &meshpv1.RouteGroupAssignment{
		RouteGroupId: "group-branch", Name: "branch", Prefixes: []string{"192.168.10.0/24"},
		Candidates: []*meshpv1.RouteCandidate{
			{PeerPublicKey: first, AdvertiserId: "adv-first", Priority: 1},
			{PeerPublicKey: second, AdvertiserId: "adv-second", Priority: 2},
		},
		LocalFailover: &meshpv1.LocalFailoverPolicy{
			Enabled: true, FailThreshold: 1, ProbeTargets: targets,
		},
	}
}

// handshaking marks every peer as freshly handshaking, which is the state the handshake
// probe calls healthy.
func handshaking(link *fakeLink) {
	for i := range link.observed.Peers {
		link.observed.Peers[i].HasHandshake = true
		link.observed.Peers[i].HandshakeAge = time.Second
	}
}

// warmUp applies once so the peers exist, then forgets that it happened.
//
// The first pass configures the interface from nothing, so there are no observed peers to
// read a handshake from and nothing is probed — which is correct behaviour and not what any
// of these tests are about. Doing it explicitly, and resetting the prober afterwards, keeps
// every count below a statement about probing rather than about start-up.
func warmUp(t *testing.T, r *Reconciler, link *fakeLink, state *peerset.Set, prober *fakeProber) {
	t.Helper()
	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	handshaking(link)
	if prober != nil {
		prober.reset()
	}
}

func (p *fakeProber) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = nil
}

// The failure this whole thing exists for.
//
// The advertiser is up, its handshake is fresh, and nothing gets through it — a branch
// router whose own uplink has failed. Before this, every device steered at that router sat
// there with no route to anything while the agent, the control plane and the handshake all
// reported health.
func TestADeviceLeavesAnAdvertiserThatIsUpButUseless(t *testing.T) {
	clk := clock.NewFake()
	link := newFakeLink()
	prober := &fakeProber{answer: func(netip.AddrPort) error { return context.DeadlineExceeded }}
	r := New(link, membership(), nil, nil, nil).
		WithChooser(routeprobe.New(clk)).
		WithProber(prober)

	state := stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{probedGroup(bobKey, carolKey, "1.1.1.1:443", "9.9.9.9:443")},
		peer(bobKey, "100.90.0.2/32"), peer(carolKey, "100.90.0.3/32"))

	handshaking(link)
	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	handshaking(link)
	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	if prober.count() == 0 {
		t.Fatal("nothing was probed, so the handshake is still the whole verdict")
	}
	if got := r.chooser.Current(state.RouteGroups()[0]).GetAdvertiserId(); got != "adv-second" {
		t.Errorf("still using %q; the device stayed on an advertiser nothing gets through", got)
	}
}

// And it stays put when the path works, or every device would move on the first probe.
func TestAWorkingPathKeepsTheAdvertiser(t *testing.T) {
	clk := clock.NewFake()
	link := newFakeLink()
	prober := &fakeProber{}
	r := New(link, membership(), nil, nil, nil).
		WithChooser(routeprobe.New(clk)).
		WithProber(prober)

	state := stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{probedGroup(bobKey, carolKey, "1.1.1.1:443", "9.9.9.9:443")},
		peer(bobKey, "100.90.0.2/32"), peer(carolKey, "100.90.0.3/32"))

	for range 5 {
		handshaking(link)
		if _, err := r.Apply(context.Background(), state); err != nil {
			t.Fatal(err)
		}
	}
	if got := r.chooser.Current(state.RouteGroups()[0]).GetAdvertiserId(); got != "adv-first" {
		t.Errorf("moved to %q while every target was answering", got)
	}
}

// The probe is dialled through the tunnel, not through whatever the routing table prefers.
// A probe on the wrong interface measures the local network and reports it as the
// advertiser's health.
func TestTheProbeGoesThroughTheTunnelInterface(t *testing.T) {
	link := newFakeLink()
	prober := &fakeProber{}
	r := New(link, membership(), nil, nil, nil).
		WithChooser(routeprobe.New(clock.NewFake())).
		WithProber(prober)

	state := stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{probedGroup(bobKey, carolKey, "1.1.1.1:443")},
		peer(bobKey, "100.90.0.2/32"), peer(carolKey, "100.90.0.3/32"))

	warmUp(t, r, link, state, prober)
	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if got := prober.lastIface(); got != membership().InterfaceName {
		t.Errorf("probed through %q, want the tunnel %q", got, membership().InterfaceName)
	}
}

// A group with no targets is not probed at all, and the handshake stays in charge. That is
// every network that has not configured one, which today is all of them.
func TestAGroupWithNoTargetsIsNotProbed(t *testing.T) {
	link := newFakeLink()
	prober := &fakeProber{answer: func(netip.AddrPort) error { return context.DeadlineExceeded }}
	r := New(link, membership(), nil, nil, nil).
		WithChooser(routeprobe.New(clock.NewFake())).
		WithProber(prober)

	state := stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{probedGroup(bobKey, carolKey)},
		peer(bobKey, "100.90.0.2/32"), peer(carolKey, "100.90.0.3/32"))

	for range 5 {
		handshaking(link)
		if _, err := r.Apply(context.Background(), state); err != nil {
			t.Fatal(err)
		}
	}
	if prober.count() != 0 {
		t.Errorf("a group with no targets was probed %d times", prober.count())
	}
	if got := r.chooser.Current(state.RouteGroups()[0]).GetAdvertiserId(); got != "adv-first" {
		t.Errorf("moved to %q on a group nobody asked to be probed", got)
	}
}

// An advertiser the handshake already says is gone is not dialled through.
//
// The tunnel the probe would have to travel through is the thing the handshake just reported
// as dead, so the packets would be spent to reach an answer already in hand — and a device
// whose gateway has failed should not also be generating traffic.
func TestASilentAdvertiserIsNotProbed(t *testing.T) {
	link := newFakeLink()
	prober := &fakeProber{}
	r := New(link, membership(), nil, nil, nil).
		WithChooser(routeprobe.New(clock.NewFake())).
		WithProber(prober)

	state := stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{probedGroup(bobKey, carolKey, "1.1.1.1:443")},
		peer(bobKey, "100.90.0.2/32"), peer(carolKey, "100.90.0.3/32"))

	// The warm-up puts the peers on the interface and hands them a fresh handshake, so that
	// what follows is a statement about a stale one rather than about start-up. Without it
	// there are no observed peers at all, nothing is probed for that reason, and this test
	// passes whatever the code does — which is how it was written the first time, and what a
	// mutation caught.
	warmUp(t, r, link, state, prober)

	// Now every peer's handshake goes stale.
	for i := range link.observed.Peers {
		link.observed.Peers[i].HasHandshake = true
		link.observed.Peers[i].HandshakeAge = time.Hour
	}
	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if prober.count() != 0 {
		t.Error("an advertiser whose handshake is stale was dialled through anyway")
	}

	// And a fresh one is probed, so the assertion above is about staleness and not about
	// the prober being unreachable from here.
	handshaking(link)
	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if prober.count() == 0 {
		t.Error("a fresh handshake was not probed either, so the check above proves nothing")
	}
}

// A host with no prober keeps the handshake, rather than failing every advertiser because it
// cannot answer the question.
func TestAHostWithNoProberFallsBackToTheHandshake(t *testing.T) {
	link := newFakeLink()
	r := New(link, membership(), nil, nil, nil).
		WithChooser(routeprobe.New(clock.NewFake()))

	state := stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{probedGroup(bobKey, carolKey, "1.1.1.1:443")},
		peer(bobKey, "100.90.0.2/32"), peer(carolKey, "100.90.0.3/32"))

	for range 5 {
		handshaking(link)
		if _, err := r.Apply(context.Background(), state); err != nil {
			t.Fatal(err)
		}
	}
	if got := r.chooser.Current(state.RouteGroups()[0]).GetAdvertiserId(); got != "adv-first" {
		t.Errorf("a host that cannot probe moved to %q anyway", got)
	}
}

// Targets the agent cannot parse mean the probe does not run, rather than running against
// the ones it could read.
//
// Dropping the unparseable ones would quietly lower the number of targets a quorum is
// measured against: a policy asking for two of three would silently become two of two, and
// the group would fail on one target's bad afternoon.
func TestUnreadableTargetsFallBackRatherThanShrinkTheQuorum(t *testing.T) {
	link := newFakeLink()
	prober := &fakeProber{}
	r := New(link, membership(), nil, nil, nil).
		WithChooser(routeprobe.New(clock.NewFake())).
		WithProber(prober)

	state := stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{probedGroup(bobKey, carolKey, "1.1.1.1:443", "not-an-address")},
		peer(bobKey, "100.90.0.2/32"), peer(carolKey, "100.90.0.3/32"))

	warmUp(t, r, link, state, prober)
	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if prober.count() != 0 {
		t.Errorf("probed with %d targets when one of them could not be read; dropping the "+
			"unreadable one turns a quorum of two-of-three into two-of-two", prober.count())
	}

	// The same group with every target readable is probed, so the check above is about the
	// bad target rather than about nothing having reached the prober.
	good := stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{probedGroup(bobKey, carolKey, "1.1.1.1:443")},
		peer(bobKey, "100.90.0.2/32"), peer(carolKey, "100.90.0.3/32"))
	handshaking(link)
	if _, err := r.Apply(context.Background(), good); err != nil {
		t.Fatal(err)
	}
	if prober.count() == 0 {
		t.Error("a group whose targets all parse was not probed either, so the check above proves nothing")
	}
}

// A group can be quieter than the daemon's reconcile interval. Without a floor, the probe
// cadence would be a daemon-wide flag, and a burst of unrelated state deltas would turn a
// probe policy into a flood.
func TestTheProbeIntervalIsAFloor(t *testing.T) {
	clk := clock.NewFake()
	link := newFakeLink()
	prober := &fakeProber{}
	r := New(link, membership(), nil, nil, nil).
		WithChooser(routeprobe.New(clk)).
		WithProber(prober)
	r.clock = clk.Now

	group := probedGroup(bobKey, carolKey, "1.1.1.1:443")
	group.LocalFailover.ProbeIntervalMs = 600_000 // ten minutes
	state := stateWithRoutes(1, []*meshpv1.RouteGroupAssignment{group},
		peer(bobKey, "100.90.0.2/32"), peer(carolKey, "100.90.0.3/32"))

	warmUp(t, r, link, state, prober)
	for range 5 {
		handshaking(link)
		if _, err := r.Apply(context.Background(), state); err != nil {
			t.Fatal(err)
		}
	}
	if prober.count() != 1 {
		t.Fatalf("probed %d times in ten minutes with a ten-minute floor, want 1", prober.count())
	}

	clk.Advance(11 * time.Minute)
	handshaking(link)
	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if prober.count() != 2 {
		t.Errorf("probed %d times after the interval elapsed, want 2", prober.count())
	}
}

// An interval of zero means every pass, which is what a group that has not thought about it
// gets — the reconcile interval is already a minute.
func TestNoIntervalMeansEveryPass(t *testing.T) {
	clk := clock.NewFake()
	link := newFakeLink()
	prober := &fakeProber{}
	r := New(link, membership(), nil, nil, nil).
		WithChooser(routeprobe.New(clk)).
		WithProber(prober)
	r.clock = clk.Now

	state := stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{probedGroup(bobKey, carolKey, "1.1.1.1:443")},
		peer(bobKey, "100.90.0.2/32"), peer(carolKey, "100.90.0.3/32"))

	warmUp(t, r, link, state, prober)
	for range 3 {
		handshaking(link)
		if _, err := r.Apply(context.Background(), state); err != nil {
			t.Fatal(err)
		}
	}
	if prober.count() != 3 {
		t.Errorf("probed %d times over three passes with no interval set, want 3", prober.count())
	}
}

// The targets that failed reach the control plane, so an operator can tell one target being
// down from the exit being down — which the boolean cannot say.
func TestFailingTargetsAreReportedOnward(t *testing.T) {
	clk := clock.NewFake()
	link := newFakeLink()
	dead := netip.MustParseAddrPort("9.9.9.9:443")
	prober := &fakeProber{answer: func(t netip.AddrPort) error {
		if t == dead {
			return context.DeadlineExceeded
		}
		return nil
	}}
	chooser := routeprobe.New(clk)
	r := New(link, membership(), nil, nil, nil).WithChooser(chooser).WithProber(prober)

	state := stateWithRoutes(1,
		[]*meshpv1.RouteGroupAssignment{probedGroup(bobKey, carolKey, "1.1.1.1:443", "9.9.9.9:443", "8.8.8.8:443")},
		peer(bobKey, "100.90.0.2/32"), peer(carolKey, "100.90.0.3/32"))

	warmUp(t, r, link, state, prober)
	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	reports := chooser.Pending()
	if len(reports) != 1 {
		t.Fatalf("%d reports, want 1", len(reports))
	}
	if !reports[0].GetReachable() {
		t.Error("two of three targets answered and the path was called broken")
	}
	failed := reports[0].GetFailedProbeTargets()
	if len(failed) != 1 || failed[0] != dead.String() {
		t.Errorf("failed_probe_targets = %v, want just the dead one", failed)
	}
	if reports[0].GetRttMs() == 0 {
		t.Error("the report carries no round trip time, so nothing measured the path")
	}
}
