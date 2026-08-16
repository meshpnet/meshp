package pathprobe

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func target(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func ok(s string, rtt time.Duration) Outcome { return Outcome{Target: target(s), RTT: rtt} }
func bad(s string) Outcome                   { return Outcome{Target: target(s), Err: errors.New("no")} }
func outcomes(o ...Outcome) []Outcome        { return o }

// A single target measures that target's path, not the advertiser's health. A majority of
// diverse targets is what makes the difference between "the exit is down" and "one operator
// is having a bad afternoon" — and getting it wrong moves a whole fleet at once.
func TestAMajorityDecides(t *testing.T) {
	for name, tc := range map[string]struct {
		outcomes []Outcome
		want     bool
	}{
		"all three answered":     {outcomes(ok("1.1.1.1:443", time.Millisecond), ok("8.8.8.8:443", time.Millisecond), ok("9.9.9.9:443", time.Millisecond)), true},
		"one of three is down":   {outcomes(ok("1.1.1.1:443", time.Millisecond), bad("8.8.8.8:443"), ok("9.9.9.9:443", time.Millisecond)), true},
		"two of three are down":  {outcomes(ok("1.1.1.1:443", time.Millisecond), bad("8.8.8.8:443"), bad("9.9.9.9:443")), false},
		"none answered":          {outcomes(bad("1.1.1.1:443"), bad("8.8.8.8:443"), bad("9.9.9.9:443")), false},
		"one of two is down":     {outcomes(ok("1.1.1.1:443", time.Millisecond), bad("8.8.8.8:443")), false},
		"the only target is up":  {outcomes(ok("1.1.1.1:443", time.Millisecond)), true},
		"the only target is out": {outcomes(bad("1.1.1.1:443")), false},
	} {
		if got := Verdict(tc.outcomes, 0); got.Reachable != tc.want {
			t.Errorf("%s: reachable = %v, want %v", name, got.Reachable, tc.want)
		}
	}
}

// An even split fails rather than passes. Two of four is not a majority, and the safe
// direction when half the internet says no is to believe it.
func TestAnEvenSplitDoesNotPass(t *testing.T) {
	got := Verdict(outcomes(
		ok("1.1.1.1:443", time.Millisecond), ok("8.8.8.8:443", time.Millisecond),
		bad("9.9.9.9:443"), bad("64.6.64.6:443")), 0)
	if got.Reachable {
		t.Error("two of four answered and the path was called healthy")
	}
}

func TestAnExplicitQuorumIsHonoured(t *testing.T) {
	three := outcomes(ok("1.1.1.1:443", time.Millisecond), bad("8.8.8.8:443"), bad("9.9.9.9:443"))
	if !Verdict(three, 1).Reachable {
		t.Error("a quorum of one was not met by one answer")
	}
	if Verdict(three, 2).Reachable {
		t.Error("a quorum of two was met by one answer")
	}
}

// A quorum larger than the number of targets can never be met, so it is clamped rather than
// obeyed. Obeying it would fail every advertiser forever, and a device that has run out of
// candidates stays on the last one while reporting it dead — a whole fleet unreachable
// because of a number nobody could see was impossible.
func TestAnImpossibleQuorumIsClamped(t *testing.T) {
	all := outcomes(ok("1.1.1.1:443", time.Millisecond), ok("8.8.8.8:443", time.Millisecond))
	if !Verdict(all, 9).Reachable {
		t.Error("a quorum bigger than the target list failed a path where every target answered")
	}
	if Quorum(9, 2) != 2 {
		t.Errorf("Quorum(9, 2) = %d, want 2", Quorum(9, 2))
	}
}

// No targets is not a verdict of unreachable. A group with nothing to probe falls back to
// what the handshake says, and answering "unreachable" here would fail every advertiser in a
// network whose administrator never configured a target — which is every network today.
func TestNoTargetsIsNotAFailure(t *testing.T) {
	got := Verdict(nil, 0)
	if got.Reachable {
		t.Error("an empty probe reported a healthy path")
	}
	if len(got.Failed) != 0 || got.Answered != 0 || got.RTT != 0 {
		t.Errorf("an empty probe invented a result: %+v", got)
	}
}

// The failing targets are named, in the order they were given, so an operator can tell one
// target being down from the exit being down.
func TestFailingTargetsAreNamed(t *testing.T) {
	got := Verdict(outcomes(
		bad("1.1.1.1:443"), ok("8.8.8.8:443", time.Millisecond), bad("9.9.9.9:443")), 0)
	if len(got.Failed) != 2 || got.Failed[0] != "1.1.1.1:443" || got.Failed[1] != "9.9.9.9:443" {
		t.Errorf("failed = %v", got.Failed)
	}
	if got.Answered != 1 {
		t.Errorf("answered = %d, want 1", got.Answered)
	}
}

// The median of the successful dials, and only the successful ones. A failure has no round
// trip time, so counting it as zero would report a path that is half broken as the fastest
// one this device has ever seen.
func TestTheRTTIsTheMedianOfWhatAnswered(t *testing.T) {
	got := Verdict(outcomes(
		ok("1.1.1.1:443", 10*time.Millisecond),
		ok("8.8.8.8:443", 90*time.Millisecond),
		ok("9.9.9.9:443", 50*time.Millisecond)), 0)
	if got.RTT != 50*time.Millisecond {
		t.Errorf("rtt = %v, want the median 50ms", got.RTT)
	}

	withFailure := Verdict(outcomes(
		bad("1.1.1.1:443"), ok("8.8.8.8:443", 90*time.Millisecond)), 1)
	if withFailure.RTT != 90*time.Millisecond {
		t.Errorf("rtt = %v, want 90ms — the failure has no round trip to average in", withFailure.RTT)
	}

	if Verdict(outcomes(bad("1.1.1.1:443")), 0).RTT != 0 {
		t.Error("a path where nothing answered reported a round trip time")
	}
}

// Literal addresses only. Resolving a name needs DNS, and DNS is one of the things that
// stops working when a gateway fails — so a probe that had to resolve first would blame the
// advertiser for a resolver's outage. A device that fails closed refuses plaintext DNS
// outside the tunnel, so the lookup would depend on the very path being tested.
func TestTargetsMustBeLiteralAddresses(t *testing.T) {
	for _, raw := range []string{
		"one.one.one.one:443",
		"1.1.1.1",
		"1.1.1.1:0",
		"",
		"1.1.1.1:https",
		"[2606:4700:4700::1111]",
	} {
		if _, err := ParseTargets([]string{raw}); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}

	got, err := ParseTargets([]string{"1.1.1.1:443", "[2606:4700:4700::1111]:443"})
	if err != nil {
		t.Fatalf("refused a pair of literal addresses: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("parsed %d targets, want 2", len(got))
	}
}
