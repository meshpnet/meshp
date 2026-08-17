package nftables

import (
	"strings"
	"testing"
)

// chains builds the shape nft --json list chains actually returns, taken from a real host
// rather than invented, so a change in that format shows up here.
func chains(entries ...string) []byte {
	return []byte(`{"nftables": [{"metainfo": {"version": "1.0.9", "json_schema_version": 1}}` +
		func() string {
			if len(entries) == 0 {
				return ""
			}
			return "," + strings.Join(entries, ",")
		}() + `]}`)
}

func base(family, table, name, hook, policy string) string {
	return `{"chain": {"family": "` + family + `", "table": "` + table + `", "name": "` + name +
		`", "handle": 1, "type": "filter", "hook": "` + hook + `", "prio": 0, "policy": "` + policy + `"}}`
}

func regular(family, table, name string) string {
	return `{"chain": {"family": "` + family + `", "table": "` + table + `", "name": "` + name + `", "handle": 2}}`
}

// The condition itself: Docker's default, which is on every host it is installed on.
func TestAForeignDropAtTheForwardHookIsFound(t *testing.T) {
	got, err := forwardRefusals(chains(base("ip", "filter", "FORWARD", "forward", "drop")))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("found %v, want one refusal", got)
	}
	if got[0].String() != "ip filter FORWARD" {
		t.Errorf("described as %q, which does not tell an operator where to look", got[0])
	}
}

// A host with nothing in the way reports nothing, or the warning means nothing.
func TestAnAcceptingForwardHookIsNotARefusal(t *testing.T) {
	got, err := forwardRefusals(chains(
		base("ip", "filter", "FORWARD", "forward", "accept"),
		base("ip", "filter", "INPUT", "input", "drop"),
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("found %v on a host that refuses nothing forwarded", got)
	}
}

// A drop at another hook is somebody else's business. Reporting an input policy as a reason
// forwarding will not work would send an operator to the wrong rule.
func TestADropAtAnotherHookIsIgnored(t *testing.T) {
	got, err := forwardRefusals(chains(
		base("ip", "filter", "INPUT", "input", "drop"),
		base("ip", "filter", "OUTPUT", "output", "drop"),
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("found %v from hooks that do not carry forwarded packets", got)
	}
}

// Only base chains are registered at a hook. A regular chain is reached by a jump and cannot
// drop anything on its own, and it has no policy to read.
func TestARegularChainIsNotARefusal(t *testing.T) {
	got, err := forwardRefusals(chains(
		regular("ip", "filter", "DOCKER-USER"),
		regular("ip", "filter", "DOCKER-ISOLATION-STAGE-1"),
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("found %v from chains that are not registered at a hook", got)
	}
}

// meshp does not report itself as its own obstacle. Its forward chain is policy accept
// today, and a device blaming its own table would be a confusing way to learn otherwise.
func TestOurOwnTablesAreNotRefusals(t *testing.T) {
	got, err := forwardRefusals(chains(
		base("inet", ForwardTableName, "forward", "forward", "drop"),
		base("inet", LockTableName, "forward", "forward", "drop"),
		base("inet", MapTableName, "outbound", "forward", "drop"),
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("meshp reported its own tables as refusing its traffic: %v", got)
	}
}

// Everything in the way, not just the first thing, and in a stable order — an operator who
// clears one obstacle needs to know about the second without waiting for another pass.
func TestEveryRefusalIsReportedInAStableOrder(t *testing.T) {
	in := chains(
		base("ip6", "filter", "FORWARD", "forward", "drop"),
		base("ip", "filter", "FORWARD", "forward", "drop"),
		base("inet", "firewalld", "filter_FORWARD", "forward", "drop"),
	)
	first, err := forwardRefusals(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 3 {
		t.Fatalf("found %v, want all three", first)
	}
	for range 5 {
		again, err := forwardRefusals(in)
		if err != nil {
			t.Fatal(err)
		}
		for i := range again {
			if again[i] != first[i] {
				t.Fatalf("the order changed between passes: %v then %v", first, again)
			}
		}
	}
}

// A ruleset with nothing in it at all is the ordinary case on a fresh host.
func TestAnEmptyRulesetRefusesNothing(t *testing.T) {
	got, err := forwardRefusals(chains())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("found %v on an empty ruleset", got)
	}
}

// Unparseable output is an error rather than an empty answer. Silently reporting "nothing in
// the way" because nft printed something unexpected is how a device claims to be healthy for
// a reason nobody can see.
func TestUnreadableOutputIsAnError(t *testing.T) {
	if _, err := forwardRefusals([]byte("this is not json")); err == nil {
		t.Error("unparseable output was read as a clean host")
	}
}
