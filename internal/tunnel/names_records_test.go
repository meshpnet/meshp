package tunnel

import (
	"log/slog"
	"net/netip"
	"testing"

	"github.com/meshpnet/meshp/internal/dns"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

func record(name, kind, value string) *meshpv1.DnsConfig_Record {
	return &meshpv1.DnsConfig_Record{Name: name, Type: kind, Value: value}
}

func addrsOf(hosts []dns.Host, name string) []string {
	for _, host := range hosts {
		if host.Name != name {
			continue
		}
		out := make([]string, 0, len(host.Addrs))
		for _, a := range host.Addrs {
			out = append(out, a.String())
		}
		return out
	}
	return nil
}

func TestAdminRecordsJoinTheDerivedNames(t *testing.T) {
	hosts := []dns.Host{{Name: "hq-gateway", Addrs: []netip.Addr{netip.MustParseAddr("10.80.0.1")}}}

	got := withAdminRecords(hosts, []*meshpv1.DnsConfig_Record{
		record("git", "A", "10.80.0.30"),
		// One name legitimately has both families. Keeping only the last would make a
		// dual-stack name resolve for one of them at random.
		record("git", "AAAA", "fd7a:115c::30"),
	}, slog.New(slog.DiscardHandler))

	if addrs := addrsOf(got, "hq-gateway"); len(addrs) != 1 {
		t.Errorf("the derived name was lost: %v", addrs)
	}
	if addrs := addrsOf(got, "git"); len(addrs) != 2 {
		t.Errorf("git = %v, want both families", addrs)
	}
}

// An administrator's record wins a collision with a device's name. Both are desired state,
// but one was typed by a person for this network and the other follows from what a machine
// happened to be called. The control plane refuses the collision at creation, so this is a
// device that arrived afterwards.
func TestAnAdminRecordWinsAgainstADeviceName(t *testing.T) {
	hosts := []dns.Host{
		{Name: "git", Addrs: []netip.Addr{netip.MustParseAddr("10.80.0.9")}},
		{Name: "laptop", Addrs: []netip.Addr{netip.MustParseAddr("10.80.0.8")}},
	}

	got := withAdminRecords(hosts, []*meshpv1.DnsConfig_Record{
		record("git", "A", "10.80.0.30"),
	}, slog.New(slog.DiscardHandler))

	if addrs := addrsOf(got, "git"); len(addrs) != 1 || addrs[0] != "10.80.0.30" {
		t.Errorf("git = %v, want the administrator's address alone", addrs)
	}
	if addrs := addrsOf(got, "laptop"); len(addrs) != 1 {
		t.Errorf("an unrelated device lost its name: %v", addrs)
	}
	if len(got) != 2 {
		t.Errorf("%d hosts, want 2: the collision should replace rather than add", len(got))
	}
}

// A record this agent cannot use is dropped, not fatal. It came from a server that has
// already validated it, so an unusable one means the two ends disagree about what a record
// is — worth a log line, not worth a device's tunnel (ADR-0008).
func TestAnUnusableRecordIsDroppedNotFatal(t *testing.T) {
	hosts := []dns.Host{{Name: "laptop", Addrs: []netip.Addr{netip.MustParseAddr("10.80.0.8")}}}

	got := withAdminRecords(hosts, []*meshpv1.DnsConfig_Record{
		record("git", "A", "not-an-address"),
		record("has.a.dot", "A", "10.80.0.30"),
		record("fine", "A", "10.80.0.31"),
	}, slog.New(slog.DiscardHandler))

	if addrsOf(got, "git") != nil || addrsOf(got, "has.a.dot") != nil {
		t.Error("an unusable record was published")
	}
	if addrs := addrsOf(got, "fine"); len(addrs) != 1 {
		t.Errorf("a usable record beside a broken one was lost: %v", addrs)
	}
	if addrsOf(got, "laptop") == nil {
		t.Error("a derived name was lost because a record was broken")
	}
}

// No records is the ordinary case and must not disturb anything.
func TestNoRecordsChangesNothing(t *testing.T) {
	hosts := []dns.Host{{Name: "laptop", Addrs: []netip.Addr{netip.MustParseAddr("10.80.0.8")}}}
	if got := withAdminRecords(hosts, nil, slog.New(slog.DiscardHandler)); len(got) != 1 {
		t.Errorf("%d hosts, want the one that was there", len(got))
	}
}
