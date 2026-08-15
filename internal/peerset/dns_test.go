package peerset

import (
	"testing"

	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// StateDelta.dns was carried on the wire and dropped here, which is the same mistake that
// killed relays: a field handled everywhere downstream and not in the fold. The package doc
// lists the four places it has to appear, and these are the two that are silent when missed.
func TestResolverConfigurationIsFolded(t *testing.T) {
	s := New()
	s.Apply(&meshpv1.StateDelta{
		FromVersion: 0, ToVersion: 1,
		Dns: &meshpv1.DnsConfig{Nameservers: []string{"100.90.0.1"}, PreventLeaks: true},
	})

	if !s.DNS().GetPreventLeaks() {
		t.Fatal("prevent_leaks did not survive the fold, so the agent would never refuse a leak")
	}

	// Absent in a delta means unchanged, or a routine peer update would switch it off.
	s.Apply(&meshpv1.StateDelta{FromVersion: 1, ToVersion: 2})
	if !s.DNS().GetPreventLeaks() {
		t.Error("a delta that said nothing about DNS switched leak prevention off")
	}
}

// A snapshot is the whole truth, so one carrying no DNS means the network has none. Keeping
// the last one would leave a device refusing queries its network has stopped asking it to.
func TestASnapshotClearsResolverConfiguration(t *testing.T) {
	s := New()
	s.Apply(&meshpv1.StateDelta{
		FromVersion: 0, ToVersion: 1,
		Dns: &meshpv1.DnsConfig{PreventLeaks: true},
	})
	s.Apply(&meshpv1.StateDelta{FromVersion: 0, ToVersion: 2})

	if s.DNS() != nil {
		t.Errorf("a snapshot with no DNS left %+v behind", s.DNS())
	}
}

// Clone has to copy it, or two sets share a pointer and Invariant 22 is gone.
func TestCloneCopiesResolverConfiguration(t *testing.T) {
	s := New()
	s.Apply(&meshpv1.StateDelta{
		FromVersion: 0, ToVersion: 1,
		Dns: &meshpv1.DnsConfig{PreventLeaks: true},
	})

	clone := s.Clone()
	if !clone.DNS().GetPreventLeaks() {
		t.Fatal("the clone lost the resolver configuration")
	}
	clone.DNS().PreventLeaks = false
	if !s.DNS().GetPreventLeaks() {
		t.Error("the clone shares a pointer with the original")
	}
}

// And Equal has to look at it, or a test that folds and compares passes without ever seeing
// the field — which is how the last one of these went unnoticed.
func TestEqualNoticesResolverConfiguration(t *testing.T) {
	a, b := New(), New()
	a.Apply(&meshpv1.StateDelta{
		FromVersion: 0, ToVersion: 1,
		Dns: &meshpv1.DnsConfig{PreventLeaks: true},
	})
	b.Apply(&meshpv1.StateDelta{FromVersion: 0, ToVersion: 1})

	if a.Equal(b) {
		t.Error("two sets differing only in DNS compared equal")
	}
}
