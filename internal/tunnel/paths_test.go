package tunnel

import (
	"testing"
	"time"

	"github.com/meshpnet/meshp/internal/wgplan"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// Nothing to say is said by saying nothing.
//
// An empty report would tell the control plane this device's peers are all down, which is a
// very different claim from "this membership has no interface yet".
func TestNoInterfaceMeansNoReport(t *testing.T) {
	link := newFakeLink()
	r := New(link, membership(), nil, nil, nil)

	if report := r.Paths(); report != nil {
		t.Errorf("an absent interface produced a report: %v", report)
	}

	link.observed.Exists = true
	if report := r.Paths(); report == nil {
		t.Error("an interface that exists produced no report")
	}
}

// How a peer is reached, which is not the same question as whether it is working.
func TestAPathReportSaysHowEachPeerIsReached(t *testing.T) {
	link := newFakeLink()
	link.observed = wgplan.Observed{
		Exists: true,
		Peers: []wgplan.Peer{
			{PublicKey: "relayed-key", Endpoint: "127.0.0.1:51820", HasHandshake: true, HandshakeAge: time.Minute},
			{PublicKey: "direct-key", Endpoint: "203.0.113.7:51820", HasHandshake: true, HandshakeAge: time.Second},
			{PublicKey: "nowhere-key"},
		},
	}
	r := New(link, membership(), nil, nil, nil)
	// What the last applied state said it relays. Read from here rather than inferred from
	// the loopback endpoint above, which is the inference wgplan refuses to make.
	r.notePaths([]string{"relayed-key"})

	report := r.Paths()
	if report == nil {
		t.Fatal("no report")
	}
	got := map[string]meshpv1.PathReport_PeerPath_Kind{}
	for _, p := range report.GetPaths() {
		got[p.GetPeerPublicKey()] = p.GetKind()
	}
	want := map[string]meshpv1.PathReport_PeerPath_Kind{
		"relayed-key": meshpv1.PathReport_PeerPath_KIND_RELAY,
		"direct-key":  meshpv1.PathReport_PeerPath_KIND_DIRECT,
		// No endpoint at all: there is nowhere to send to, which is what DOWN means here.
		"nowhere-key": meshpv1.PathReport_PeerPath_KIND_DOWN,
	}
	for key, kind := range want {
		if got[key] != kind {
			t.Errorf("%s = %v, want %v", key, got[key], kind)
		}
	}
}

// A handshake travels as an instant, not as an age.
//
// An age computed here and read a minute later is wrong in the direction that makes a dead
// tunnel look recent, so the conversion happens once, at the end that knows the clock.
func TestAHandshakeTravelsAsAnInstant(t *testing.T) {
	link := newFakeLink()
	link.observed = wgplan.Observed{
		Exists: true,
		Peers: []wgplan.Peer{
			{PublicKey: "talking", HasHandshake: true, HandshakeAge: 90 * time.Second},
			{PublicKey: "never"},
		},
	}
	r := New(link, membership(), nil, nil, nil)

	before := time.Now()
	report := r.Paths()
	after := time.Now()

	byKey := map[string]*meshpv1.PathReport_PeerPath{}
	for _, p := range report.GetPaths() {
		byKey[p.GetPeerPublicKey()] = p
	}
	if got := byKey["never"].GetLastHandshakeUnix(); got != 0 {
		t.Errorf("a peer that never handshaked reported %d, want 0", got)
	}
	stamp := time.Unix(byKey["talking"].GetLastHandshakeUnix(), 0)
	if stamp.Before(before.Add(-91*time.Second)) || stamp.After(after.Add(-89*time.Second)) {
		t.Errorf("handshake stamp %v is not ~90s before now (%v)", stamp, before)
	}
}

// The field means a path MTU somebody discovered, and nothing discovers one yet. Reporting
// the configured MTU would answer a different question with a number that looks like an
// answer to this one.
func TestNoMTUIsClaimed(t *testing.T) {
	link := newFakeLink()
	link.observed = wgplan.Observed{Exists: true, MTU: 1420}
	r := New(link, membership(), nil, nil, nil)

	if got := r.Paths().GetDiscoveredMtu(); got != 0 {
		t.Errorf("discovered_mtu = %d, want 0: nothing discovers an MTU", got)
	}
}
