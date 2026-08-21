package tunnel

import (
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// Paths reports what this membership's data plane actually looks like.
//
// The gap this closes: an acknowledgement says a device applied version N, and a device can
// apply every version it is sent while passing no traffic at all. Nothing told the control
// plane the difference, so a laptop with a dead tunnel and a live control session read as
// healthy (#117). PathReport has been in the protocol since the first commit with nothing
// sending it and nothing handling it.
//
// Read from the kernel on each call rather than remembered from the last reconcile. The
// numbers are what an operator is looking at while deciding whether something is wrong, and
// a cached handshake age is a number that stops changing exactly when it matters.
//
// Nil when there is nothing to say, which the caller treats as "do not send": a membership
// whose interface has not come up has no paths to describe, and an empty report would be
// indistinguishable from one whose peers are all down.
func (r *Reconciler) Paths() *meshpv1.PathReport {
	name := r.membership.InterfaceName
	if name == "" {
		return nil
	}
	observed, err := r.link.Observe(name)
	if err != nil || !observed.Exists {
		return nil
	}

	r.mu.Lock()
	relayed := r.relayed
	r.mu.Unlock()

	report := &meshpv1.PathReport{
		Paths: make([]*meshpv1.PathReport_PeerPath, 0, len(observed.Peers)),
	}
	for _, peer := range observed.Peers {
		key := string(peer.PublicKey)
		path := &meshpv1.PathReport_PeerPath{
			PeerPublicKey: key,
			// How this peer is reached, which is not the same question as whether it is
			// working. A relayed peer is relayed whether or not it has handshaked
			// recently; freshness travels separately, below, so a reader can tell "reached
			// through a relay" from "not reached at all".
			Kind: meshpv1.PathReport_PeerPath_KIND_DOWN,
		}
		switch {
		case relayed[key]:
			path.Kind = meshpv1.PathReport_PeerPath_KIND_RELAY
		case peer.Endpoint != "":
			path.Kind = meshpv1.PathReport_PeerPath_KIND_DIRECT
		}
		if peer.HasHandshake {
			// Sent as an instant rather than as an age, so it stays true while the message
			// is in flight and while the server holds it. An age computed here and read
			// two minutes later is simply wrong, and wrong in the direction that makes a
			// dead tunnel look recent.
			path.LastHandshakeUnix = r.now().Add(-peer.HandshakeAge).Unix()
		}
		report.Paths = append(report.Paths, path)
	}

	// discovered_mtu is deliberately left unset. The field means a path MTU somebody
	// discovered, and nothing in this project discovers one yet — reporting the interface's
	// configured MTU here would answer a question nobody asked with a number that looks
	// like an answer to the one they did.
	return report
}

// notePaths remembers which peers this state relays, so a report can say how a peer is
// reached rather than guessing from its endpoint.
//
// Guessing would mean treating a loopback endpoint as proof of relaying, which is exactly
// the inference wgplan refuses to make: the address is a consequence of the decision, not
// the decision, and reading it backwards would misreport any future arrangement that
// happens to use one.
func (r *Reconciler) notePaths(keys []string) {
	relayed := make(map[string]bool, len(keys))
	for _, key := range keys {
		relayed[key] = true
	}
	r.mu.Lock()
	r.relayed = relayed
	r.mu.Unlock()
}
