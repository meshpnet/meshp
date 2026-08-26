package main

import (
	"testing"

	"github.com/meshpnet/meshp/internal/nftables"
	"github.com/meshpnet/meshp/internal/pathprobe"
	"github.com/meshpnet/meshp/internal/relaylink"
	"github.com/meshpnet/meshp/internal/resolved"
	"github.com/meshpnet/meshp/internal/tunnel"
	"github.com/meshpnet/meshp/internal/wglink"
)

// The trap these functions exist for, which this package could not reach until they took an
// argument.
//
// A nil *T put into an interface is a non-nil interface holding a nil pointer. Every
// `x == nil` downstream then passes and the first method call panics — on the platform with
// no data plane, no dialer, no packet filter, which is exactly where the absence was
// supposed to be the answer. Four separate comments in this package warned about it and
// nothing checked.
//
// Each case names what actually goes wrong, because "returns nil" is not why any of this is
// written the way it is.
func TestAnAbsentImplementationBecomesANilInterface(t *testing.T) {
	if got := proberOrNil(nil); got != nil {
		t.Error("a host with no bound dialer got a prober; the first path probe would panic " +
			"instead of the reconciler falling back to the handshake")
	}
	if got := routerOrNil(nil); got != nil {
		t.Error("a host that cannot claim a default route got an Egress; it would report a " +
			"full tunnel honoured and send nothing through it")
	}
	if got := filterOrNil(nil); got != nil {
		t.Error("a host that cannot filter got a Filter; it would accept a network's policy " +
			"and fail on every one (ADR-0007)")
	}
	if got := resolverOrNil(nil); got != nil {
		t.Error("a host whose resolver meshp cannot configure got a SystemResolver; every " +
			"reconcile would panic rather than names answering directly")
	}
	if got := relayOrNil(nil); got != nil {
		t.Error("a build with no relay got a Relay; configuring a relayed peer would panic")
	}
	if got := relayCredentials(nil); got != nil {
		t.Error("a build with no relay got RelayCredentials; the session would panic asking " +
			"for a capability that cannot exist")
	}
	if got := pathsOrNil(nil); got != nil {
		t.Error("a membership with no reconciler got a PathReports; it would report paths " +
			"for an interface that does not exist")
	}
}

// And the other half, or the check above would be satisfied by functions that return nil
// always — which would take the data plane off every device on every platform.
func TestSomethingPresentIsHandedOver(t *testing.T) {
	if got := proberOrNil(&pathprobe.BoundDialer{}); got == nil {
		t.Error("a host with a bound dialer was reported as having none")
	}
	if got := routerOrNil(&wglink.Router{}); got == nil {
		t.Error("a host that can claim a default route was reported as unable to")
	}
	if got := filterOrNil(&nftables.Filter{}); got == nil {
		t.Error("a host that can enforce a policy was reported as unable to")
	}
	if got := resolverOrNil(&resolved.System{}); got == nil {
		t.Error("a host whose resolver meshp can configure was reported as unable to")
	}
	if got := relayOrNil(&relaylink.Link{}); got == nil {
		t.Error("a live relay link was dropped, leaving every relayed peer unreachable")
	}
	if got := relayCredentials(&relaylink.Link{}); got == nil {
		t.Error("a live relay link was not offered as the holder of its capability")
	}
	if got := pathsOrNil(&tunnel.Reconciler{}); got == nil {
		t.Error("a live reconciler was not offered as a path reporter, so the control plane " +
			"would never learn which paths work")
	}
}
