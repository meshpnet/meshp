package main

import (
	"github.com/meshpnet/meshp/internal/nftables"
	"github.com/meshpnet/meshp/internal/pathprobe"
	"github.com/meshpnet/meshp/internal/relaylink"
	"github.com/meshpnet/meshp/internal/resolved"
	"github.com/meshpnet/meshp/internal/sessionclient"
	"github.com/meshpnet/meshp/internal/tunnel"
	"github.com/meshpnet/meshp/internal/wglink"
)

// proberOrNil hands over a dialer as the interface, or nothing when this host has none.
//
// The canonical version of a conversion this file repeats seven times, and the reason it is
// written out at all rather than assigned directly.
//
// A nil *T put into an interface is not a nil interface. It is a non-nil interface holding a
// nil pointer, so every `x == nil` downstream passes and the first method call panics — on
// the platform with no data plane, no dialer, no packet filter, which is precisely where the
// absence was supposed to *be* the answer. It has bitten this project already.
//
// Each of these takes what a constructor returned rather than calling the constructor
// itself, and that is not a style choice. Every one of these constructors returns something
// on Linux and on macOS, so the case that matters cannot be reached by calling them; passing
// the value in is what lets a test hand over a nil and see what comes back (#165).
func proberOrNil(d *pathprobe.BoundDialer) tunnel.Prober {
	if d == nil {
		return nil
	}
	return d
}

// routerOrNil hands over a router as the interface, or nothing — so a device asked for a
// full tunnel it cannot deliver reports the group unhonoured instead of pretending.
func routerOrNil(r *wglink.Router) tunnel.Egress {
	if r == nil {
		return nil
	}
	return r
}

// filterOrNil hands over a packet filter as the interface, or nothing — so a host that
// cannot enforce says so rather than accepting a policy it will not apply (ADR-0007).
func filterOrNil(f *nftables.Filter) tunnel.Filter {
	if f == nil {
		return nil
	}
	return f
}

// resolverOrNil hands over the host's resolver configurer as the interface, or nothing —
// so names answer to a direct query and `meshp status` says why (ADR-0021).
func resolverOrNil(s *resolved.System) tunnel.SystemResolver {
	if s == nil {
		return nil
	}
	return s
}

// relayOrNil hands over a relay link as the interface, or nothing when this build has no
// relay: relayed peers then get no endpoint, which is what they had before there was one.
func relayOrNil(l *relaylink.Link) tunnel.Relay {
	if l == nil {
		return nil
	}
	return l
}

// relayCredentials hands over the same link as the thing that holds its capability.
func relayCredentials(l *relaylink.Link) sessionclient.RelayCredentials {
	if l == nil {
		return nil
	}
	return l
}

// pathsOrNil hands over the reconciler as a path reporter, or nothing.
//
// The same trap the control plane's presence hook documents, reached from the other side: a
// membership with no reconciler is a device with no data plane, and it would report paths
// for an interface that does not exist.
func pathsOrNil(r *tunnel.Reconciler) sessionclient.PathReports {
	if r == nil {
		return nil
	}
	return r
}
