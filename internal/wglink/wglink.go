// Package wglink creates, configures, observes and removes WireGuard interfaces.
//
// It is the only place in meshp that talks to the kernel about interfaces, and it holds
// no opinions about what an interface should contain — that is wgplan's job, decided
// without privileges and tested without a platform. What is here is the part that can
// only be checked against a real interface, kept small enough that checking it against
// one is practical.
package wglink

import (
	"errors"
	"fmt"

	"github.com/meshpnet/meshp/internal/wgplan"
)

// RouteProtocol marks the routes meshp installs as meshp's own.
//
// Linux records a protocol number against every route, and it is the only way to tell
// "we put this here" from "it was already here" without keeping a list on disk and hoping
// the list and the kernel agree. Invariant 20 is that everything the agent installs, the
// agent can remove — which also means the agent removes nothing else. Observing the
// interface's routes without this filter reports the kernel's own local and multicast
// routes as ours, and the reconciler would then withdraw them on every pass.
//
// 61 is inside the range Linux leaves for private use: values above RTPROT_STATIC are not
// assigned by the kernel, and nothing interprets them but the tools that set them.
const RouteProtocol = 61

// Kind is which WireGuard implementation is behind an interface.
type Kind string

const (
	// KindKernel is WireGuard in the kernel.
	KindKernel Kind = "kernel"
	// KindUserspace is a userspace implementation, reached over its UAPI socket.
	KindUserspace Kind = "userspace"
	// KindUnknown is a device that exists but did not say what it is.
	KindUnknown Kind = "unknown"
)

// ErrUnsupported means this build cannot manage interfaces on this platform.
//
// A distinct error rather than a panic or a silent no-op: the daemon runs on platforms
// where the data plane is not implemented yet, and "enrolled, no tunnel, and here is why"
// is a state it should be able to report rather than crash in.
var ErrUnsupported = errors.New("wglink: managing WireGuard interfaces is not implemented on this platform")

// Link manages one host's WireGuard interfaces.
type Link interface {
	// Observe reports what an interface currently holds. A name that does not exist is
	// not an error: it returns Observed{Exists: false}, which is what the planner needs
	// to decide to create it.
	Observe(name string) (wgplan.Observed, error)

	// Apply carries out one operation.
	Apply(name string, op wgplan.Op) error

	// Kind reports which implementation is behind an existing interface.
	Kind(name string) (Kind, error)

	// Close releases the netlink and control sockets.
	Close() error
}

// ApplyPlan carries out every operation in order, stopping at the first failure.
//
// Stopping rather than continuing: the operations are ordered because they depend on each
// other — a route needs its address, a peer needs its device — so continuing past a
// failure applies operations whose preconditions are gone, and turns one clear error into
// several confusing ones. The error names the operation that failed and how far it got,
// because "apply failed" on a twenty-operation plan is not something anyone can act on.
func ApplyPlan(l Link, name string, plan wgplan.Plan) error {
	for i, op := range plan.Ops {
		if err := l.Apply(name, op); err != nil {
			return fmt.Errorf("wglink: %s: operation %d of %d (%s): %w",
				name, i+1, len(plan.Ops), op, err)
		}
	}
	return nil
}
