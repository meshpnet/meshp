// Package netwatch reports when this machine's networking changes underneath meshp.
//
// It exists because until now nothing did. The agent corrects an interface that has drifted
// on a timer — a minute by default — and that timer was the only thing that noticed a laptop
// had moved from wifi to a phone. A minute of no network every time somebody changes rooms is
// not a tunnel anybody wants to carry (#172).
//
// # Why this is worse than a slow reconcile
//
// On Linux the tunnel's own packets are exempted by a firewall mark, so nothing is pinned to a
// gateway and a change of network costs a handshake. macOS and Windows have no marks, so the
// routes keeping the relay and the control plane off the tunnel are pinned to whatever gateway
// was current when the claim was made (ADR-0026, ADR-0030). On a new network those point at a
// gateway that is not there — and if the device is failing closed, nothing else gets out
// either. The minute is not a slow tunnel; it is a minute of no network at all.
//
// # What this is not
//
// Not a replacement for the timer. A notification that is missed, coalesced away, or never
// sent because the platform did not consider something a change still has to be corrected
// eventually, and the periodic pass is what makes that true. This makes recovery prompt; the
// ticker makes it certain.
package netwatch

import (
	"context"
	"time"
)

// settle is how long the watcher waits for quiet before reporting a change.
//
// A machine joining a network produces a burst — an address, a route, a gateway, a DNS server,
// each its own notification — and reconciling on every one of them would mean several passes
// where one will do, at the moment the machine is busiest. Waiting for the burst to stop also
// means reconciling against the network's settled state rather than halfway through it, which
// is the difference between correcting the routes once and correcting them three times.
const settle = 500 * time.Millisecond

// debounce turns a stream of raw notifications into one signal per settled change.
//
// Non-blocking on the way out: the reconciler may be busy with the last change, and a watcher
// that blocked waiting to hand over the next one would stop reading from the kernel — which
// on some platforms means a full socket buffer and lost notifications. A change that arrives
// while one is already pending is the same answer anyway.
func debounce(ctx context.Context, raw <-chan struct{}, out chan<- struct{}) {
	timer := time.NewTimer(settle)
	if !timer.Stop() {
		<-timer.C
	}
	pending := false

	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-raw:
			if !ok {
				return
			}
			if !pending {
				pending = true
			} else if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(settle)
		case <-timer.C:
			pending = false
			select {
			case out <- struct{}{}:
			default:
			}
		}
	}
}
