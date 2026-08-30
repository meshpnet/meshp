//go:build windows

package netwatch

import (
	"context"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Watch reports when this machine's networking changes, or returns nil where it cannot tell.
//
// Callbacks rather than a socket, which is what this platform offers: the IP Helper API calls
// back on a thread of its own when a route, an interface or an address changes. All three are
// registered for the reason the other platforms watch all three — an adapter that keeps its
// name and gains a new address is the laptop-moved case, and watching only routes would sleep
// through it.
//
// Nothing the callback is handed is read. Any notification means something moved, and what
// moved is the reconciler's question.
func Watch(ctx context.Context) <-chan struct{} {
	raw := make(chan struct{}, 1)
	out := make(chan struct{}, 1)

	nudge := func() {
		select {
		case raw <- struct{}{}:
		default:
		}
	}

	routes, err := winipcfg.RegisterRouteChangeCallback(
		func(winipcfg.MibNotificationType, *winipcfg.MibIPforwardRow2) { nudge() })
	if err != nil {
		return nil
	}
	interfaces, err := winipcfg.RegisterInterfaceChangeCallback(
		func(winipcfg.MibNotificationType, *winipcfg.MibIPInterfaceRow) { nudge() })
	if err != nil {
		_ = routes.Unregister()
		return nil
	}
	addresses, err := winipcfg.RegisterUnicastAddressChangeCallback(
		func(winipcfg.MibNotificationType, *winipcfg.MibUnicastIPAddressRow) { nudge() })
	if err != nil {
		_ = interfaces.Unregister()
		_ = routes.Unregister()
		return nil
	}

	go func() {
		<-ctx.Done()
		// Unregistered in the order they were taken, so a callback cannot fire against a
		// channel whose reader has gone.
		_ = addresses.Unregister()
		_ = interfaces.Unregister()
		_ = routes.Unregister()
		close(raw)
	}()

	go debounce(ctx, raw, out)
	return out
}
