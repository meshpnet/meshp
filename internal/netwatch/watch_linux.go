//go:build linux

package netwatch

import (
	"context"
	"golang.org/x/sys/unix"
)

// The multicast groups worth listening to.
//
// Routes and links on both families. Addresses are deliberately included: an interface that
// keeps its name and gains a new address is exactly the laptop-moved case, and a watcher
// listening only for link state would sleep through it.
const watchGroups = unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE |
	unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR | unix.RTMGRP_LINK

// Watch reports when this machine's networking changes, or returns nil where it cannot tell.
//
// A netlink socket bound to the route groups. Nothing is parsed — any message means something
// moved, and working out what is the reconciler's job. A watcher that decoded messages would
// be a second, quieter implementation of the thing wgplan already does properly.
func Watch(ctx context.Context) <-chan struct{} {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC,
		unix.NETLINK_ROUTE)
	if err != nil {
		return nil
	}
	addr := &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: watchGroups}
	if err := unix.Bind(fd, addr); err != nil {
		_ = unix.Close(fd)
		return nil
	}

	raw := make(chan struct{}, 1)
	out := make(chan struct{}, 1)

	go func() {
		defer close(raw)
		buf := make([]byte, 8192)
		for {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				return
			}
			if n <= 0 {
				continue
			}
			select {
			case raw <- struct{}{}:
			default:
			}
		}
	}()

	go func() {
		<-ctx.Done()
		_ = unix.Close(fd)
	}()

	go debounce(ctx, raw, out)
	return out
}
