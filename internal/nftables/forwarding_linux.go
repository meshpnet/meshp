//go:build linux

package nftables

import (
	"fmt"
	"os"
	"strings"
)

// forwardingSysctls are what the kernel needs before it will pass a packet between
// interfaces at all. Without them the ruleset above is correct and nothing crosses.
var forwardingSysctls = []string{
	"/proc/sys/net/ipv4/ip_forward",
	"/proc/sys/net/ipv6/conf/all/forwarding",
}

// EnableForwarding turns on IP forwarding, and never turns it off.
//
// Asymmetric on purpose. A host can be forwarding because of Docker, another VPN, or
// because somebody configured it that way years ago, and none of that is visible from here.
// Turning it off when a device stops carrying a prefix would silently break whatever else
// depended on it — a much worse failure than leaving a setting on, which costs nothing on a
// host with no routes to use it.
//
// Already-on is not reported as a change, so an operator reading the log sees this only
// when meshp actually altered the host.
func EnableForwarding() (changed []string, err error) {
	for _, path := range forwardingSysctls {
		current, readErr := os.ReadFile(path)
		if readErr != nil {
			// A kernel without IPv6, or a container with a read-only proc. Reported per
			// setting rather than fatally: forwarding IPv4 only is worth having.
			continue
		}
		if strings.TrimSpace(string(current)) == "1" {
			continue
		}
		if writeErr := os.WriteFile(path, []byte("1\n"), 0o644); writeErr != nil {
			err = fmt.Errorf("nftables: enabling forwarding via %s: %w", path, writeErr)
			continue
		}
		changed = append(changed, path)
	}
	return changed, err
}
