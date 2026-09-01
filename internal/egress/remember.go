package egress

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Remembering answers a name from what it answered last time, when it cannot answer it now.
//
// It exists because the carve-out needs the control plane's address and refuses to be built
// without it — a device that locked itself away from its control plane would be off the
// network for a reason nobody watching could see. That refusal is right, and combined with a
// claimed full tunnel it made a cycle a device could not leave (#204):
//
//	a claim is in place, so DNS goes through the tunnel
//	something disturbs it — a route group withdrawn, a change of network
//	the next pass needs the control plane's address, and cannot resolve it
//	the claim is abandoned; the device still wants one, so nothing is released
//	round again, for as long as the device is on
//
// Observed on a laptop: no network at all until somebody typed `meshp down`.
//
// The address remembered here is the one a working claim was already built on, so using it
// again is not a guess. It is only reached when DNS has stopped answering, which is a state
// this cache did not cause and cannot make worse: without it there is no carve-out at all.
//
// Kept under /var/run deliberately. A cache that outlived a reboot would answer with a stale
// address on a machine whose DNS is working perfectly and whose control plane has moved —
// and a reboot is the one moment no claim is in place, so the name resolves normally.
func Remembering(next Resolver, path string) Resolver {
	if next == nil {
		next = SystemResolver
	}
	var mu sync.Mutex

	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		addrs, err := next(ctx, host)
		if err == nil && len(addrs) > 0 {
			mu.Lock()
			remember(path, host, addrs)
			mu.Unlock()
			return addrs, nil
		}

		mu.Lock()
		remembered := recall(path, host)
		mu.Unlock()
		if len(remembered) > 0 {
			return remembered, nil
		}
		if err == nil {
			// Answered, with nothing. Reported as the failure it is rather than passed on
			// as an empty success, which the caller would read as "this name has no
			// addresses" and refuse the carve-out over.
			return nil, fmt.Errorf("egress: %q resolved to nothing and nothing was remembered", host)
		}
		return nil, err
	}
}

// remember writes down what a name resolved to. Best effort: a device that cannot write here
// still has working DNS today, and the cost is only that it will not have this tomorrow.
func remember(path, host string, addrs []netip.Addr) {
	known := recallAll(path)
	known[host] = addrs

	var b strings.Builder
	for name, list := range known {
		if strings.ContainsAny(name, " \t\n") {
			continue
		}
		b.WriteString(name)
		for _, addr := range list {
			b.WriteString(" ")
			b.WriteString(addr.String())
		}
		b.WriteString("\n")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	_ = os.WriteFile(path, []byte(b.String()), 0o600)
}

func recall(path, host string) []netip.Addr { return recallAll(path)[host] }

// recallAll reads the whole cache. A line that will not parse is skipped rather than failing
// the read: one bad entry should not cost a device the name it does remember.
func recallAll(path string) map[string][]netip.Addr {
	out := map[string][]netip.Addr{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		var addrs []netip.Addr
		for _, field := range fields[1:] {
			if addr, err := netip.ParseAddr(field); err == nil {
				addrs = append(addrs, addr)
			}
		}
		if len(addrs) > 0 {
			out[fields[0]] = addrs
		}
	}
	return out
}
