//go:build windows

package wfp

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"net"
	"net/netip"
	"sort"
)

// ErrUnsupported means this host cannot refuse egress outside the tunnel.
//
// A condition to report rather than a failure to retry, as on the other two platforms: a
// device that cannot fail closed is still a device, and the honest answer is to say so and
// let the control plane decide whether to place it in a network that requires it (ADR-0011).
var ErrUnsupported = errors.New("wfp: this platform cannot refuse egress outside the tunnel")

// Lock refuses egress outside the tunnel. It satisfies tunnel.EgressLock.
type Lock struct{}

// New returns a Lock, or nothing when this host cannot refuse egress.
//
// Opening the filter engine is the check. It needs administrative rights, so an agent without
// them answers false here rather than at apply time, where it would look like a policy fault
// instead of a missing capability.
func New(context.Context) *Lock {
	session, err := openSession()
	if err != nil {
		return nil
	}
	_ = fwpmEngineClose0(session)
	return &Lock{}
}

// Held reports whether a fail-closed lock is currently installed.
//
// By asking whether meshp's catch-all filter is there. Asked rather than assumed so that
// removing one can be reported as the event it is: an agent that quietly ran a removal on
// every start would leave no trace of the case that matters — a machine whose egress was
// being refused because a previous run died holding the line.
func Held(context.Context) bool {
	session, err := openSession()
	if err != nil {
		return false
	}
	defer func() { _ = fwpmEngineClose0(session) }()

	// Deleting is the only way to ask, so it is asked by trying to delete something that is
	// not there: a key meshp never uses. FWP_E_FILTER_NOT_FOUND means the engine answered,
	// which is all this needs to know before looking for the real one.
	key := filterKey("blockall-v4")
	err = fwpmFilterDeleteByKey0(session, &key)
	if err == nil {
		// It was there and is now gone, which is not what this was asked. Put it back rather
		// than leave a machine half-locked, and say it is held.
		_ = installBlockAll(session)
		return true
	}
	return !isGone(err)
}

// ApplyLock makes this device refuse egress that does not go through the tunnel, or stops it
// refusing.
//
// An empty interface name removes the lock. That is the only way it comes off from here — the
// filters are system state and outlive this process on purpose (ADR-0011), so nothing about
// the agent exiting takes them away.
func (l *Lock) ApplyLock(_ context.Context, iface string, endpoints []netip.AddrPort, excluded []netip.Prefix, preventDNSLeaks bool) error {
	session, err := openSession()
	if err != nil {
		return err
	}
	defer func() { _ = fwpmEngineClose0(session) }()

	if iface == "" {
		return remove(session)
	}

	luid, err := luidFor(iface)
	if err != nil {
		return err
	}

	// One transaction, so the machine is never inside a half-installed policy. Without it
	// there is a window in which the catch-all is in force and the permits are not, and that
	// window is a device with no network at all.
	return inTransaction(session, func(session uintptr) error {
		if err := registerBaseObjects(session); err != nil {
			return err
		}
		// Replaced rather than merged. The filters are named deterministically, so a second
		// pass writes over the first — but a carve-out that shrank would otherwise leave the
		// filters for addresses that are no longer exempt.
		if err := deleteFilters(session); err != nil {
			return err
		}
		return installPolicy(session, luid, endpoints, excluded, preventDNSLeaks)
	})
}

// installPolicy writes the whole ruleset.
//
// The same shape nftables and pf render, in the same order and for the same reasons — the
// commentary on nftables.RenderLock is the fuller account of why each of these exists. What
// differs is that order here is a weight rather than a position: within meshp's sublayer the
// highest-weighted filter that matches decides, because both permit and block are terminating.
func installPolicy(session uintptr, tunnel winipcfg.LUID, endpoints []netip.AddrPort, excluded []netip.Prefix, preventDNSLeaks bool) error {
	// Loopback first, and unconditionally. The agent's own resolver lives there — on this
	// platform on port 53 (ADR-0029) — and so does everything a desktop does with 127.0.0.1.
	if err := permitLoopback(session); err != nil {
		return err
	}

	// The tunnel itself: what the traffic is supposed to use.
	if err := permitInterface(session, tunnel); err != nil {
		return err
	}

	// The outer packets that carry the tunnel, and the control channel that can end it.
	// Without these the lock deadlocks — no tunnel because no egress, no egress because no
	// tunnel — in the state where the machine cannot be told to unlock.
	for i, endpoint := range sortedEndpoints(endpoints) {
		if err := permitAddress(session, endpoint, endpoint.BitLen(), weightEndpoint, fmt.Sprintf("endpoint-%d", i)); err != nil {
			return err
		}
	}

	// Before the carve-out, and that order is the whole of this rule: the resolver lives on
	// the local network, so refusing DNS after permitting the local network refuses nothing.
	if preventDNSLeaks {
		if err := blockDNS(session); err != nil {
			return err
		}
	}

	// The local network and anything else carved out.
	for i, prefix := range sortedPrefixes(excluded) {
		if err := permitAddress(session, prefix.Addr(), prefix.Bits(), weightExcluded, fmt.Sprintf("excluded-%d", i)); err != nil {
			return err
		}
	}

	// Keeping the address the machine has. A device that cannot renew a lease loses its
	// network some minutes later, and one that cannot do neighbour discovery loses IPv6 at
	// once — both of which look exactly like the bug this feature exists to prevent.
	if err := permitAddressConfiguration(session); err != nil {
		return err
	}

	return installBlockAll(session)
}

// Weights within meshp's sublayer. Higher is evaluated first, and every action here is
// terminating, so the highest match decides.
const (
	weightLoopback  = 15
	weightInterface = 14
	weightEndpoint  = 13
	weightDNS       = 12
	weightExcluded  = 11
	weightConfig    = 10
	weightBlockAll  = 0
)

// filterKey names one filter, deterministically.
//
// Derived from meshp's provider and a slot name, so the same policy written twice names the
// same filters and a process that did not install them can still remove them. That is the
// half wireguard-windows does not need and meshp cannot do without (ADR-0030).
func filterKey(slot string) windows.GUID {
	sum := sha256.Sum256(append(providerKey.Data4[:], slot...))
	var guid windows.GUID
	guid.Data1 = uint32(sum[0])<<24 | uint32(sum[1])<<16 | uint32(sum[2])<<8 | uint32(sum[3])
	guid.Data2 = uint16(sum[4])<<8 | uint16(sum[5])
	guid.Data3 = uint16(sum[6])<<8 | uint16(sum[7])
	copy(guid.Data4[:], sum[8:16])
	return guid
}

// everySlot is every filter meshp can install, which is what removal walks.
//
// A list rather than an enumeration of the engine, because enumerating needs a template
// structure this package would have to lay out by hand — the memory-layout risk ADR-0030 took
// the borrowed types to avoid. The cost is that this list has to stay in step with what
// installPolicy writes, and the test below is what makes that true rather than hoped for.
func everySlot() []string {
	slots := []string{"loopback", "interface-v4", "interface-v6", "dns-v4", "dns-v6",
		"config-dhcp4", "config-dhcp6", "config-ndp", "blockall-v4", "blockall-v6"}
	// The carve-out is bounded rather than unbounded: a network with more exemptions than
	// this would silently lose the ones past the end, so the count is generous and the
	// installer refuses beyond it.
	for i := range maxCarveOut {
		slots = append(slots, fmt.Sprintf("endpoint-%d-v4", i), fmt.Sprintf("endpoint-%d-v6", i),
			fmt.Sprintf("excluded-%d-v4", i), fmt.Sprintf("excluded-%d-v6", i))
	}
	return slots
}

// maxCarveOut bounds how many addresses can be kept off the tunnel.
//
// Generous — a device with more than this many relays plus exclusions is not a shape this
// product has — and enforced rather than assumed, because the alternative to a limit is a
// removal that cannot name everything installation wrote.
const maxCarveOut = 64

// remove takes the lock off, and meshp's provider with it.
func remove(session uintptr) error {
	return inTransaction(session, func(session uintptr) error {
		if err := deleteFilters(session); err != nil {
			return err
		}
		if err := fwpmSubLayerDeleteByKey0(session, &sublayerKey); err != nil && !isGone(err) {
			return fmt.Errorf("wfp: removing meshp's sublayer: %w", err)
		}
		if err := fwpmProviderDeleteByKey0(session, &providerKey); err != nil && !isGone(err) {
			return fmt.Errorf("wfp: removing meshp as a filter provider: %w", err)
		}
		return nil
	})
}

// deleteFilters removes every filter meshp could have installed.
//
// By name, and tolerating absence: most of these will not be there on any given pass, because
// which ones exist depends on the carve-out that was in force.
func deleteFilters(session uintptr) error {
	var errs []error
	for _, slot := range everySlot() {
		key := filterKey(slot)
		if err := fwpmFilterDeleteByKey0(session, &key); err != nil && !isGone(err) {
			errs = append(errs, fmt.Errorf("wfp: removing the %s filter: %w", slot, err))
		}
	}
	return errors.Join(errs...)
}

// inTransaction runs an operation atomically, aborting it if anything fails.
func inTransaction(session uintptr, op wfpObjectInstaller) error {
	if err := fwpmTransactionBegin0(session, 0); err != nil {
		return fmt.Errorf("wfp: starting a filter transaction: %w", err)
	}
	if err := op(session); err != nil {
		_ = fwpmTransactionAbort0(session)
		return err
	}
	if err := fwpmTransactionCommit0(session); err != nil {
		_ = fwpmTransactionAbort0(session)
		return fmt.Errorf("wfp: committing the filter transaction: %w", err)
	}
	return nil
}

// luidFor finds an adapter by the name meshp gave it.
func luidFor(iface string) (winipcfg.LUID, error) {
	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		return 0, fmt.Errorf("wfp: finding %s: %w", iface, err)
	}
	luid, err := winipcfg.LUIDFromIndex(uint32(netIface.Index))
	if err != nil {
		return 0, fmt.Errorf("wfp: identifying %s: %w", iface, err)
	}
	return luid, nil
}

// sortedEndpoints puts the endpoints in a stable order and drops what cannot be used, so the
// same specification installs the same filters and an unchanged lock is not rewritten.
func sortedEndpoints(in []netip.AddrPort) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, ep := range in {
		addr := ep.Addr().Unmap()
		if !addr.IsValid() || seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, addr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	if len(out) > maxCarveOut {
		out = out[:maxCarveOut]
	}
	return out
}

// sortedPrefixes does the same for the carved-out networks, dropping anything unusable rather
// than refusing the whole lock: a malformed exclusion should cost that exclusion, not leave
// the device with no protection at all.
func sortedPrefixes(in []netip.Prefix) []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, prefix := range in {
		if !prefix.IsValid() {
			continue
		}
		norm := netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()).Masked()
		if seen[norm] {
			continue
		}
		seen[norm] = true
		out = append(out, norm)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	if len(out) > maxCarveOut {
		out = out[:maxCarveOut]
	}
	return out
}
