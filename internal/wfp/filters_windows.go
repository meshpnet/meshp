//go:build windows

package wfp

import (
	"fmt"
	"net/netip"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// One filter, at both address families where that makes sense.
//
// Everything here goes at ALE_AUTH_CONNECT, which is where Windows decides whether a
// connection may be made — the outbound equivalent of the hook nftables and pf use. Both
// families get their own filter because the layers are separate; a policy installed at one
// says nothing about the other, and a device that refused IPv4 and permitted IPv6 would leak
// exactly the traffic the lock exists to stop.

// addFilter installs one filter and gives it a name meshp can find again.
func addFilter(session uintptr, slot string, layer windows.GUID, action wtFwpActionType,
	weight uint8, conditions []wtFwpmFilterCondition0, description string) error {

	displayData, err := createWtFwpmDisplayData0("meshp", description)
	if err != nil {
		return wrapErr(err)
	}

	filter := wtFwpmFilter0{
		filterKey:           filterKey(slot),
		displayData:         *displayData,
		providerKey:         &providerKey,
		layerKey:            layer,
		subLayerKey:         sublayerKey,
		weight:              filterWeight(weight),
		numFilterConditions: uint32(len(conditions)),
		action:              wtFwpmAction0{_type: action},
	}
	if len(conditions) > 0 {
		filter.filterCondition = &conditions[0]
	}

	var id uint64
	err = fwpmFilterAdd0(session, &filter, 0, &id)
	// The conditions are pointed at by the structure the kernel just read. Held until after
	// the call so nothing moves underneath it.
	runtime.KeepAlive(conditions)
	runtime.KeepAlive(displayData)
	if err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("wfp: installing the %s filter: %w", slot, err)
	}
	return nil
}

// permitLoopback lets the machine talk to itself.
//
// Unconditional and first. The agent's own resolver is on loopback — on this platform on port
// 53 (ADR-0029) — and so is everything a desktop does with 127.0.0.1. A lock that broke them
// would break the machine rather than its egress.
func permitLoopback(session uintptr) error {
	condition := []wtFwpmFilterCondition0{{
		fieldKey:  cFWPM_CONDITION_FLAGS,
		matchType: cFWP_MATCH_FLAGS_ALL_SET,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_UINT32,
			value: uintptr(cFWP_CONDITION_FLAG_IS_LOOPBACK),
		},
	}}
	for _, layer := range bothLayers() {
		if err := addFilter(session, "loopback", layer.key, cFWP_ACTION_PERMIT, weightLoopback,
			condition, "permit loopback"); err != nil {
			return err
		}
	}
	return nil
}

// permitInterface lets everything out through the tunnel, which is the point of claiming a
// default route in the first place.
func permitInterface(session uintptr, luid winipcfg.LUID) error {
	value := uint64(luid)
	for _, layer := range bothLayers() {
		condition := []wtFwpmFilterCondition0{{
			fieldKey:  cFWPM_CONDITION_IP_LOCAL_INTERFACE,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT64,
				value: uintptr(unsafe.Pointer(&value)),
			},
		}}
		if err := addFilter(session, "interface-"+layer.suffix, layer.key, cFWP_ACTION_PERMIT,
			weightInterface, condition, "permit the tunnel"); err != nil {
			return err
		}
	}
	runtime.KeepAlive(value)
	return nil
}

// permitAddress keeps one address or network reachable directly.
//
// Used for both halves of the carve-out: the endpoints that make the tunnel possible, and the
// networks an administrator said to leave alone. They differ only in weight, so that a DNS
// refusal can sit between them.
func permitAddress(session uintptr, addr netip.Addr, bits int, weight uint8, slot string) error {
	layer, ok := layerFor(addr)
	if !ok {
		return nil
	}

	if addr.Is4() {
		value := wtFwpV4AddrAndMask{
			addr: beUint32(addr.As4()),
			mask: ^uint32(0) << (32 - bits),
		}
		condition := []wtFwpmFilterCondition0{{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_V4_ADDR_MASK,
				value: uintptr(unsafe.Pointer(&value)),
			},
		}}
		err := addFilter(session, slot+"-v4", layer, cFWP_ACTION_PERMIT, weight, condition,
			"keep off the tunnel")
		runtime.KeepAlive(value)
		return err
	}

	value := wtFwpV6AddrAndMask{addr: addr.As16(), prefixLength: uint8(bits)}
	condition := []wtFwpmFilterCondition0{{
		fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_V6_ADDR_MASK,
			value: uintptr(unsafe.Pointer(&value)),
		},
	}}
	err := addFilter(session, slot+"-v6", layer, cFWP_ACTION_PERMIT, weight, condition,
		"keep off the tunnel")
	runtime.KeepAlive(value)
	return err
}

// blockDNS refuses plaintext DNS that is not going through the tunnel.
//
// Above the carve-out and below the tunnel, which is the whole of it: the resolver lives on
// the local network and the carve-out permits the local network, so a refusal placed after it
// would refuse nothing. Plaintext only — DNS over TLS on 853 does not disclose the query to
// the network it crosses, and DNS over HTTPS is indistinguishable from any other HTTPS.
func blockDNS(session uintptr) error {
	for _, layer := range bothLayers() {
		port := uint16(53)
		conditions := []wtFwpmFilterCondition0{{
			fieldKey:       cFWPM_CONDITION_IP_REMOTE_PORT,
			matchType:      cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{_type: cFWP_UINT16, value: uintptr(port)},
		}}
		if err := addFilter(session, "dns-"+layer.suffix, layer.key, cFWP_ACTION_BLOCK,
			weightDNS, conditions, "refuse plaintext DNS off the tunnel"); err != nil {
			return err
		}
	}
	return nil
}

// permitAddressConfiguration keeps the address the machine has.
//
// A device that cannot renew a lease loses its network some minutes later, and one that
// cannot do neighbour discovery loses IPv6 immediately. Neither carries any of the user's
// traffic, and both look exactly like the bug this feature exists to prevent.
func permitAddressConfiguration(session uintptr) error {
	udp := uint8(cIPPROTO_UDP)
	v4 := []wtFwpmFilterCondition0{{
		fieldKey:       cFWPM_CONDITION_IP_PROTOCOL,
		matchType:      cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{_type: cFWP_UINT8, value: uintptr(udp)},
	}, {
		fieldKey:       cFWPM_CONDITION_IP_REMOTE_PORT,
		matchType:      cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{_type: cFWP_UINT16, value: uintptr(uint16(67))},
	}}
	if err := addFilter(session, "config-dhcp4", cFWPM_LAYER_ALE_AUTH_CONNECT_V4,
		cFWP_ACTION_PERMIT, weightConfig, v4, "permit DHCP"); err != nil {
		return err
	}

	v6 := []wtFwpmFilterCondition0{{
		fieldKey:       cFWPM_CONDITION_IP_PROTOCOL,
		matchType:      cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{_type: cFWP_UINT8, value: uintptr(udp)},
	}, {
		fieldKey:       cFWPM_CONDITION_IP_REMOTE_PORT,
		matchType:      cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{_type: cFWP_UINT16, value: uintptr(uint16(547))},
	}}
	if err := addFilter(session, "config-dhcp6", cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
		cFWP_ACTION_PERMIT, weightConfig, v6, "permit DHCPv6"); err != nil {
		return err
	}

	icmp6 := uint8(cIPPROTO_ICMPV6)
	ndp := []wtFwpmFilterCondition0{{
		fieldKey:       cFWPM_CONDITION_IP_PROTOCOL,
		matchType:      cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{_type: cFWP_UINT8, value: uintptr(icmp6)},
	}}
	return addFilter(session, "config-ndp", cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
		cFWP_ACTION_PERMIT, weightConfig, ndp, "permit neighbour discovery")
}

// installBlockAll refuses everything the filters above did not permit.
//
// Weight zero, so every permit outranks it. This is the filter whose absence is the whole
// failure: a lock with a carve-out and no catch-all permits exactly what it names and
// everything else besides.
func installBlockAll(session uintptr) error {
	for _, layer := range bothLayers() {
		if err := addFilter(session, "blockall-"+layer.suffix, layer.key, cFWP_ACTION_BLOCK,
			weightBlockAll, nil, "refuse everything else"); err != nil {
			return err
		}
	}
	return nil
}

// layer names one address family's connect layer.
type layer struct {
	key    windows.GUID
	suffix string
}

func bothLayers() []layer {
	return []layer{
		{cFWPM_LAYER_ALE_AUTH_CONNECT_V4, "v4"},
		{cFWPM_LAYER_ALE_AUTH_CONNECT_V6, "v6"},
	}
}

func layerFor(addr netip.Addr) (windows.GUID, bool) {
	if addr.Is4() {
		return cFWPM_LAYER_ALE_AUTH_CONNECT_V4, true
	}
	if addr.Is6() {
		return cFWPM_LAYER_ALE_AUTH_CONNECT_V6, true
	}
	return windows.GUID{}, false
}

// beUint32 is an IPv4 address as the filtering platform wants it: host byte order, most
// significant octet first.
func beUint32(a [4]byte) uint32 {
	return uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
}
