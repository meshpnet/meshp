package wglink

// EgressMark is the firewall mark WireGuard puts on its own outer packets when this device
// sends everything through the tunnel, and EgressTable is the routing table holding that
// tunnel's default route.
//
// The same number for both, as wg-quick does: one value to recognise, one to remove, and no
// chance of the two drifting apart. It is high and arbitrary to stay clear of the marks
// other software picks, which conventionally live in the low bits.
//
// Here rather than beside the Linux implementation because they are plain numbers with no
// platform behaviour, and because `meshp doctor` has to be able to print them on any build:
// the person reading that output is at a console on a machine with no network, and the exact
// `ip rule del fwmark ...` they need is the whole value of the command.
const (
	EgressMark  uint32 = 0x6d657368 // "mesh"
	EgressTable uint32 = 0x6d657368
)
