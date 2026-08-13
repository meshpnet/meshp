package nftables

import "errors"

// ErrUnsupported means this host cannot enforce a packet filter.
//
// A condition to report, not a failure to retry: a device that cannot filter is still a
// device, and the honest answer is to say so in its capabilities and let the control plane
// decide whether to place it in a network whose policy requires enforcement (ADR-0007).
var ErrUnsupported = errors.New("nftables: this platform cannot enforce a packet filter")
