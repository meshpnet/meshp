// Package pf refuses egress that does not go through the tunnel, on macOS.
//
// The macOS half of ADR-0011, and the sibling of internal/nftables — same job, different
// mechanism, and the difference is not only syntax. nftables gives meshp a table it owns
// outright, which can be created and destroyed without reference to anything else on the
// machine. pf has one main ruleset shared by everything, and rules live in *anchors* that
// are evaluated only if that ruleset points at them.
//
// ADR-0026 settles where meshp's rules go, and every constant here is a finding from that
// record rather than a preference: the anchor is nested under Apple's because the shipped
// `/etc/pf.conf` references exactly one anchor point and a top-level anchor of meshp's own
// is loaded and never evaluated. That was established on a real macOS, not reasoned about,
// and the reasoning would have got it wrong.
//
// Two things follow that have no analogue on Linux.
//
// meshp does not own the switch. pf ships disabled and is turned on with a reference count
// (`pfctl -E`), so several programs can each need it on and none can turn it off underneath
// the others. This package takes a reference and gives it back, and holds the token on disk
// so a killed daemon's reference can be released by the next one.
//
// The anchor point is verified before the lock is trusted. A future macOS that renamed it,
// or dropped the wildcard, would leave meshp's rules loaded and never evaluated — a device
// still reporting that it fails closed while everything leaks. The check turns that into
// "this host cannot enforce", which is a state the rest of the system already knows how to
// carry.
package pf

import "errors"

// AnchorName is where meshp's rules live.
//
// Nested under `com.apple` because that is the only anchor point `/etc/pf.conf` references
// (ADR-0026). Exported because `meshp doctor` prints the command that flushes it, and the
// person reading that is at a console on a machine with no network.
const AnchorName = "com.apple/meshp"

// anchorPoint is what the main ruleset must contain for AnchorName to be evaluated.
//
// The wildcard is the whole of it. `anchor "com.apple"` without one loads Apple's own rules
// and evaluates no nested anchor, so meshp's would sit there being ignored.
const anchorPoint = "com.apple/*"

// ErrUnsupported means this host cannot refuse egress outside the tunnel.
//
// A condition to report rather than a failure to retry, exactly as nftables.ErrUnsupported
// is: a device that cannot fail closed is still a device, and the honest answer is to say so
// and let the control plane decide whether to place it in a network that requires it
// (ADR-0011).
var ErrUnsupported = errors.New("pf: this platform cannot refuse egress outside the tunnel")
