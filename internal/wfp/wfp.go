//go:build windows

// Package wfp refuses egress that does not go through the tunnel, on Windows.
//
// The Windows half of ADR-0011, and the sibling of internal/nftables and internal/pf. Same
// job, third mechanism, and this one differs from the other two in a way that matters: it is
// not a program meshp runs. nftables and pf are `nft` and `pfctl`, whose interfaces are
// stable and whose failures are text. This is structures passed to a kernel API.
//
// # Why not the firewall everybody has heard of
//
// Windows Firewall resolves conflicts by precedence and an explicit block beats an explicit
// allow, so the shape the other platforms use — refuse everything, then permit the tunnel,
// the relay, the control plane and the local network — inverts, and the blanket block wins
// over every permit. The way round it is to set the profile's default outbound action to
// Block, which is a machine-wide setting whose undo means putting back somebody else's value
// (ADR-0030).
//
// The filtering platform underneath it has sublayers with weights, so a permit genuinely
// beats a block, which is how the policy is expressible at all here.
//
// # Why not the implementation that exists
//
// golang.zx2c4.com/wireguard/windows/tunnel/firewall does this and cannot be used. It opens a
// dynamic session, so every filter it adds is deleted when the process exits — the exact
// inverse of what ADR-0011 requires, where the lock survives the daemon because agent crash
// and agent kill are two of the cases the feature exists to cover. Its provider GUID is
// generated per session for the same reason, so a restarted daemon could not find what its
// predecessor installed.
//
// Its type and syscall definitions are borrowed, under their own licence and with their
// copyright retained. Its policy is not, and neither is its lifetime.
package wfp

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// wfpObjectInstaller is what runTransaction takes.
//
// Declared here rather than in the borrowed files because it belongs to the half that is
// meshp's: blocker.go is the file it came from and blocker.go is the file not taken.
type wfpObjectInstaller func(uintptr) error

// providerKey and sublayerKey are meshp's namespace in the filtering platform.
//
// Fixed, which is the whole difference from the implementation this borrows from. Every object
// meshp adds hangs beneath these two, so a daemon that has just started can find everything its
// predecessor installed and take it off — Invariant 20, on a platform with no equivalent of
// Linux's firewall mark. A generated GUID would make the lock unremovable by anything but the
// process that made it, which is the process that is no longer running.
//
// Never change these. A release that did would orphan every lock the last one installed, on
// every machine that had one, with no way to find them again short of enumerating the whole
// filter engine.
var (
	providerKey = windows.GUID{
		Data1: 0x8f1d3b2a, Data2: 0x5c74, Data3: 0x4e19,
		Data4: [8]byte{0x9a, 0x2b, 0x6d, 0x65, 0x73, 0x68, 0x70, 0x01},
	}
	sublayerKey = windows.GUID{
		Data1: 0x8f1d3b2a, Data2: 0x5c74, Data3: 0x4e19,
		Data4: [8]byte{0x9a, 0x2b, 0x6d, 0x65, 0x73, 0x68, 0x70, 0x02},
	}
)

// session opens the filtering platform for the calls below.
//
// Not dynamic, and that is the decision. A dynamic session deletes everything it added when
// the handle closes, which is what the implementation this borrows from wants and the inverse
// of what ADR-0011 wants: a lock that vanished with the daemon would fail open at exactly the
// moment it is needed.
//
// The objects are also not persistent, which is the other half. Persistent means surviving a
// reboot, and a machine that came back up with no meshpd and no network would have lost the
// recovery path that Linux and macOS both keep. What is wanted is the middle — outlives the
// process, does not outlive the boot — and that is what a non-dynamic session with
// non-persistent objects is documented to give. ADR-0030 records that this is the one claim
// in the design that had not been verified when it was written; TestALockOutlivesTheProcess
// is where it is.
func openSession() (uintptr, error) {
	var handle uintptr
	if err := fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, nil, unsafe.Pointer(&handle)); err != nil {
		return 0, fmt.Errorf("wfp: opening the filter engine: %w", wrapErr(err))
	}
	return handle, nil
}

// registerBaseObjects makes meshp's provider and sublayer exist.
//
// Idempotent: both are added inside a transaction and an "already there" is success, because
// the reconciler installs the lock on every pass and the objects outlive the process that
// made them.
//
// The sublayer's weight is high so that meshp's permits are evaluated above the blocks other
// software has installed in its own sublayers. Within meshp's sublayer the filters' own
// weights decide, which is where the policy actually lives.
func registerBaseObjects(session uintptr) error {
	displayData, err := createWtFwpmDisplayData0("meshp", "meshp fail-closed egress")
	if err != nil {
		return wrapErr(err)
	}

	provider := wtFwpmProvider0{
		providerKey: providerKey,
		displayData: *displayData,
	}
	if err := fwpmProviderAdd0(session, &provider, 0); err != nil &&
		!isAlreadyExists(err) {
		return fmt.Errorf("wfp: registering meshp as a filter provider: %w", wrapErr(err))
	}

	sublayer := wtFwpmSublayer0{
		subLayerKey: sublayerKey,
		displayData: *displayData,
		providerKey: &providerKey,
		weight:      ^uint16(0),
	}
	if err := fwpmSubLayerAdd0(session, &sublayer, 0); err != nil &&
		!isAlreadyExists(err) {
		return fmt.Errorf("wfp: registering meshp's sublayer: %w", wrapErr(err))
	}
	return nil
}

// isAlreadyExists reports whether an error means the object was there already.
//
// Success on the reconcile path: the provider and sublayer outlive the process, so every pass
// after the first finds them. Distinguished rather than swallowed, because every other reason
// an add can fail is one the caller should hear about.
func isAlreadyExists(err error) bool { return isFwpErr(err, fwpErrAlreadyExists) }

// isGone reports whether an error means the object was not there to remove.
//
// Success on the way out, for the reason removal is idempotent everywhere else in this
// project: teardown runs whether or not anything was installed.
func isGone(err error) bool {
	return isFwpErr(err, fwpErrNotFound) || isFwpErr(err, fwpErrFilterNotFound)
}

func isFwpErr(err error, code uintptr) bool {
	errno, ok := err.(windows.Errno)
	return ok && uintptr(errno) == code
}

// The filtering platform's own error codes, which are HRESULT-shaped rather than Win32 and
// are not in x/sys/windows.
//
// Only the two this package has to tell apart from everything else: an object that is already
// there, which is success on the reconcile path, and one that is not, which is success on the
// way out.
const (
	fwpErrAlreadyExists  = 0x80320009
	fwpErrFilterNotFound = 0x80320003
	fwpErrNotFound       = 0x80320008
)
