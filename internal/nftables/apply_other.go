//go:build !linux

package nftables

import "context"

// Available is false everywhere but Linux.
//
// Reported rather than assumed, because it decides what the agent claims it can do and the
// control plane acts on that claim. Windows enforces through WFP and macOS through the
// network extension's packet-filter path (ADR-0007); neither is implemented, and saying so
// is what stops a device being placed in a network whose policy it cannot honour.
func Available(context.Context) bool { return false }

// Apply is unsupported off Linux.
func Apply(context.Context, string) error { return ErrUnsupported }
