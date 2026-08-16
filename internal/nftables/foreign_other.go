//go:build !linux

package nftables

import "context"

// ForwardRefusals reports nothing off Linux, where meshp does not forward at all.
//
// Nil rather than an error: a host that cannot carry a prefix is refused earlier, by
// Available, and reporting an obstacle to something that was never going to happen would put
// a condition in front of an operator that means nothing on their machine.
func ForwardRefusals(context.Context) ([]Refusal, error) { return nil, nil }
