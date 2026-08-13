package nftables

import (
	"context"

	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// Filter enforces packet filters through nftables. It satisfies tunnel.Filter.
type Filter struct{}

// New returns a Filter, or nothing when this host cannot enforce one.
//
// Nil rather than an error, and checked once at construction rather than on every apply:
// the answer decides what the agent claims in its capabilities, and a capability that
// flapped between reconciles would be worse than one that is simply false.
func New(ctx context.Context) *Filter {
	if !Available(ctx) {
		return nil
	}
	return &Filter{}
}

// Apply renders and loads a filter, or removes the ruleset when there is none.
func (f *Filter) Apply(ctx context.Context, iface string, filter *meshpv1.PacketFilter) error {
	script, err := Render(iface, filter)
	if err != nil {
		return err
	}
	return Apply(ctx, script)
}
