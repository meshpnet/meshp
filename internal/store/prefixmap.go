package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/prefixmap"
	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// DefaultMappedBlock is where mapped ranges come from when nothing says otherwise.
//
// Inside 100.64.0.0/10, which is carrier-grade NAT space: it is routable-looking, it is not
// somebody's LAN, and it is the range mesh overlays already live in — so a device that
// carries it is not shadowing a customer's own addressing. Deliberately away from the /16s
// this project's own examples and tests hand out mesh addresses from, because a mapped range
// landing on a network's own addresses is the collision one level up (ADR-0020).
//
// A /16 holds 256 mapped /24s, which is 256 colliding customer prefixes across a deployment.
// An MSP that outgrows that changes the block rather than discovering a limit silently:
// allocation reports exhaustion as its own error.
var DefaultMappedBlock = netip.MustParsePrefix("100.71.0.0/16")

// PrefixMapping is one customer prefix and the range a device reaches it by.
type PrefixMapping struct {
	NetworkID uuid.UUID
	Prefix    netip.Prefix
	Mapped    netip.Prefix
}

// ErrMappingUnavailable means a colliding prefix could not be given a range.
//
// Distinguished so a caller can keep the honest refusal from PR #70 rather than carrying one
// of two identical prefixes: a device that says it cannot reach either customer is worse to
// use and better to trust than one that quietly reaches the wrong one.
var ErrMappingUnavailable = errors.New("store: a colliding prefix has no mapped range")

// EnsureMappings returns the mapped ranges a device needs, allocating any that are missing.
//
// Lazily, on the path that builds desired state, and that is a deliberate choice about when
// rather than a shortcut. A collision appears when a device joins a second network or when
// somebody adds a prefix to a route group, and there is no single event to hang allocation
// off that both of those reach. Doing it here means the answer exists the first time a device
// that needs it asks, and never for a deployment where nobody is in two networks at once.
//
// Cheap when there is nothing to do, which is the overwhelmingly common case: one indexed
// read of what this device's networks carry, and a second only if two of them carry the same
// prefix. Nothing is written unless a collision has no range yet.
//
// Returns every mapping for the device's networks, not only the ones allocated now, because
// the caller needs the whole set to put on the wire.
func (s *Store) EnsureMappings(ctx context.Context, deviceID uuid.UUID, block netip.Prefix) ([]PrefixMapping, error) {
	if !block.IsValid() {
		block = DefaultMappedBlock
	}
	q := dbgen.New(s.pool)

	carried, err := q.CarriedPrefixesForDevice(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("store: reading what this device's networks carry: %w", err)
	}
	if len(carried) == 0 {
		return nil, nil
	}

	byNetwork := make(map[string][]netip.Prefix)
	networks := make(map[string]uuid.UUID)
	for _, row := range carried {
		id := row.NetworkID.String()
		byNetwork[id] = append(byNetwork[id], row.Prefix)
		networks[id] = row.NetworkID
	}

	colliding := prefixmap.Colliding(byNetwork)
	if len(colliding) == 0 {
		// The ordinary device. No read of the mapping table at all, because a device whose
		// prefixes do not collide has nothing there and never will.
		return nil, nil
	}

	ids := make([]uuid.UUID, 0, len(networks))
	for _, id := range networks {
		ids = append(ids, id)
	}
	existing, err := q.MappedPrefixesForNetworks(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("store: reading existing mappings: %w", err)
	}

	out := make([]PrefixMapping, 0, len(existing))
	have := make(map[string]bool, len(existing))
	for _, row := range existing {
		out = append(out, PrefixMapping{NetworkID: row.NetworkID, Prefix: row.Prefix, Mapped: row.MappedPrefix})
		have[row.NetworkID.String()+"|"+row.Prefix.String()] = true
	}

	missing := needed(colliding, byNetwork, networks, have)
	if len(missing) == 0 {
		return out, nil
	}

	org, err := q.OrganizationForDevice(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("store: reading the device's organisation: %w", err)
	}
	spoken, err := q.SpokenForRangesInOrganization(ctx, dbgen.SpokenForRangesInOrganizationParams{
		OrganizationID: org,
		// The block is passed so the query can reserve only the carried prefixes that could
		// actually land on it. A customer LAN in RFC 1918 cannot overlap a block in CGNAT
		// space and is not reserved; one inside 100.64.0.0/10 is, because a mapped range on
		// top of it would shadow a network this device can genuinely reach.
		Block: block,
	})
	if err != nil {
		return nil, fmt.Errorf("store: reading what is already spoken for: %w", err)
	}

	// Every range already handed out counts against the next one, including the ones
	// allocated inside this loop. Without that, two prefixes colliding on the same device
	// would both be offered the lowest free range and the second insert would be refused by
	// the unique constraint.
	reserved := prefixmap.Reserved(spoken)
	for _, m := range missing {
		mapped, allocErr := prefixmap.Allocate(block, m.Prefix, reserved)
		if allocErr != nil {
			return out, fmt.Errorf("%w: %v: %w", ErrMappingUnavailable, m.Prefix, allocErr)
		}
		row, insErr := q.InsertPrefixMapping(ctx, dbgen.InsertPrefixMappingParams{
			OrganizationID: org,
			NetworkID:      m.NetworkID,
			Prefix:         m.Prefix,
			MappedPrefix:   mapped,
		})
		if insErr != nil {
			return out, fmt.Errorf("store: recording a mapped range for %v: %w", m.Prefix, insErr)
		}
		if row.MappedPrefix.IsValid() {
			// A row came back, so this session allocated it.
			out = append(out, PrefixMapping{NetworkID: row.NetworkID, Prefix: row.Prefix, Mapped: row.MappedPrefix})
			reserved = append(reserved, row.MappedPrefix)
			continue
		}
		// No row: another session allocated for this prefix between the read above and
		// this insert, and the conflict was ignored rather than raised. Its answer is the
		// one that stands, and it is read back on the next pass. Skipping is correct here
		// rather than re-reading: the state this builds is versioned, and a mapping that
		// arrives one delta later is a mapping the device did not have yet anyway.
		reserved = append(reserved, mapped)
	}
	return out, nil
}

// needed lists the (network, prefix) pairs that collide and have no range yet.
//
// Every network carrying a colliding prefix needs its own range, including the first one.
// Leaving one unmapped would mean a device reaching one customer at their real address and
// another at a mapped one, which is harder to explain than mapping both and is not
// meaningfully cheaper.
func needed(colliding []netip.Prefix, byNetwork map[string][]netip.Prefix,
	networks map[string]uuid.UUID, have map[string]bool,
) []PrefixMapping {
	var out []PrefixMapping
	for _, prefix := range colliding {
		for id, carried := range byNetwork {
			for _, p := range carried {
				if p.Masked() != prefix {
					continue
				}
				if have[id+"|"+prefix.String()] {
					break
				}
				out = append(out, PrefixMapping{NetworkID: networks[id], Prefix: prefix})
				break
			}
		}
	}
	// Sorted by prefix then network, so two sessions allocating at once tend to walk the
	// same order and a deployment's ranges do not depend on map iteration.
	sortMappings(out)
	return out
}

// sortMappings orders by prefix then network, for a stable allocation order.
func sortMappings(m []PrefixMapping) {
	slices.SortFunc(m, func(a, b PrefixMapping) int {
		if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
			return c
		}
		if c := a.Prefix.Bits() - b.Prefix.Bits(); c != 0 {
			return c
		}
		return strings.Compare(a.NetworkID.String(), b.NetworkID.String())
	})
}
