package enroll

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/clock"
	"github.com/meshpnet/meshp/internal/dns"
	"github.com/meshpnet/meshp/internal/ipam"
	"github.com/meshpnet/meshp/internal/keys"
	"github.com/meshpnet/meshp/internal/store"
	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

var (
	// ErrAlreadyInNetwork means this device already has a membership here. Enrolling
	// twice into the same network is a mistake; enrolling into a second network is
	// not (ADR-0004).
	ErrAlreadyInNetwork = errors.New("enroll: device is already enrolled in this network")

	// ErrDeviceRevoked means the identity key belongs to a device an administrator
	// has revoked. Presenting a valid token does not undo that.
	ErrDeviceRevoked = errors.New("enroll: device has been revoked")

	// ErrNoAddressPool means the network cannot hand out an address.
	ErrNoAddressPool = errors.New("enroll: network has no device address pool")

	// ErrProofFailed means the signature over the challenge did not verify, so the
	// enroller does not hold the private key for the public key it presented.
	ErrProofFailed = errors.New("enroll: proof of possession failed")

	// ErrWireGuardKeyInUse means the presented WireGuard key already belongs to a
	// membership. Every membership needs its own key, including several memberships
	// of the same device: sharing one would let two networks recognise the same
	// device by its key (Invariant 19).
	ErrWireGuardKeyInUse = errors.New("enroll: that WireGuard key is already in use; generate a fresh one for each network")
)

// Service performs enrolment against the database.
type Service struct {
	store      *store.Store
	challenger *Challenger
	clk        clock.Clock
	log        *slog.Logger
}

// NewService wires an enrolment service.
func NewService(st *store.Store, ch *Challenger, clk clock.Clock, log *slog.Logger) *Service {
	if clk == nil {
		clk = clock.System{}
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{store: st, challenger: ch, clk: clk, log: log}
}

// ChallengeRequest asks for something to sign.
type ChallengeRequest struct {
	Token             string
	IdentityPublicKey []byte
}

// ChallengeResponse carries the bytes to sign.
type ChallengeResponse struct {
	Challenge string    `json:"challenge"`
	ExpiresAt time.Time `json:"expires_at"`
}

// IssueChallenge validates the token and returns a challenge bound to it.
//
// The token is checked here as well as at redemption, which does make this a
// yes-or-no oracle for token validity. That is an acceptable trade: guessing a
// 160-bit token is hopeless, and the alternative — issuing a challenge for a token
// that cannot possibly work — turns a clear "that token has expired" into a
// confusing failure two round trips later.
func (s *Service) IssueChallenge(ctx context.Context, req ChallengeRequest) (ChallengeResponse, error) {
	hash, err := HashToken(req.Token)
	if err != nil {
		return ChallengeResponse{}, err
	}
	if err := validateIdentityKey(req.IdentityPublicKey); err != nil {
		return ChallengeResponse{}, err
	}

	tok, err := s.store.Queries().GetEnrollmentTokenByHash(ctx, hash)
	if err != nil {
		if store.IsNotFound(err) {
			return ChallengeResponse{}, ErrTokenUnknown
		}
		return ChallengeResponse{}, fmt.Errorf("enroll: looking up token: %w", err)
	}
	if err := s.classifyToken(tok); err != nil {
		return ChallengeResponse{}, err
	}

	ch, err := s.challenger.Issue(hash, req.IdentityPublicKey)
	if err != nil {
		return ChallengeResponse{}, err
	}
	return ChallengeResponse{Challenge: ch.Encoded(), ExpiresAt: ch.ExpiresAt}, nil
}

// RedeemRequest is a device asking to join.
type RedeemRequest struct {
	Token              string
	IdentityPublicKey  []byte
	Challenge          []byte
	Signature          []byte
	WireGuardPublicKey string

	Name         string
	Hostname     string
	OS           string
	OSVersion    string
	AgentVersion string
	Capabilities map[string]any

	// SourceIP is recorded in the audit trail. Optional.
	SourceIP *netip.Addr
}

// RedeemResult is what the device needs to bring an interface up.
type RedeemResult struct {
	DeviceID      uuid.UUID   `json:"device_id"`
	MembershipID  uuid.UUID   `json:"membership_id"`
	NetworkID     uuid.UUID   `json:"network_id"`
	InterfaceName string      `json:"interface_name"`
	AddressV4     *netip.Addr `json:"address_v4,omitempty"`
	AddressV6     *netip.Addr `json:"address_v6,omitempty"`
	StateVersion  int64       `json:"state_version"`
}

// Redeem exchanges a token and a proof of possession for a network membership.
//
// Everything happens in one transaction. A device that appears in the network but
// holds no address, or holds an address nobody recorded, is worse than a device
// that failed to enrol — so either all of it lands or none of it does.
func (s *Service) Redeem(ctx context.Context, req RedeemRequest) (RedeemResult, error) {
	hash, err := HashToken(req.Token)
	if err != nil {
		return RedeemResult{}, err
	}
	if err := validateIdentityKey(req.IdentityPublicKey); err != nil {
		return RedeemResult{}, err
	}
	wgKey, err := keys.ParseWireGuardKey(req.WireGuardPublicKey)
	if err != nil {
		return RedeemResult{}, err
	}
	if wgKey.IsZero() {
		return RedeemResult{}, errors.New("enroll: WireGuard public key is all zeroes")
	}

	var result RedeemResult
	err = s.store.InTx(ctx, func(q *dbgen.Queries) error {
		// Locked, so two devices presenting the same token serialise here instead of
		// both reading a use count that is about to change.
		tok, err := q.GetEnrollmentTokenByHash(ctx, hash)
		if err != nil {
			if store.IsNotFound(err) {
				return ErrTokenUnknown
			}
			return fmt.Errorf("enroll: looking up token: %w", err)
		}
		if err := s.classifyToken(tok); err != nil {
			return err
		}

		// Authenticate before consuming anything. A failed proof must not burn a use
		// of a token that is still good.
		if err := s.challenger.Verify(req.Challenge, hash, req.IdentityPublicKey); err != nil {
			return err
		}
		if err := keys.VerifyIdentity(req.IdentityPublicKey, req.Challenge, req.Signature); err != nil {
			return fmt.Errorf("%w: %w", ErrProofFailed, err)
		}

		// The guarded increment is what actually stops a replay; the classification
		// above only produced a readable error. If it matches no row, another
		// transaction took the last use between the two statements.
		if _, err := q.ConsumeEnrollmentToken(ctx, dbgen.ConsumeEnrollmentTokenParams{
			ID:  tok.ID,
			Now: s.clk.Now(),
		}); err != nil {
			if store.IsNotFound(err) {
				return ErrTokenExhausted
			}
			return fmt.Errorf("enroll: consuming token: %w", err)
		}

		device, err := s.upsertDevice(ctx, q, tok, req)
		if err != nil {
			return err
		}

		// A device already in this network is a mistake worth naming; a device in
		// another network is the MSP technician case and entirely expected.
		existing, err := q.CountMembershipsForDevice(ctx, device.ID)
		if err != nil {
			return fmt.Errorf("enroll: counting memberships: %w", err)
		}

		chosen, err := s.pickAddresses(ctx, q, tok.NetworkID, device.ID)
		if err != nil {
			return err
		}
		v4, v6 := chosen.v4(), chosen.v6()

		label, err := freeLabel(ctx, q, tok.NetworkID, device.Name, device.ID)
		if err != nil {
			return err
		}

		membership, err := q.CreateMembership(ctx, dbgen.CreateMembershipParams{
			DeviceID:      device.ID,
			NetworkID:     tok.NetworkID,
			InterfaceName: fmt.Sprintf("meshp%d", existing),
			AddressV4:     v4,
			AddressV6:     v6,
			Tags:          tok.PreassignedTags,
			DnsLabel:      label,
		})
		if err != nil {
			if store.IsUniqueViolation(err) {
				// Two constraints on this table can be violated here and they mean
				// opposite things. A device already in the network is the caller's
				// answer; a label taken between choosing it and inserting it is a race
				// this lost, and the caller should be told to try again rather than told
				// they are already enrolled.
				if store.ConstraintName(err) == "device_network_memberships_dns_label_key" {
					return fmt.Errorf("enroll: the name %q was taken while enrolling; try again", label)
				}
				return ErrAlreadyInNetwork
			}
			return fmt.Errorf("enroll: creating membership: %w", err)
		}

		if err := s.recordAddresses(ctx, q, tok.NetworkID, membership.ID, chosen); err != nil {
			return err
		}

		if _, err := q.CreateWireGuardKey(ctx, dbgen.CreateWireGuardKeyParams{
			MembershipID: membership.ID,
			PublicKey:    wgKey.String(),
		}); err != nil {
			if store.IsUniqueViolation(err) {
				return ErrWireGuardKeyInUse
			}
			return fmt.Errorf("enroll: recording WireGuard key: %w", err)
		}

		if _, err := q.CreateMembershipState(ctx, dbgen.CreateMembershipStateParams{
			MembershipID: membership.ID,
			NetworkID:    tok.NetworkID,
		}); err != nil {
			return fmt.Errorf("enroll: creating membership state: %w", err)
		}

		// A new device changes what every other agent in the network should know, so the
		// bump belongs in this transaction rather than after it — and it carries the change
		// that explains it, so a delta from before this version can be built.
		version, err := store.BumpVersion(ctx, q, tok.NetworkID, store.PeerUpserted(membership.ID))
		if err != nil {
			return err
		}

		// And every other network this device is already in, because what they should send
		// it has just changed.
		//
		// A device's colliding prefixes are a property of the device -- two of *its* networks
		// carrying the same prefix (ADR-0020) -- while state versions are per network
		// (ADR-0008). Joining here can create a collision over there, and nothing over there
		// knows: its own version never moves, so no delta is ever sent, and that membership
		// goes on routing the customer's real prefix while the range allocated for it sits
		// unused. An end-to-end run found exactly that, with one interface mapped and the
		// other not.
		//
		// Routes rather than peers, because what changed for those networks is which prefixes
		// their assignments carry and how they are reached, not who is in them -- this device
		// is not joining them.
		//
		// In the same transaction as the join, so a device is never enrolled without the
		// networks that need to hear about it having been told.
		others, err := q.OtherNetworksForDevice(ctx, dbgen.OtherNetworksForDeviceParams{
			DeviceID:  device.ID,
			NetworkID: tok.NetworkID,
		})
		if err != nil {
			return fmt.Errorf("enroll: reading this device's other networks: %w", err)
		}
		for _, other := range others {
			if _, err := store.BumpVersion(ctx, q, other, store.RoutesChanged()); err != nil {
				return fmt.Errorf("enroll: telling network %s that this device joined another: %w", other, err)
			}
		}

		metadata, _ := json.Marshal(map[string]any{
			"interface_name": membership.InterfaceName,
			"os":             req.OS,
			"agent_version":  req.AgentVersion,
			"token_id":       tok.ID,
		})
		if _, err := q.CreateAuditEvent(ctx, dbgen.CreateAuditEventParams{
			OrganizationID: &tok.OrganizationID,
			NetworkID:      &tok.NetworkID,
			ActorKind:      "device",
			ActorID:        &device.ID,
			ActorLabel:     device.Name,
			Action:         "device.enrolled",
			ResourceKind:   "membership",
			ResourceID:     &membership.ID,
			SourceIp:       req.SourceIP,
			Metadata:       metadata,
		}); err != nil {
			return fmt.Errorf("enroll: writing audit event: %w", err)
		}

		result = RedeemResult{
			DeviceID:      device.ID,
			MembershipID:  membership.ID,
			NetworkID:     tok.NetworkID,
			InterfaceName: membership.InterfaceName,
			AddressV4:     v4,
			AddressV6:     v6,
			StateVersion:  version,
		}
		return nil
	})
	if err != nil {
		return RedeemResult{}, err
	}

	s.log.Info("device enrolled",
		"device_id", result.DeviceID,
		"network_id", result.NetworkID,
		"interface", result.InterfaceName,
		"address_v4", result.AddressV4,
		"address_v6", result.AddressV6)
	return result, nil
}

// upsertDevice returns the device for this identity key, creating it if new.
//
// A device that already exists is reused rather than rejected: that is how one
// laptop comes to hold memberships in several networks at once. Its
// organization_id stays as it was — the device is owned by the organisation that
// first enrolled it, and later memberships grant it reach into other networks
// without transferring ownership. For a managed service provider that is exactly
// right: the technician's laptop belongs to the provider, not to each customer.
func (s *Service) upsertDevice(ctx context.Context, q *dbgen.Queries, tok dbgen.EnrollmentToken, req RedeemRequest) (dbgen.Device, error) {
	device, err := q.GetDeviceByIdentityKey(ctx, req.IdentityPublicKey)
	switch {
	case err == nil:
		if device.RevokedAt != nil {
			return dbgen.Device{}, ErrDeviceRevoked
		}
		return device, nil
	case !store.IsNotFound(err):
		return dbgen.Device{}, fmt.Errorf("enroll: looking up device: %w", err)
	}

	capabilities := []byte("{}")
	if len(req.Capabilities) > 0 {
		if encoded, err := json.Marshal(req.Capabilities); err == nil {
			capabilities = encoded
		}
	}
	name := req.Name
	if name == "" {
		name = req.Hostname
	}
	if name == "" {
		name = "unnamed-device"
	}

	device, err = q.CreateDevice(ctx, dbgen.CreateDeviceParams{
		OrganizationID:    tok.OrganizationID,
		UserID:            tok.ScopedUserID,
		Name:              name,
		Hostname:          req.Hostname,
		Os:                req.OS,
		OsVersion:         req.OSVersion,
		AgentVersion:      req.AgentVersion,
		IdentityPublicKey: req.IdentityPublicKey,
		Capabilities:      capabilities,
	})
	if err != nil {
		if store.IsUniqueViolation(err) {
			// Another transaction created it between the lookup and the insert.
			return dbgen.Device{}, ErrAlreadyInNetwork
		}
		return dbgen.Device{}, fmt.Errorf("enroll: creating device: %w", err)
	}
	return device, nil
}

// chosenAddress is one address picked from one pool.
type chosenAddress struct {
	poolID uuid.UUID
	family int16
	addr   netip.Addr
}

type chosenAddresses []chosenAddress

func (c chosenAddresses) byFamily(family int16) *netip.Addr {
	for i := range c {
		if c[i].family == family {
			return &c[i].addr
		}
	}
	return nil
}

func (c chosenAddresses) v4() *netip.Addr { return c.byFamily(4) }
func (c chosenAddresses) v6() *netip.Addr { return c.byFamily(6) }

// pickAddresses chooses one address from each of the network's device pools.
//
// The pool rows are locked by ListDeviceAddressPools, so the read-decide-write
// sequence cannot interleave with another enrolment in the same network. Loading
// every allocation in a pool is linear in the number of devices, which is fine
// because enrolment happens once per device and networks are small; if that stops
// being true the fix is a next-free query, not a longer-held lock.
func (s *Service) pickAddresses(ctx context.Context, q *dbgen.Queries, networkID, deviceID uuid.UUID) (chosenAddresses, error) {
	pools, err := q.ListDeviceAddressPools(ctx, networkID)
	if err != nil {
		return nil, fmt.Errorf("enroll: listing address pools: %w", err)
	}
	if len(pools) == 0 {
		return nil, ErrNoAddressPool
	}

	out := make(chosenAddresses, 0, len(pools))
	for _, pool := range pools {
		rows, err := q.ListAllocationsForPool(ctx, pool.ID)
		if err != nil {
			return nil, fmt.Errorf("enroll: listing allocations: %w", err)
		}

		allocator, err := ipam.New(ipam.Config{Prefix: pool.Prefix}, s.clk)
		if err != nil {
			return nil, fmt.Errorf("enroll: pool %s: %w", pool.Prefix, err)
		}
		entries := make([]ipam.Entry, 0, len(rows))
		for _, r := range rows {
			e := ipam.Entry{Addr: r.Address}
			if r.State == "quarantined" && r.ReleasedAt != nil {
				e.ReleasedAt = *r.ReleasedAt
			}
			entries = append(entries, e)
		}
		if err := allocator.Restore(entries); err != nil {
			return nil, fmt.Errorf("enroll: rebuilding pool %s: %w", pool.Prefix, err)
		}

		addr, err := allocator.Allocate(deviceID.String())
		if err != nil {
			return nil, fmt.Errorf("enroll: pool %s: %w", pool.Prefix, err)
		}
		out = append(out, chosenAddress{poolID: pool.ID, family: pool.Family, addr: addr})
	}
	return out, nil
}

// recordAddresses writes the allocations pickAddresses chose, against the
// membership that now holds them.
func (s *Service) recordAddresses(ctx context.Context, q *dbgen.Queries, networkID, membershipID uuid.UUID, chosen chosenAddresses) error {
	for _, c := range chosen {
		if _, err := q.CreateAddressAllocation(ctx, dbgen.CreateAddressAllocationParams{
			PoolID:     c.poolID,
			NetworkID:  networkID,
			Address:    c.addr,
			HolderKind: "membership",
			HolderID:   &membershipID,
		}); err != nil {
			return fmt.Errorf("enroll: recording allocation %s: %w", c.addr, err)
		}
	}
	return nil
}

// classifyToken turns a token row into the specific reason it cannot be used.
func (s *Service) classifyToken(tok dbgen.EnrollmentToken) error {
	if tok.RevokedAt != nil {
		return ErrTokenRevoked
	}
	if !s.clk.Now().Before(tok.ExpiresAt) {
		return fmt.Errorf("%w at %s", ErrTokenExpired, tok.ExpiresAt.Format(time.RFC3339))
	}
	if tok.Uses >= tok.MaxUses {
		return ErrTokenExhausted
	}
	return nil
}

func validateIdentityKey(pub []byte) error {
	const ed25519PublicKeySize = 32
	if len(pub) != ed25519PublicKeySize {
		return fmt.Errorf("enroll: identity public key is %d bytes, want %d", len(pub), ed25519PublicKeySize)
	}
	return nil
}

// freeLabel picks the name this device answers to inside a network.
//
// Suffixed on collision, never refused. A fleet imaged with one hostname would otherwise
// produce one enrolment and forty-nine failures, for a reason the person running the
// installer can neither see nor fix (ADR-0021). `fileserver` becomes `fileserver-2`, and
// the caller is told which name it actually got.
//
// The database holds the real constraint. This picks a candidate that looks free, and if it
// loses a race the unique index catches it — which is why the insert distinguishes that
// violation rather than reporting it as an enrolment that already happened.
func freeLabel(ctx context.Context, q *dbgen.Queries, networkID uuid.UUID, displayName string, deviceID uuid.UUID) (string, error) {
	base := dns.Label(displayName)
	if base == "" {
		// Nothing usable in the name at all. Derived from the device's id rather than
		// refused: every membership needs a label, and an opaque one beats no enrolment.
		// The same fallback the migration uses, so a device that predates this and one
		// that arrives after it are named the same way.
		base = "device-" + strings.ReplaceAll(deviceID.String(), "-", "")[:8]
	}

	taken, err := q.TakenDNSLabels(ctx, dbgen.TakenDNSLabelsParams{NetworkID: networkID, Prefix: &base})
	if err != nil {
		return "", fmt.Errorf("enroll: reading the names already in use: %w", err)
	}
	used := make(map[string]struct{}, len(taken))
	for _, t := range taken {
		used[t] = struct{}{}
	}

	if _, clash := used[base]; !clash {
		return base, nil
	}
	// Bounded. A network with this many devices sharing one name has a naming problem the
	// enrolment path cannot fix, and an unbounded loop here would hold a transaction open
	// while it counted.
	for n := 2; n <= 1000; n++ {
		candidate := dns.Suffixed(base, n)
		if _, clash := used[candidate]; !clash {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("enroll: a thousand devices in this network are already called %q", base)
}
