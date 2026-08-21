package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/meshpnet/meshp/internal/dns"
	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// Errors a caller is allowed to distinguish. Each names something the person typing can
// fix, which is the test for whether it deserves to be separate from a generic failure.
var (
	// ErrRecordExists means this exact name, type and value is already there.
	ErrRecordExists = errors.New("store: that record already exists")

	// ErrNoSuchRecord means the record is not in this network.
	ErrNoSuchRecord = errors.New("store: no such record in this network")
)

// DNSRecord is one administrator-entered name.
type DNSRecord struct {
	ID    uuid.UUID
	Name  string
	Type  string
	Value string
	TTL   int32
}

// CreateDNSRecordRequest is a name somebody typed.
type CreateDNSRecordRequest struct {
	NetworkID   uuid.UUID
	NetworkSlug string
	Suffix      string

	Name  string
	Type  string
	Value string
	TTL   int32
}

// CreateDNSRecord writes down a name nothing can derive.
//
// Validated here rather than at the edge, because this is the last place before the row
// exists and a record that reaches an agent unparseable is a record that silently does
// nothing on every device in the network. The agent refuses such a record rather than the
// whole state, which means a bad one would be invisible except to whoever was reading logs
// on the device.
func (s *Store) CreateDNSRecord(ctx context.Context, req CreateDNSRecordRequest) (DNSRecord, error) {
	name := strings.ToLower(strings.TrimSpace(req.Name))
	if !dns.ValidLabel(name) {
		// The same rule device names follow (ADR-0021 §5). A record and a device name land
		// in one namespace and are answered by one resolver, so two rules would mean a name
		// that is legal to write and impossible to reach.
		return DNSRecord{}, invalid("%q is not a DNS label: use letters, digits and hyphens", req.Name)
	}

	recordType := strings.ToUpper(strings.TrimSpace(req.Type))
	addr, err := netip.ParseAddr(strings.TrimSpace(req.Value))
	switch {
	case recordType != "A" && recordType != "AAAA":
		// CNAME is in the schema and is refused here rather than stored. The resolver
		// answers from a flat name-to-address map; an alias needs chasing or returning as
		// its own record type, and accepting one now would store a record that arrives at
		// every device and does nothing.
		return DNSRecord{}, invalid(
			"%q is not a record type this serves: A and AAAA are, and CNAME is not yet", req.Type)
	case err != nil:
		return DNSRecord{}, invalid("%q is not an IP address", req.Value)
	case recordType == "A" && !addr.Is4():
		return DNSRecord{}, invalid("an A record needs an IPv4 address, and %q is not one", req.Value)
	case recordType == "AAAA" && addr.Is4():
		return DNSRecord{}, invalid("an AAAA record needs an IPv6 address, and %q is not one", req.Value)
	}

	ttl := req.TTL
	if ttl <= 0 {
		ttl = dns.DefaultTTL
	}

	var out DNSRecord
	err = s.InTx(ctx, func(q *dbgen.Queries) error {
		// A device already answering to this name. Refused here, where the person typing
		// can pick another, rather than resolved silently on every device in the network:
		// the agent lets the record win, which would take a machine's name away from it
		// without anybody being told.
		taken, err := q.CountDevicesWithDNSLabel(ctx, dbgen.CountDevicesWithDNSLabelParams{
			NetworkID: req.NetworkID,
			DnsLabel:  name,
		})
		if err != nil {
			return fmt.Errorf("store: checking for a device with that name: %w", err)
		}
		if taken > 0 {
			return invalid(
				"a device in this network already answers to %q; pick another name or rename the device",
				name)
		}

		zone, err := q.EnsureDNSZone(ctx, dbgen.EnsureDNSZoneParams{
			NetworkID: req.NetworkID,
			Name:      req.Suffix,
		})
		if err != nil {
			return fmt.Errorf("store: ensuring the zone: %w", err)
		}

		row, err := q.CreateDNSRecord(ctx, dbgen.CreateDNSRecordParams{
			ZoneID:    zone.ID,
			NetworkID: req.NetworkID,
			Name:      name,
			Type:      recordType,
			Value:     addr.String(),
			Ttl:       ttl,
		})
		if IsUniqueViolation(err) {
			return ErrRecordExists
		}
		if err != nil {
			return fmt.Errorf("store: writing the record: %w", err)
		}

		// Every device in this network needs to hear about it, and the delta machinery is
		// what makes that happen (ADR-0008). A record written without this reaches nobody
		// until something else moves the version, which is the sort of "it works on the
		// second change" behaviour nobody can debug.
		if _, err := BumpVersion(ctx, q, req.NetworkID, DNSRecordsChanged(name, recordType)); err != nil {
			return err
		}

		out = DNSRecord{ID: row.ID, Name: row.Name, Type: row.Type, Value: row.Value, TTL: row.Ttl}
		return nil
	})
	return out, err
}

// ListDNSRecords returns a network's administrator-entered records.
func (s *Store) ListDNSRecords(ctx context.Context, networkID uuid.UUID) ([]DNSRecord, error) {
	rows, err := s.Queries().ListDNSRecordsForNetwork(ctx, networkID)
	if err != nil {
		return nil, fmt.Errorf("store: listing records: %w", err)
	}
	out := make([]DNSRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, DNSRecord{
			ID: row.ID, Name: row.Name, Type: row.Type, Value: row.Value, TTL: row.Ttl,
		})
	}
	return out, nil
}

// DeleteDNSRecord removes one, and tells the network.
func (s *Store) DeleteDNSRecord(ctx context.Context, networkID, recordID uuid.UUID) error {
	return s.InTx(ctx, func(q *dbgen.Queries) error {
		rows, err := q.DeleteDNSRecord(ctx, dbgen.DeleteDNSRecordParams{
			ID: recordID, NetworkID: networkID,
		})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("store: deleting the record: %w", err)
		}
		if rows == 0 {
			// A record in another network reads the same as one that does not exist. The
			// alternative tells a caller holding one network's token whether an id exists
			// in another.
			return ErrNoSuchRecord
		}
		if _, err := BumpVersion(ctx, q, networkID, DNSRecordsChanged("", "")); err != nil {
			return err
		}
		return nil
	})
}
