package api

import (
	"net/http"

	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/internal/session"
	"github.com/meshpnet/meshp/internal/store"
)

// handleCreateDNSRecord writes down a name nothing can derive.
//
// The half of ADR-0021 §2 that was never built. Device names come from the peer list the
// agent already holds; these are the ones that cannot be synthesised — a name for something
// that is not a meshp device at all, or a second name for one that is — so they are desired
// state and travel with everything else.
func (s *Server) handleCreateDNSRecord(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}
	var body struct {
		Name  string `json:"name"`
		Type  string `json:"type"`
		Value string `json:"value"`
		TTL   int32  `json:"ttl_seconds"`
	}
	if err := decode(w, r, &body); err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	network, err := s.store.Queries().GetNetwork(r.Context(), networkID)
	if err != nil {
		if store.IsNotFound(err) {
			httpx.Error(w, s.log, http.StatusNotFound, "no_such_network", "no such network")
			return
		}
		s.respondError(w, r, err)
		return
	}

	record, err := s.store.CreateDNSRecord(r.Context(), store.CreateDNSRecordRequest{
		NetworkID:   networkID,
		NetworkSlug: network.Slug,
		// The zone is the network's own suffix rather than anything a caller chooses. A
		// record in some other zone would be a name this resolver never answers for, which
		// is a form of "accepted and does nothing".
		Suffix: network.Slug + "." + session.DefaultDNSSuffix,
		Name:   body.Name,
		Type:   body.Type,
		Value:  body.Value,
		TTL:    body.TTL,
	})
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	httpx.WriteJSON(w, s.log, http.StatusCreated, dnsRecordJSON(record, network.Slug))
}

// handleListDNSRecords answers what has been written down.
func (s *Server) handleListDNSRecords(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}
	network, err := s.store.Queries().GetNetwork(r.Context(), networkID)
	if err != nil {
		if store.IsNotFound(err) {
			httpx.Error(w, s.log, http.StatusNotFound, "no_such_network", "no such network")
			return
		}
		s.respondError(w, r, err)
		return
	}

	records, err := s.store.ListDNSRecords(r.Context(), networkID)
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(records))
	for _, record := range records {
		out = append(out, dnsRecordJSON(record, network.Slug))
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{"records": out})
}

// handleDeleteDNSRecord removes one.
func (s *Server) handleDeleteDNSRecord(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}
	recordID, ok := s.pathUUID(w, r, "recordID")
	if !ok {
		return
	}
	if err := s.store.DeleteDNSRecord(r.Context(), networkID, recordID); err != nil {
		s.respondError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// dnsRecordJSON renders a record, including the name it will actually answer to.
//
// The fully-qualified form is returned rather than left for the caller to assemble. It is
// what somebody types, the suffix is the server's to decide, and a client building it from
// two fields is a client that will get it wrong once.
func dnsRecordJSON(record store.DNSRecord, networkSlug string) map[string]any {
	return map[string]any{
		"id":          record.ID,
		"name":        record.Name,
		"fqdn":        record.Name + "." + networkSlug + "." + session.DefaultDNSSuffix,
		"type":        record.Type,
		"value":       record.Value,
		"ttl_seconds": record.TTL,
	}
}
