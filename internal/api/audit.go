package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/httpx"
	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// auditPageParams builds the query's arguments. The network id is a pointer in the
// generated params because the column is nullable — an event whose network was deleted
// keeps its record — so it is taken by address here rather than at three call sites.
func auditPageParams(networkID uuid.UUID, before int64, limit int) dbgen.PageAuditEventsForNetworkParams {
	return dbgen.PageAuditEventsForNetworkParams{
		NetworkID: &networkID,
		Before:    before,
		PageSize:  int32(limit),
	}
}

// Audit page bounds.
//
// A default small enough to read and a ceiling that stops one request asking the database
// for a network's entire history. A caller wanting all of it pages, which is also what makes
// the response size predictable for the commercial layer reading many networks on a timer.
const (
	defaultAuditPage = 50
	maxAuditPage     = 500
)

// handleListAuditEvents answers what has happened in a network.
//
// Three subsystems have been writing here since the beginning — enrolment, policy
// publication, revocation — and since #124 a device moving itself between candidates. Only
// a test had ever read one back, so "auditable" meant "queryable in psql" and the record
// that answers "why did my outbound IP change?" was reachable only by whoever had the
// database (ADR-0018).
//
// Behind the administrative token rather than the browser's cookie. ADR-0022 §5 scopes that
// cookie to the read endpoints it names, and widening it is a decision about a credential
// rather than a route to be added quietly — see the note in the ADR.
func (s *Server) handleListAuditEvents(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}
	limit, ok := s.auditLimit(w, r)
	if !ok {
		return
	}
	before, ok := s.auditCursor(w, r)
	if !ok {
		return
	}

	// One more than asked for, so the response can say whether there is another page
	// without a second query and without a count over the whole table.
	rows, err := s.store.Queries().PageAuditEventsForNetwork(r.Context(), auditPageParams(networkID, before, limit+1))
	if err != nil {
		s.respondError(w, r, err)
		return
	}

	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}

	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		event := map[string]any{
			"id":         strconv.FormatInt(row.ID, 10),
			"at":         row.CreatedAt.UTC(),
			"actor_kind": row.ActorKind,
			"action":     row.Action,
		}
		if row.ActorLabel != "" {
			event["actor_label"] = row.ActorLabel
		}
		if row.ActorID != nil {
			event["actor_id"] = row.ActorID
		}
		if row.ResourceKind != "" {
			event["resource_kind"] = row.ResourceKind
		}
		if row.ResourceID != nil {
			event["resource_id"] = row.ResourceID
		}
		if row.SourceIp != nil {
			event["source_ip"] = row.SourceIp.String()
		}
		// Passed through as the object it is rather than as an escaped string. Every writer
		// puts a JSON object here, and re-encoding it would hand a reader something it has
		// to parse twice.
		if len(row.Metadata) > 0 {
			event["metadata"] = json.RawMessage(row.Metadata)
		}
		out = append(out, event)
	}

	body := map[string]any{"events": out}
	if more && len(rows) > 0 {
		// The cursor for the next page, rather than a page number. Events are only ever
		// appended, so an offset would shift under a caller reading a busy network — the
		// one situation where a page of history is most likely to be read.
		body["next_before"] = strconv.FormatInt(rows[len(rows)-1].ID, 10)
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, body)
}

// auditLimit reads ?limit=.
func (s *Server) auditLimit(w http.ResponseWriter, r *http.Request) (int, bool) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return defaultAuditPage, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request",
			"limit must be a positive whole number")
		return 0, false
	}
	if n > maxAuditPage {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request",
			"limit may be at most "+strconv.Itoa(maxAuditPage))
		return 0, false
	}
	return n, true
}

// auditCursor reads ?before=, which is an id from a previous response.
//
// Refused rather than ignored when it will not parse. A cursor silently treated as "start
// again from the newest" would make a paging caller loop over the first page forever while
// looking like it was making progress.
func (s *Server) auditCursor(w http.ResponseWriter, r *http.Request) (int64, bool) {
	raw := r.URL.Query().Get("before")
	if raw == "" {
		return 0, true
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request",
			"before must be an id from a previous response")
		return 0, false
	}
	return n, true
}
