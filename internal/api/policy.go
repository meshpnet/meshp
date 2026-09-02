package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/acl"
	"github.com/meshpnet/meshp/internal/httpx"
	"github.com/meshpnet/meshp/internal/store"
)

// maxPolicyBytes bounds a policy document.
//
// Generous for anything a person writes and far below what would trouble the compiler; the
// point is that an unbounded body is a way to make a control plane allocate whatever it is
// sent.
const maxPolicyBytes = 1 << 20

// handleGetPolicy returns the policy in force.
//
// A network with no policy answers 404 rather than an empty document, because those mean
// opposite things: no policy permits everything, and an empty policy permits nothing. An
// administrator reading `{"rules":[]}` for a network that has never had a policy would
// believe their network was closed.
func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}

	policy, err := s.store.ActivePolicy(r.Context(), networkID)
	if errors.Is(err, store.ErrNoPolicy) {
		httpx.Error(w, s.log, http.StatusNotFound, "no_policy",
			"this network has no policy; every device may reach every other")
		return
	}
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{
		"version":    policy.Version,
		"created_at": policy.CreatedAt,
		"document":   policy.Document,
	})
}

// handlePublishPolicy stores a document and makes it the one in force.
func (s *Server) handlePublishPolicy(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}

	payload, err := io.ReadAll(io.LimitReader(r.Body, maxPolicyBytes+1))
	if err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", "could not read the body")
		return
	}
	if len(payload) > maxPolicyBytes {
		httpx.Error(w, s.log, http.StatusRequestEntityTooLarge, "too_large",
			"that policy is larger than this control plane will accept")
		return
	}

	doc, err := acl.Parse(payload)
	if err != nil {
		// The reason reaches the author verbatim. This is the one place where a detailed
		// error is the whole value: "rule 3: names ports with protocol icmp" is the
		// difference between fixing a policy and guessing at it, and the caller is an
		// administrator holding this network's token rather than an untrusted device.
		httpx.Error(w, s.log, http.StatusBadRequest, "invalid_policy", err.Error())
		return
	}

	req := store.PublishPolicyRequest{
		NetworkID: networkID,
		Document:  doc,
		Actor:     s.actor(r),
		SourceIP:  sourceAddr(r),
	}
	if network, err := s.store.Queries().GetNetwork(r.Context(), networkID); err == nil {
		req.OrganizationID = &network.OrganizationID
	}

	policy, err := s.store.PublishPolicy(r.Context(), req)
	if err != nil {
		s.respondError(w, r, err)
		return
	}

	s.log.Info("policy published",
		"network_id", networkID, "policy_version", policy.Version, "rules", len(doc.Rules))

	// Every device's filter changed, so every connected agent needs fresh state. Without
	// this a policy takes up to a heartbeat interval to reach anyone, which for a control
	// that exists to deny traffic is the wrong direction to be slow in.
	s.tellNetwork(networkID)

	httpx.WriteJSON(w, s.log, http.StatusCreated, map[string]any{
		"status":     "published",
		"version":    policy.Version,
		"created_at": policy.CreatedAt,
	})
}

// handleListPolicyVersions returns every version ever published.
//
// With their documents, because a policy is meant to be diffed and rolled back (ADR-0007)
// and a list of numbers supports neither.
func (s *Server) handleListPolicyVersions(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}
	rows, err := s.store.Queries().ListPolicyVersions(r.Context(), networkID)
	if err != nil {
		s.respondError(w, r, err)
		return
	}

	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		entry := map[string]any{
			"version":    row.Version,
			"active":     row.IsActive,
			"created_at": row.CreatedAt,
		}
		// Passed through as stored rather than re-encoded. A version this build can no
		// longer parse is exactly the one an operator most needs to read, so a policy that
		// fails to validate must still be visible here.
		entry["document"] = json.RawMessage(row.Document)
		out = append(out, entry)
	}
	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{"policies": out})
}

// handleTestPolicy compiles a policy for one device without publishing it.
//
// The question this answers is the one nobody could ask before: given this document, what
// would that device actually enforce? A policy is written in selectors and read by people;
// what reaches a device is a packet filter in prefixes, and the step between them is where
// a rule that does not do what its author meant goes unnoticed until somebody cannot reach
// something.
//
// Compiled the way the session builder compiles it, from store.PolicyDevices and
// acl.Compile, so the answer is what the device would be sent rather than a second
// implementation's opinion of it (ADR-0023). The one difference is how the subject is
// found: the session knows a membership row without a key and matches on address, and this
// has the key and matches on that. Both land on the same device.
//
// Behind acl.write rather than acl.read. A dry-run is a step in publishing and the people
// who take it are the people who publish — and a caller supplying an arbitrary document
// could otherwise probe which devices carry which tags, which reading the policy does not
// tell them.
func (s *Server) handleTestPolicy(w http.ResponseWriter, r *http.Request) {
	networkID, ok := s.pathUUID(w, r, "networkID")
	if !ok {
		return
	}

	var req struct {
		// Device names the subject: a membership id, a device id, or a device name.
		Device string `json:"device"`
		// Document is the policy to test. Omitted means the one in force, which is how
		// somebody asks "what is this device enforcing right now".
		Document json.RawMessage `json:"document,omitempty"`
	}
	payload, err := io.ReadAll(io.LimitReader(r.Body, maxPolicyBytes+1))
	if err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", "could not read the body")
		return
	}
	if len(payload) > maxPolicyBytes {
		httpx.Error(w, s.log, http.StatusRequestEntityTooLarge, "too_large",
			"that policy is larger than this control plane will accept")
		return
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request", "body must be JSON")
		return
	}
	if req.Device == "" {
		httpx.Error(w, s.log, http.StatusBadRequest, "bad_request",
			"name a device to compile for: a membership id, a device id, or its name")
		return
	}

	doc, ok := s.policyToTest(w, r, networkID, req.Document)
	if !ok {
		return
	}

	subject, found, err := s.subjectOf(r, networkID, req.Device)
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	if !found {
		httpx.Error(w, s.log, http.StatusNotFound, "not_found",
			"no device in this network is named by that, or it holds no address")
		return
	}

	devices, err := s.store.PolicyDevices(r.Context(), networkID)
	if err != nil {
		s.respondError(w, r, err)
		return
	}
	self, ok := selfByKey(devices, subject.key)
	if !ok {
		// In the network but not among the devices a policy resolves against: revoked,
		// suspended, or holding no address. Compiling from a guess would be worse than
		// saying so.
		httpx.Error(w, s.log, http.StatusConflict, "not_in_policy",
			"that device is in this network but not among the devices its policy applies to")
		return
	}

	filter, err := acl.Compile(doc, self, devices)
	if err != nil {
		httpx.Error(w, s.log, http.StatusBadRequest, "invalid_policy", err.Error())
		return
	}

	httpx.WriteJSON(w, s.log, http.StatusOK, map[string]any{
		"device":        subject.name,
		"membership_id": subject.membershipID,
		// What the device is told, rendered as it is sent. A caller comparing this against
		// what a device reports is comparing the same thing.
		"filter": filter,
		// Said explicitly, because an empty rule list means two opposite things depending
		// on it and somebody reading a dry-run needs to know which.
		"default_deny": filter.GetDefaultDeny(),
	})
}

// policyToTest is the document a dry-run should compile: the one supplied, or the one in
// force when none was.
func (s *Server) policyToTest(w http.ResponseWriter, r *http.Request, networkID uuid.UUID,
	supplied json.RawMessage) (acl.Document, bool) {

	if len(supplied) > 0 {
		doc, err := acl.Parse(supplied)
		if err != nil {
			// Verbatim, for the reason handlePublishPolicy gives: this is an administrator
			// holding this network's token, and the reason is the whole value.
			httpx.Error(w, s.log, http.StatusBadRequest, "invalid_policy", err.Error())
			return acl.Document{}, false
		}
		return doc, true
	}

	policy, err := s.store.ActivePolicy(r.Context(), networkID)
	if errors.Is(err, store.ErrNoPolicy) {
		httpx.Error(w, s.log, http.StatusNotFound, "no_policy",
			"this network has no policy to test; supply a document, or publish one")
		return acl.Document{}, false
	}
	if err != nil {
		s.respondError(w, r, err)
		return acl.Document{}, false
	}
	return policy.Document, true
}

// subject is the device a dry-run is about.
type subject struct {
	membershipID uuid.UUID
	name         string
	key          string
}

// subjectOf finds the device a dry-run names.
//
// By membership id, device id, or name, which is what the CLI accepts and what somebody
// asking this question has. An ambiguous name is refused rather than resolved: compiling
// for whichever of two devices called "laptop" sorted first would answer a question nobody
// asked.
func (s *Server) subjectOf(r *http.Request, networkID uuid.UUID, want string) (subject, bool, error) {
	rows, err := s.store.Queries().ListMembershipsForNetwork(r.Context(), networkID)
	if err != nil {
		return subject{}, false, err
	}

	var byName []subject
	for _, row := range rows {
		key := ""
		if row.WireguardPublicKey != nil {
			key = *row.WireguardPublicKey
		}
		found := subject{membershipID: row.MembershipID, name: row.DeviceName, key: key}
		if row.MembershipID.String() == want || row.DeviceID.String() == want {
			return found, true, nil
		}
		if strings.EqualFold(row.DeviceName, want) {
			byName = append(byName, found)
		}
	}
	if len(byName) == 1 {
		return byName[0], true, nil
	}
	return subject{}, false, nil
}

// selfByKey finds a device among those a policy resolves against.
//
// By WireGuard key, which is what acl.Device is identified by. The session builder matches
// on address instead, because the membership row it holds carries addresses and not a key
// — a difference in what each caller has, not in which device is found.
func selfByKey(devices []acl.Device, key string) (acl.Device, bool) {
	if key == "" {
		return acl.Device{}, false
	}
	for _, device := range devices {
		if device.Key == key {
			return device, true
		}
	}
	return acl.Device{}, false
}
