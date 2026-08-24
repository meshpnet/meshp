package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/authz"
)

// Every route says how it is gated, and the permission it names exists.
//
// Routes panics on either failure, so building a server is itself the check — this test says
// what that panic means and fails with a sentence rather than a stack trace. The forcing
// function is the zero value of guardKind: adding an endpoint without deciding who may reach
// it is not something a reviewer has to notice.
func TestEveryRouteSaysHowItIsGated(t *testing.T) {
	h := newHarness(t)

	seen := map[string]bool{}
	for _, rt := range h.srv.routes() {
		if rt.kind == guardUnset {
			t.Errorf("%s was registered without saying how it is gated", rt.pattern)
		}
		if seen[rt.pattern] {
			t.Errorf("%s is registered twice", rt.pattern)
		}
		seen[rt.pattern] = true

		switch rt.kind {
		case guardNetwork, guardOrganization, guardCallerOrganization:
			if !authz.Known(string(rt.perm)) {
				t.Errorf("%s needs %q, which is not in the catalogue", rt.pattern, rt.perm)
			}
		default:
			if rt.perm != "" {
				t.Errorf("%s names %q next to a guard that never checks it", rt.pattern, rt.perm)
			}
		}
	}
}

// A permission no route requires is one nobody can use.
//
// The catalogue is public API — ADR-0009 makes the commercial layer a consumer and ADR-0023
// says that surface cannot be reshaped freely — so an entry that reaches nothing is a string
// somebody will grant, and then wonder why it changed nothing. Deleting it later is a
// breaking change; not adding it is free.
func TestEveryPermissionIsRequiredBySomeRoute(t *testing.T) {
	h := newHarness(t)

	required := map[authz.Permission]bool{}
	for _, rt := range h.srv.routes() {
		if rt.perm != "" {
			required[rt.perm] = true
		}
	}
	for _, e := range authz.Catalogue {
		if !required[e.Name] {
			t.Errorf("%q is in the catalogue and no route requires it, so granting it does nothing", e.Name)
		}
	}
}

// A permission's family decides how it is checked, so a route must not check one against the
// wrong scope. An `organization.` permission checked against a network would be granted by a
// binding narrowed to that network, which is the one thing the two families exist to prevent.
func TestRoutesCheckPermissionsAgainstTheRightScope(t *testing.T) {
	h := newHarness(t)

	for _, rt := range h.srv.routes() {
		switch rt.kind {
		case guardNetwork:
			if !strings.HasPrefix(string(rt.perm), "network.") {
				t.Errorf("%s checks %q against a network; only a network.* permission may be",
					rt.pattern, rt.perm)
			}
		case guardOrganization, guardCallerOrganization:
			if !strings.HasPrefix(string(rt.perm), "organization.") {
				t.Errorf("%s checks %q against an organisation; only an organization.* permission may be",
					rt.pattern, rt.perm)
			}
		}
	}
}

// The MSP case, over HTTP, which is what the whole slice is for.
//
// A technician holds a role on one customer's network. They can act there. On the network
// next door they are refused — not with a 404 that would tell them it exists, and not with a
// 401 that would suggest signing in again would help.
func TestATechnicianBoundToOneNetworkCannotTouchAnother(t *testing.T) {
	h := newHarness(t)
	org := orgOf(t, h)
	other := h.secondNetwork(t)

	tech := createUser(t, h, "tech@example.com")
	takeAwayEveryRole(t, h, tech)
	grantRole(t, h, tech, map[string]any{
		"role": authz.RoleOperator, "network_id": h.netID.String(),
	})

	cookie := signIn(t, h, "tech@example.com", testPassword)

	mine := h.withCookie(http.MethodGet, "/api/v1/networks/"+h.netID.String()+"/devices", cookie)
	_ = mine.Body.Close()
	if mine.StatusCode != http.StatusOK {
		t.Errorf("reading the network they look after = %d, want 200", mine.StatusCode)
	}

	theirs := h.withCookie(http.MethodGet, "/api/v1/networks/"+other.String()+"/devices", cookie)
	_ = theirs.Body.Close()
	if theirs.StatusCode != http.StatusForbidden {
		t.Errorf("reading the network next door = %d, want 403", theirs.StatusCode)
	}

	// And the organisation-wide act their role would allow if it were not narrowed.
	users := h.withCookie(http.MethodGet, "/api/v1/organizations/"+org.String()+"/users", cookie)
	_ = users.Body.Close()
	if users.StatusCode != http.StatusForbidden {
		t.Errorf("listing the organisation's people = %d, want 403 — a grant narrowed to one "+
			"network must not reach the organisation", users.StatusCode)
	}
}

// Revoking a role takes effect on the next request, not on the next sign-in.
//
// This is the reason permissions are read per request rather than resolved once and carried
// in the session. Getting it wrong leaves somebody who has just been demoted holding their
// old powers for as long as they keep their browser open, which on a laptop that has been
// left somewhere is exactly as long as it matters.
func TestARevokedRoleStopsWorkingImmediately(t *testing.T) {
	h := newHarness(t)
	org := orgOf(t, h)

	person := createUser(t, h, "person@example.com")
	takeAwayEveryRole(t, h, person)
	grantRole(t, h, person, map[string]any{"role": authz.RoleAdministrator})

	cookie := signIn(t, h, "person@example.com", testPassword)

	before := h.withCookie(http.MethodGet, "/api/v1/networks/"+h.netID.String()+"/devices", cookie)
	_ = before.Body.Close()
	if before.StatusCode != http.StatusOK {
		t.Fatalf("before the demotion = %d, want 200", before.StatusCode)
	}

	// Same cookie, same session, no sign-out.
	status, _, body := doJSON(t, http.MethodGet,
		h.server.URL+"/api/v1/organizations/"+org.String()+"/users/"+person.String()+"/roles",
		nil, nil, true)
	if status != http.StatusOK {
		t.Fatalf("listing their roles = %d: %v", status, body)
	}
	held, _ := body["roles"].([]any)
	if len(held) != 1 {
		t.Fatalf("they hold %d roles, want 1", len(held))
	}
	bindingID := held[0].(map[string]any)["binding_id"].(string)

	status, _, body = doJSON(t, http.MethodDelete,
		h.server.URL+"/api/v1/organizations/"+org.String()+"/users/"+person.String()+"/roles/"+bindingID,
		nil, nil, true)
	if status != http.StatusNoContent {
		t.Fatalf("revoking = %d: %v", status, body)
	}

	after := h.withCookie(http.MethodGet, "/api/v1/networks/"+h.netID.String()+"/devices", cookie)
	_ = after.Body.Close()
	if after.StatusCode != http.StatusForbidden {
		t.Errorf("after the demotion, with the same session = %d, want 403", after.StatusCode)
	}
}

// Somebody with no role at all is told what is actually wrong. "You may not do this" and
// "you hold nothing here" need different things done about them, and a person who has just
// been given an account and no role gets the second.
func TestSomebodyWithNoRoleIsToldSo(t *testing.T) {
	h := newHarness(t)
	person := createUser(t, h, "nobody@example.com")
	takeAwayEveryRole(t, h, person)

	cookie := signIn(t, h, "nobody@example.com", testPassword)
	status, _, body := doJSONWithCookie(t, h, http.MethodGet,
		"/api/v1/networks/"+h.netID.String()+"/devices", cookie)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", status)
	}
	if message, _ := body["message"].(string); !strings.Contains(message, "no role") {
		t.Errorf("message = %q, want it to say they hold no role", message)
	}
}

// An administrator configures networks and does not decide who may act. That line is the
// whole reason the two are different roles, so it is asserted over HTTP rather than only in
// the role definitions.
func TestAnAdministratorCannotGrantRoles(t *testing.T) {
	h := newHarness(t)
	org := orgOf(t, h)

	admin := createUser(t, h, "admin@example.com")
	takeAwayEveryRole(t, h, admin)
	grantRole(t, h, admin, map[string]any{"role": authz.RoleAdministrator})
	cookie := signIn(t, h, "admin@example.com", testPassword)

	// They can publish a policy.
	status, _, _ := doJSONWithBody(t, h, http.MethodPut,
		"/api/v1/networks/"+h.netID.String()+"/acl",
		map[string]any{"version": 1, "rules": []any{}}, cookie)
	if status != http.StatusOK && status != http.StatusCreated {
		t.Errorf("an administrator publishing a policy = %d", status)
	}

	// They cannot make somebody an owner.
	status, _, _ = doJSONWithBody(t, h, http.MethodPost,
		"/api/v1/organizations/"+org.String()+"/users/"+admin.String()+"/roles",
		map[string]any{"role": authz.RoleOwner}, cookie)
	if status != http.StatusForbidden {
		t.Errorf("an administrator granting themselves owner = %d, want 403", status)
	}
}

// The catalogue is served, because a consumer choosing what a role should hold is choosing
// from it and a list nobody can enumerate has to be read out of the source.
func TestThePermissionCatalogueIsServed(t *testing.T) {
	h := newHarness(t)
	status, _, body := doJSON(t, http.MethodGet, h.server.URL+"/api/v1/permissions", nil, nil, true)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	entries, _ := body["permissions"].([]any)
	if len(entries) != len(authz.Catalogue) {
		t.Fatalf("%d permissions served, want %d", len(entries), len(authz.Catalogue))
	}
	first, _ := entries[0].(map[string]any)
	for _, key := range []string{"permission", "description", "scope"} {
		if first[key] == "" || first[key] == nil {
			t.Errorf("a catalogue entry has no %s: %v", key, first)
		}
	}
}

// --- helpers ----------------------------------------------------------------

// secondNetwork is another network in the same organisation, so "the network next door" is
// a real thing to be refused rather than a UUID that does not exist.
func (h *harness) secondNetwork(t *testing.T) uuid.UUID {
	t.Helper()
	org := orgOf(t, h)
	var id uuid.UUID
	if err := h.store.Pool().QueryRow(h.ctx,
		`INSERT INTO networks (organization_id, slug, name) VALUES ($1,'branch','Branch') RETURNING id`,
		org).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// takeAwayEveryRole leaves an account with nothing, so a test can grant exactly what it
// means to test rather than testing the default on top of it.
func takeAwayEveryRole(t *testing.T, h *harness, user uuid.UUID) {
	t.Helper()
	if _, err := h.store.Pool().Exec(h.ctx,
		`DELETE FROM role_bindings WHERE user_id = $1`, user); err != nil {
		t.Fatal(err)
	}
}

func grantRole(t *testing.T, h *harness, user uuid.UUID, body map[string]any) {
	t.Helper()
	org := orgOf(t, h)
	status, _, out := doJSON(t, http.MethodPost,
		h.server.URL+"/api/v1/organizations/"+org.String()+"/users/"+user.String()+"/roles",
		body, nil, true)
	if status != http.StatusCreated {
		t.Fatalf("granting %v = %d: %v", body, status, out)
	}
}

func doJSONWithCookie(t *testing.T, h *harness, method, path string, cookie *http.Cookie) (int, []*http.Cookie, map[string]any) {
	t.Helper()
	return doJSON(t, method, h.server.URL+path, nil, cookie, false)
}

func doJSONWithBody(t *testing.T, h *harness, method, path string, body any, cookie *http.Cookie) (int, []*http.Cookie, map[string]any) {
	t.Helper()
	return doJSON(t, method, h.server.URL+path, body, cookie, false)
}
