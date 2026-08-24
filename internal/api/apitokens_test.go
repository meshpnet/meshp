package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/meshpnet/meshp/internal/authz"
)

// withToken makes a request as a machine holding an API token.
func (h *harness) withToken(method, path, token string, body any) (int, map[string]any) {
	h.t.Helper()
	var reader io.Reader = bytes.NewReader([]byte("{}"))
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, h.server.URL+path, reader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	out := map[string]any{}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// mintToken asks for a credential as a signed-in person and returns its secret and id.
func mintAPIToken(t *testing.T, h *harness, cookie *http.Cookie, body map[string]any) (string, string) {
	t.Helper()
	status, _, out := doJSONWithBody(t, h, http.MethodPost, "/api/v1/me/tokens", body, cookie)
	if status != http.StatusCreated {
		t.Fatalf("minting %v = %d: %v", body, status, out)
	}
	secret, _ := out["token"].(string)
	id, _ := out["token_id"].(string)
	if secret == "" || id == "" {
		t.Fatalf("minting returned no token: %v", out)
	}
	return secret, id
}

// The whole story ADR-0024 §2 asks for: a machine mints a credential scoped to reads, uses
// it, has it revoked, and finds its owner in the audit trail.
func TestAMachineCanAuthenticateAsItself(t *testing.T) {
	h := newHarness(t)
	createUser(t, h, "alice@example.com")
	cookie := signIn(t, h, "alice@example.com", testPassword)

	secret, tokenID := mintAPIToken(t, h, cookie, map[string]any{
		"name":        "the-commercial-layer",
		"permissions": []string{string(authz.NetworkRead), string(authz.OrganizationNetworksRead)},
	})
	if !strings.HasPrefix(secret, "meshp_api_") {
		t.Errorf("token %q does not carry a recognisable prefix", secret)
	}

	// It reads.
	if status, _ := h.withToken(http.MethodGet, "/api/v1/networks", secret, nil); status != http.StatusOK {
		t.Errorf("a token scoped to reads listing networks = %d, want 200", status)
	}
	if status, _ := h.withToken(http.MethodGet,
		"/api/v1/networks/"+h.netID.String()+"/overview", secret, nil); status != http.StatusOK {
		t.Errorf("a token scoped to reads reading an overview = %d, want 200", status)
	}

	// It knows what it is, which is the first thing a machine asks.
	status, me := h.withToken(http.MethodGet, "/api/v1/me", secret, nil)
	if status != http.StatusOK {
		t.Fatalf("a token asking who it is = %d", status)
	}
	if me["kind"] != "api_token" || me["owner"] != "alice@example.com" {
		t.Errorf("/api/v1/me for a token = %v, want it to name itself and its owner", me)
	}

	// It is revoked, and stops.
	status, _, body := doJSONWithCookie(t, h, http.MethodDelete, "/api/v1/me/tokens/"+tokenID, cookie)
	if status != http.StatusNoContent {
		t.Fatalf("revoking = %d: %v", status, body)
	}
	if status, _ := h.withToken(http.MethodGet, "/api/v1/networks", secret, nil); status != http.StatusUnauthorized {
		t.Errorf("a revoked token = %d, want 401", status)
	}

	// And the trail names the person at the end of the machine.
	var kind, label string
	if err := h.store.Pool().QueryRow(h.ctx,
		`SELECT actor_kind, actor_label FROM audit_events
		 WHERE action = 'api_token.minted' ORDER BY id DESC LIMIT 1`).Scan(&kind, &label); err != nil {
		t.Fatal(err)
	}
	if kind != "user" || label != "alice@example.com" {
		t.Errorf("minting was recorded as %s/%q, want the person who did it", kind, label)
	}
}

// A token scoped to reads cannot write, even though its owner can. The scope is a ceiling,
// and this is what makes minting a narrow credential worth doing.
func TestATokenScopedToReadsCannotWrite(t *testing.T) {
	h := newHarness(t)
	createUser(t, h, "alice@example.com")
	cookie := signIn(t, h, "alice@example.com", testPassword)

	secret, _ := mintAPIToken(t, h, cookie, map[string]any{
		"name":        "watcher",
		"permissions": []string{string(authz.NetworkRead), string(authz.NetworkACLRead)},
	})

	// The owner is an owner and can publish a policy.
	status, _, _ := doJSONWithBody(t, h, http.MethodPut,
		"/api/v1/networks/"+h.netID.String()+"/acl",
		map[string]any{"version": 1, "rules": []any{}}, cookie)
	if status != http.StatusOK && status != http.StatusCreated {
		t.Fatalf("the owner publishing a policy = %d", status)
	}

	// Their token cannot.
	status, body := h.withToken(http.MethodPut, "/api/v1/networks/"+h.netID.String()+"/acl",
		secret, map[string]any{"version": 1, "rules": []any{}})
	if status != http.StatusForbidden {
		t.Errorf("a token scoped to reads publishing a policy = %d, want 403", status)
	}
	if message, _ := body["message"].(string); !strings.Contains(message, string(authz.NetworkACLWrite)) {
		t.Errorf("message = %q, want it to name the permission that was missing", message)
	}
}

// A token cannot mint a token. Otherwise a leaked credential could produce a fresh one on
// the way out and survive its own revocation, which is the property revoking is for.
func TestATokenCannotMintATokenOrChangeAPassword(t *testing.T) {
	h := newHarness(t)
	createUser(t, h, "alice@example.com")
	cookie := signIn(t, h, "alice@example.com", testPassword)

	// Minted with every permission its owner has, so what stops it is not the scope.
	perms := make([]string, 0, len(authz.Catalogue))
	for _, e := range authz.Catalogue {
		perms = append(perms, string(e.Name))
	}
	secret, _ := mintAPIToken(t, h, cookie, map[string]any{"name": "powerful", "permissions": perms})

	status, body := h.withToken(http.MethodPost, "/api/v1/me/tokens", secret,
		map[string]any{"name": "child", "permissions": []string{string(authz.NetworkRead)}})
	if status != http.StatusForbidden {
		t.Errorf("a token minting a token = %d, want 403", status)
	}
	if code, _ := body["error"].(string); code != "person_required" {
		t.Errorf("error = %q, want person_required", code)
	}

	status, _ = h.withToken(http.MethodPost, "/api/v1/me/password", secret,
		map[string]any{"current_password": testPassword, "new_password": "another long enough passphrase"})
	if status != http.StatusForbidden {
		t.Errorf("a token changing its owner's password = %d, want 403", status)
	}

	// The password really did not change, which is the part that would matter.
	if signIn(t, h, "alice@example.com", testPassword) == nil {
		t.Error("the owner can no longer sign in with their password")
	}
}

// A token narrowed to one network is refused on another, the same way a role binding is.
func TestATokenNarrowedToOneNetworkIsRefusedOnAnother(t *testing.T) {
	h := newHarness(t)
	other := h.secondNetwork(t)
	createUser(t, h, "alice@example.com")
	cookie := signIn(t, h, "alice@example.com", testPassword)

	secret, _ := mintAPIToken(t, h, cookie, map[string]any{
		"name":        "hq-only",
		"permissions": []string{string(authz.NetworkRead)},
		"network_id":  h.netID.String(),
	})

	if status, _ := h.withToken(http.MethodGet,
		"/api/v1/networks/"+h.netID.String()+"/overview", secret, nil); status != http.StatusOK {
		t.Errorf("reading the network it was minted for = %d, want 200", status)
	}
	if status, _ := h.withToken(http.MethodGet,
		"/api/v1/networks/"+other.String()+"/overview", secret, nil); status != http.StatusForbidden {
		t.Errorf("reading another network = %d, want 403", status)
	}
}

// An owner can see and revoke a colleague's credentials, which is what somebody needs when a
// person leaves. An administrator cannot: a token is an actor, and deciding who may act is
// the line between the two roles.
func TestRevokingSomebodyElsesTokenNeedsAnOwner(t *testing.T) {
	h := newHarness(t)
	org := orgOf(t, h)

	createUser(t, h, "alice@example.com")
	ownerCookie := signIn(t, h, "alice@example.com", testPassword)
	_, tokenID := mintAPIToken(t, h, ownerCookie, map[string]any{
		"name": "alices", "permissions": []string{string(authz.NetworkRead)},
	})

	admin := createUser(t, h, "admin@example.com")
	takeAwayEveryRole(t, h, admin)
	grantRole(t, h, admin, map[string]any{"role": authz.RoleAdministrator})
	adminCookie := signIn(t, h, "admin@example.com", testPassword)

	// An administrator can see the list — knowing what credentials exist is a read.
	status, _, body := doJSONWithCookie(t, h, http.MethodGet,
		"/api/v1/organizations/"+org.String()+"/tokens", adminCookie)
	if status != http.StatusOK {
		t.Fatalf("an administrator listing tokens = %d: %v", status, body)
	}
	tokens, _ := body["tokens"].([]any)
	if len(tokens) != 1 {
		t.Fatalf("%d tokens listed, want 1", len(tokens))
	}
	if first, _ := tokens[0].(map[string]any); first["owner"] != "alice@example.com" {
		t.Errorf("the listing does not say whose the token is: %v", tokens[0])
	}

	// And cannot revoke it.
	status, _, _ = doJSONWithCookie(t, h, http.MethodDelete,
		"/api/v1/organizations/"+org.String()+"/tokens/"+tokenID, adminCookie)
	if status != http.StatusForbidden {
		t.Errorf("an administrator revoking a colleague's token = %d, want 403", status)
	}

	// The owner can.
	status, _, _ = doJSONWithCookie(t, h, http.MethodDelete,
		"/api/v1/organizations/"+org.String()+"/tokens/"+tokenID, ownerCookie)
	if status != http.StatusNoContent {
		t.Errorf("an owner revoking a colleague's token = %d, want 204", status)
	}
}

// The secret is returned once. A list that carried it would put every credential in every
// log line that ever captured a response.
func TestATokenSecretIsShownOnlyOnce(t *testing.T) {
	h := newHarness(t)
	createUser(t, h, "alice@example.com")
	cookie := signIn(t, h, "alice@example.com", testPassword)
	secret, _ := mintAPIToken(t, h, cookie, map[string]any{
		"name": "once", "permissions": []string{string(authz.NetworkRead)},
	})

	status, _, body := doJSONWithCookie(t, h, http.MethodGet, "/api/v1/me/tokens", cookie)
	if status != http.StatusOK {
		t.Fatalf("listing = %d", status)
	}
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), secret) {
		t.Error("the listing carries the token's secret")
	}
	if !strings.Contains(string(raw), "once") {
		t.Error("the listing does not carry the token's name, so nobody could prune it")
	}
}

// A token belongs to one organisation, as its owner does.
func TestATokenHoldsNothingInAnotherOrganisation(t *testing.T) {
	h := newHarness(t)
	createUser(t, h, "alice@example.com")
	cookie := signIn(t, h, "alice@example.com", testPassword)
	secret, _ := mintAPIToken(t, h, cookie, map[string]any{
		"name": "alices", "permissions": []string{string(authz.OrganizationUsersRead)},
	})

	status, _, body := doJSON(t, http.MethodPost, h.server.URL+"/api/v1/organizations",
		map[string]any{"slug": "globex", "name": "Globex"}, nil, true)
	if status != http.StatusCreated {
		t.Fatalf("creating a second organisation = %d: %v", status, body)
	}
	other, _ := body["organization_id"].(string)

	if status, _ := h.withToken(http.MethodGet,
		"/api/v1/organizations/"+other+"/users", secret, nil); status != http.StatusForbidden {
		t.Errorf("a token reading another organisation's people = %d, want 403", status)
	}
}

// A machine acting within its owner's organisation does not have to name it.
//
// Found by writing the quickstart rather than by reading the code: the route derives the
// organisation from the caller, and until now "the caller" meant a person. A token holding
// organization.networks.create was refused for not naming an organisation the guard had
// already scoped it to — a permission it could hold and could not use.
func TestATokenCreatesANetworkInItsOwnersOrganisation(t *testing.T) {
	h := newHarness(t)
	createUser(t, h, "alice@example.com")
	cookie := signIn(t, h, "alice@example.com", testPassword)
	secret, _ := mintAPIToken(t, h, cookie, map[string]any{
		"name":        "ci",
		"permissions": []string{string(authz.OrganizationNetworksCreate)},
	})

	status, body := h.withToken(http.MethodPost, "/api/v1/networks", secret, map[string]any{
		"slug": "branch", "name": "Branch", "address_pools": []string{"100.91.0.0/24"},
	})
	if status != http.StatusCreated {
		t.Fatalf("a token creating a network = %d: %v", status, body)
	}

	// And it landed in the owner's organisation rather than nowhere.
	var org string
	if err := h.store.Pool().QueryRow(h.ctx,
		`SELECT organization_id::text FROM networks WHERE slug = 'branch'`).Scan(&org); err != nil {
		t.Fatal(err)
	}
	if org != orgOf(t, h).String() {
		t.Errorf("the network landed in %s, want the owner's organisation", org)
	}
}
