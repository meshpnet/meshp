package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/clock"
	"github.com/meshpnet/meshp/internal/enroll"
	"github.com/meshpnet/meshp/internal/enrollclient"
	"github.com/meshpnet/meshp/internal/keys"
	"github.com/meshpnet/meshp/internal/session"
	"github.com/meshpnet/meshp/internal/store"
	"github.com/meshpnet/meshp/internal/testdb"
	"github.com/meshpnet/meshp/migrations"
)

const testAdminToken = "an-administrative-token-long-enough"

type harness struct {
	t      *testing.T
	server *httptest.Server
	store  *store.Store
	clk    *clock.Fake
	netID  uuid.UUID
	ctx    context.Context
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	url := testdb.URL(t, "api")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)

	clk := clock.NewFake()
	st, err := store.Open(ctx, store.DefaultConfig(url), migrations.FS, nil)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(st.Close)

	rows, err := st.Pool().Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname='public'`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		names = append(names, n)
	}
	rows.Close()
	for _, n := range names {
		if _, err := st.Pool().Exec(ctx, `DROP TABLE IF EXISTS "`+n+`" CASCADE`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	var orgID, netID uuid.UUID
	if err := st.Pool().QueryRow(ctx,
		`INSERT INTO organizations (slug,name) VALUES ('acme','Acme') RETURNING id`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool().QueryRow(ctx,
		`INSERT INTO networks (organization_id,slug,name) VALUES ($1,'hq','HQ') RETURNING id`,
		orgID).Scan(&netID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool().Exec(ctx,
		`INSERT INTO address_pools (network_id,prefix,family,purpose)
		 VALUES ($1,'100.90.0.0/24',4,'device'), ($1,'fd7c::/120',6,'device')`, netID); err != nil {
		t.Fatal(err)
	}

	challenger, err := enroll.NewChallenger([]byte("api-test-master-secret-value"), enroll.DefaultChallengeTTL, clk)
	if err != nil {
		t.Fatal(err)
	}
	sessionServer, err := session.NewServer(st, session.NewHub(), session.Config{
		MasterSecret: []byte("api-test-master-secret-value"),
		Clock:        clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := New(st, enroll.NewService(st, challenger, clk, nil), sessionServer, Config{
		AdminToken: testAdminToken,
		Clock:      clk,
		// Generous, so tests about something else are not throttled. The limiter has
		// its own tests.
		EnrolRatePerSecond: 1000,
		EnrolBurst:         1000,
	})

	mux := http.NewServeMux()
	srv.Routes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	return &harness{t: t, server: ts, store: st, clk: clk, netID: netID, ctx: ctx}
}

// mintToken uses the administrative endpoint, the way an operator would.
func (h *harness) mintToken(maxUses int, expiresIn time.Duration) string {
	h.t.Helper()
	body, _ := json.Marshal(map[string]any{
		"max_uses":           maxUses,
		"expires_in_seconds": int64(expiresIn.Seconds()),
		"tags":               []string{"laptop"},
	})
	req, _ := http.NewRequest(http.MethodPost,
		h.server.URL+"/api/v1/networks/"+h.netID.String()+"/enrollment-tokens", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		h.t.Fatalf("minting a token returned %d", resp.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.t.Fatal(err)
	}
	return out.Token
}

func newDevice(t *testing.T) (keys.Identity, keys.WireGuardPair) {
	t.Helper()
	id, err := keys.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	wg, err := keys.NewWireGuardPair()
	if err != nil {
		t.Fatal(err)
	}
	return id, wg
}

// --- the gate, over HTTP ----------------------------------------------------

func TestJoinOverHTTP(t *testing.T) {
	h := newHarness(t)
	token := h.mintToken(1, time.Hour)
	id, wg := newDevice(t)

	// The same client the CLI uses, so this exercises the shipping code rather than
	// something that resembles it.
	res, err := enrollclient.New(h.server.URL, nil).Join(h.ctx, enrollclient.JoinRequest{
		Token: token, Identity: id, WireGuard: wg,
		Name: "test-laptop", Hostname: "test-host", OS: "linux", AgentVersion: "test",
	})
	if err != nil {
		t.Fatalf("Join: %v", err)
	}

	if res.DeviceID == uuid.Nil || res.MembershipID == uuid.Nil {
		t.Fatalf("no identifiers returned: %+v", res)
	}
	if res.AddressV4 == nil || res.AddressV6 == nil {
		t.Fatalf("no addresses returned: %+v", res)
	}
	if res.InterfaceName != "meshp0" {
		t.Errorf("interface = %q, want meshp0", res.InterfaceName)
	}
}

func TestReplayOverHTTPIsRefused(t *testing.T) {
	h := newHarness(t)
	token := h.mintToken(1, time.Hour)
	client := enrollclient.New(h.server.URL, nil)

	id1, wg1 := newDevice(t)
	if _, err := client.Join(h.ctx, enrollclient.JoinRequest{Token: token, Identity: id1, WireGuard: wg1}); err != nil {
		t.Fatalf("first join: %v", err)
	}

	id2, wg2 := newDevice(t)
	_, err := client.Join(h.ctx, enrollclient.JoinRequest{Token: token, Identity: id2, WireGuard: wg2})

	var apiErr *enrollclient.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want an APIError", err)
	}
	if apiErr.Status != http.StatusConflict || apiErr.Code != "token_exhausted" {
		t.Errorf("got %d/%s, want 409/token_exhausted", apiErr.Status, apiErr.Code)
	}
	// The message has to be usable by whoever is looking at a terminal.
	if !strings.Contains(apiErr.Message, "already been used") {
		t.Errorf("message = %q", apiErr.Message)
	}
}

// --- administrative access --------------------------------------------------

func TestAdminEndpointsRequireTheToken(t *testing.T) {
	h := newHarness(t)
	path := h.server.URL + "/api/v1/networks/" + h.netID.String() + "/enrollment-tokens"

	tests := []struct {
		name   string
		header string
		want   int
	}{
		{"no header at all", "", http.StatusUnauthorized},
		{"not a bearer", testAdminToken, http.StatusUnauthorized},
		{"wrong secret", "Bearer wrong-token-of-similar-length", http.StatusUnauthorized},
		{"a prefix of the real secret", "Bearer " + testAdminToken[:10], http.StatusUnauthorized},
		{"correct", "Bearer " + testAdminToken, http.StatusCreated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tt.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.want)
			}
		})
	}
}

// With no secret configured the administrative API must be off, not open. A control
// plane that mints enrolment tokens for anyone who asks is worse than one whose
// admin API is unavailable.
func TestAdminEndpointsAreClosedWhenUnconfigured(t *testing.T) {
	h := newHarness(t)
	challenger, _ := enroll.NewChallenger([]byte("api-test-master-secret-value"), 0, h.clk)
	open := New(h.store, enroll.NewService(h.store, challenger, h.clk, nil), nil, Config{Clock: h.clk})

	mux := http.NewServeMux()
	open.Routes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost,
		ts.URL+"/api/v1/networks/"+h.netID.String()+"/enrollment-tokens", strings.NewReader(`{}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

func TestMintedTokenIsNotReturnedAgain(t *testing.T) {
	h := newHarness(t)
	plaintext := h.mintToken(1, time.Hour)

	req, _ := http.NewRequest(http.MethodGet,
		h.server.URL+"/api/v1/networks/"+h.netID.String()+"/enrollment-tokens", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	body := new(bytes.Buffer)
	if _, err := body.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	// Only the hash is stored, so there is nothing to leak here — asserted rather
	// than assumed, because a future convenience field could reintroduce it.
	if strings.Contains(body.String(), plaintext) {
		t.Error("listing tokens returned the plaintext")
	}
	if strings.Contains(body.String(), enroll.TokenPrefix) {
		t.Error("listing tokens returned something token-shaped")
	}
}

func TestRevokeIsScopedToItsNetwork(t *testing.T) {
	h := newHarness(t)
	token := h.mintToken(1, time.Hour)

	// Find the token's id through the administrative listing.
	req, _ := http.NewRequest(http.MethodGet,
		h.server.URL+"/api/v1/networks/"+h.netID.String()+"/enrollment-tokens", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	resp, _ := http.DefaultClient.Do(req)
	var listed struct {
		Tokens []struct {
			ID uuid.UUID `json:"ID"`
		} `json:"tokens"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&listed)
	_ = resp.Body.Close()
	if len(listed.Tokens) != 1 {
		t.Fatalf("listed %d tokens", len(listed.Tokens))
	}
	tokenID := listed.Tokens[0].ID

	// A different network's id must not be able to revoke it.
	otherNetwork := uuid.New()
	del, _ := http.NewRequest(http.MethodDelete,
		h.server.URL+"/api/v1/networks/"+otherNetwork.String()+"/enrollment-tokens/"+tokenID.String(), nil)
	del.Header.Set("Authorization", "Bearer "+testAdminToken)
	resp2, err := http.DefaultClient.Do(del)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("cross-network revoke returned %d, want 404", resp2.StatusCode)
	}

	// The token still works, which is the point of the previous assertion.
	id, wg := newDevice(t)
	if _, err := enrollclient.New(h.server.URL, nil).Join(h.ctx,
		enrollclient.JoinRequest{Token: token, Identity: id, WireGuard: wg}); err != nil {
		t.Errorf("token stopped working after a rejected revoke: %v", err)
	}
}

// --- request handling -------------------------------------------------------

func TestUnknownFieldsAreRejected(t *testing.T) {
	h := newHarness(t)
	// A misspelled field that was silently ignored would produce an enrolment that
	// looks like it worked and behaves like it did not.
	resp, err := http.Post(h.server.URL+"/api/v1/enroll/challenge", "application/json",
		strings.NewReader(`{"token":"meshp_tok_x","identity_publickey":"AAA="}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestOversizedBodyIsRejected(t *testing.T) {
	h := newHarness(t)
	huge := `{"token":"` + strings.Repeat("a", 64<<10) + `"}`
	resp, err := http.Post(h.server.URL+"/api/v1/enroll/challenge", "application/json", strings.NewReader(huge))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 400 {
		t.Errorf("status = %d, want a refusal", resp.StatusCode)
	}
}

func TestTrailingGarbageIsRejected(t *testing.T) {
	h := newHarness(t)
	resp, err := http.Post(h.server.URL+"/api/v1/enroll/challenge", "application/json",
		strings.NewReader(`{"token":"meshp_tok_x"} {"token":"another"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestMalformedTokenIsRefusedWithoutTouchingTheDatabase(t *testing.T) {
	h := newHarness(t)
	resp, err := http.Post(h.server.URL+"/api/v1/enroll/challenge", "application/json",
		strings.NewReader(`{"token":"not-a-meshp-token","identity_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusBadRequest || body["error"] != "token_malformed" {
		t.Errorf("got %d/%s, want 400/token_malformed", resp.StatusCode, body["error"])
	}
}

// An unrecognised internal error must reach the client as nothing at all. Here the
// database is closed underneath a live server, which is the cheapest way to produce
// an error nobody has classified.
func TestInternalErrorsDoNotLeak(t *testing.T) {
	h := newHarness(t)
	token := h.mintToken(1, time.Hour)
	h.store.Close()

	id, wg := newDevice(t)
	_, err := enrollclient.New(h.server.URL, nil).Join(h.ctx,
		enrollclient.JoinRequest{Token: token, Identity: id, WireGuard: wg})

	var apiErr *enrollclient.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want an APIError", err)
	}
	if apiErr.Status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", apiErr.Status)
	}
	for _, leak := range []string{"pgx", "sql", "SELECT", "pool", "closed", "postgres"} {
		if strings.Contains(strings.ToLower(apiErr.Message), strings.ToLower(leak)) {
			t.Errorf("the 500 body mentions %q: %q", leak, apiErr.Message)
		}
	}
}

func TestBadNetworkIDIsRejected(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest(http.MethodPost,
		h.server.URL+"/api/v1/networks/not-a-uuid/enrollment-tokens", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestUnknownNetworkIsANotFound(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest(http.MethodPost,
		h.server.URL+"/api/v1/networks/"+uuid.New().String()+"/enrollment-tokens", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// --- small helpers shared by the tests in this package ----------------------

func newTestChallengerFor(t *testing.T, h *harness) (*enroll.Service, error) {
	t.Helper()
	ch, err := enroll.NewChallenger([]byte("api-test-master-secret-value"), enroll.DefaultChallengeTTL, h.clk)
	if err != nil {
		return nil, err
	}
	return enroll.NewService(h.store, ch, h.clk, nil), nil
}

func newTestServer(t *testing.T, h http.Handler) string {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts.URL
}

func stringReader(s string) *strings.Reader { return strings.NewReader(s) }

// --- session endpoints ------------------------------------------------------

// The session wiring is exercised end to end by scripts/e2e-enrol.sh with real
// binaries. These cover the api layer's own behaviour: what it accepts, what it
// refuses, and what it does when the control channel is not available.
func TestSessionChallengeEndpoint(t *testing.T) {
	h := newHarness(t)
	id, _ := newDevice(t)

	body, _ := json.Marshal(map[string]string{
		"identity_public_key": base64.StdEncoding.EncodeToString(id.Public),
		"membership_id":       uuid.New().String(),
	})
	resp, err := http.Post(h.server.URL+"/api/v1/session/challenge", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var out struct {
		Challenge string    `json:"challenge"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(out.Challenge)
	if err != nil {
		t.Fatalf("challenge is not base64: %v", err)
	}
	if len(raw) == 0 {
		t.Error("challenge is empty")
	}
	if out.ExpiresAt.IsZero() {
		t.Error("no expiry was returned, so a client cannot tell when to ask again")
	}
}

// Deliberately not an enumeration oracle: a challenge is issued for a membership id
// that does not exist, because refusing here would tell a caller which ids are real.
// The signature check at connect time is what decides.
func TestSessionChallengeDoesNotRevealWhetherAMembershipExists(t *testing.T) {
	h := newHarness(t)
	id, _ := newDevice(t)

	body, _ := json.Marshal(map[string]string{
		"identity_public_key": base64.StdEncoding.EncodeToString(id.Public),
		"membership_id":       uuid.New().String(),
	})
	resp, err := http.Post(h.server.URL+"/api/v1/session/challenge", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d for an unknown membership, want 200", resp.StatusCode)
	}
}

func TestSessionChallengeRejectsMalformedInput(t *testing.T) {
	h := newHarness(t)
	id, _ := newDevice(t)
	goodKey := base64.StdEncoding.EncodeToString(id.Public)

	tests := []struct{ name, body string }{
		{"empty object", `{}`},
		{"key is not base64", `{"identity_public_key":"!!!","membership_id":"` + uuid.New().String() + `"}`},
		{"membership is not a uuid", `{"identity_public_key":"` + goodKey + `","membership_id":"nope"}`},
		{"unknown field", `{"identity_public_key":"` + goodKey + `","membership":"x"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := http.Post(h.server.URL+"/api/v1/session/challenge", "application/json", strings.NewReader(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
		})
	}
}

// With no control channel configured, both session endpoints must say so rather than
// panic on a nil server.
func TestSessionEndpointsWhenTheChannelIsUnavailable(t *testing.T) {
	h := newHarness(t)
	challenger, _ := enroll.NewChallenger([]byte("api-test-master-secret-value"), 0, h.clk)
	without := New(h.store, enroll.NewService(h.store, challenger, h.clk, nil), nil, Config{Clock: h.clk})

	mux := http.NewServeMux()
	without.Routes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/session/challenge", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("challenge status = %d, want 503", resp.StatusCode)
	}

	upgrade, err := http.Get(ts.URL + "/api/v1/session")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upgrade.Body.Close() }()
	if upgrade.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("upgrade status = %d, want 503", upgrade.StatusCode)
	}
}

// A plain GET on the upgrade path is not a WebSocket handshake and must be refused
// rather than left hanging.
func TestSessionUpgradeRefusesAPlainRequest(t *testing.T) {
	h := newHarness(t)
	resp, err := http.Get(h.server.URL + "/api/v1/session")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 400 {
		t.Errorf("status = %d, want a refusal", resp.StatusCode)
	}
}
