package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/meshpnet/meshp/internal/cliapi"
)

// session is a browser-shaped session, held for the length of one command.
//
// It exists only so that a token can be minted: POST /api/v1/me/tokens needs somebody signed
// in, and signing in needs a password. What is kept afterwards is the token (ADR-0031 §1).
type session struct {
	client *cliapi.Client
	cookie string
}

// openSession signs in with an email address and a password.
func openSession(ctx context.Context, client *cliapi.Client, email, password string) (*session, error) {
	cookie, err := client.OpenSession(ctx, email, password)
	if err != nil {
		var apiErr *cliapi.Error
		if errors.As(err, &apiErr) && apiErr.Code == "ambiguous_sign_in" {
			// The server asks for an organisation only when the address is in more than
			// one. Passed on as it said it, because it knows which and this does not.
			return nil, fmt.Errorf("%s; use --organisation", apiErr.Message)
		}
		return nil, err
	}
	return &session{client: client, cookie: cookie}, nil
}

// mintedToken is what the control plane hands back once, and never again.
type mintedToken struct {
	ID    string
	Name  string
	Token string
}

// permissions is everything this control plane can express.
//
// Asked for rather than guessed at, and asked of the server rather than compiled in: a CLI
// carrying its own copy of the catalogue would grant nothing new on a control plane that had
// learned a permission, and would fail outright on one that had dropped it.
func (s *session) permissions(ctx context.Context) ([]string, error) {
	var out struct {
		Permissions []struct {
			Permission string `json:"permission"`
		} `json:"permissions"`
	}
	if err := s.client.DoWithCookie(ctx, http.MethodGet, "/api/v1/permissions", s.cookie, nil, &out); err != nil {
		return nil, fmt.Errorf("reading what this control plane can grant: %w", err)
	}
	names := make([]string, 0, len(out.Permissions))
	for _, p := range out.Permissions {
		names = append(names, p.Permission)
	}
	if len(names) == 0 {
		return nil, errors.New("the control plane lists no permissions, so a token could do nothing")
	}
	return names, nil
}

// mintToken creates the API token this machine will keep.
//
// Scoped to the whole catalogue, which is not the same as unlimited: the control plane
// intersects a token's scope with what its owner may do, per request, so this asks for
// everything and receives what the person actually has. A CLI that could do less than the
// person driving it is one they will work around (ADR-0031).
func (s *session) mintToken(ctx context.Context, name string) (mintedToken, error) {
	scope, err := s.permissions(ctx)
	if err != nil {
		return mintedToken{}, err
	}
	body := map[string]any{"name": name, "permissions": scope}
	var out struct {
		// token_id, not id. Read from the field the control plane actually sends: an
		// unmarshal into the wrong name is not an error, it is an empty string — and an
		// empty id is a token this machine holds and can never revoke, which is most of
		// what ADR-0031 chose a token for.
		ID    string `json:"token_id"`
		Name  string `json:"name"`
		Token string `json:"token"`
	}
	if err = s.client.DoWithCookie(ctx, http.MethodPost, "/api/v1/me/tokens", s.cookie, body, &out); err != nil {
		var apiErr *cliapi.Error
		if errors.As(err, &apiErr) && apiErr.Code == "token_name_taken" {
			// Signing in again from a machine that already has a token is ordinary: a
			// token expired, or a logout could not reach the control plane. Names are
			// unique per person, so the old one is taken away and replaced rather than
			// leaving somebody to pick a name they do not care about.
			if err := s.replaceToken(ctx, name); err != nil {
				return mintedToken{}, err
			}
			if err := s.client.DoWithCookie(ctx, http.MethodPost, "/api/v1/me/tokens", s.cookie, body, &out); err != nil {
				return mintedToken{}, fmt.Errorf("minting a token: %w", err)
			}
		} else {
			return mintedToken{}, fmt.Errorf("minting a token: %w", err)
		}
	}
	if out.Token == "" {
		return mintedToken{}, errors.New("the control plane minted a token and did not return it")
	}
	if out.ID == "" {
		// Refused rather than stored. A token with no id can be used and never revoked
		// from here, and somebody would find that out at the moment they most wanted to
		// revoke it.
		return mintedToken{}, errors.New(
			"the control plane minted a token and did not say which one, so it could never be revoked")
	}
	return mintedToken{ID: out.ID, Name: out.Name, Token: out.Token}, nil
}

// close ends the session. Best effort: the token is already minted and stored by the time
// this runs, and a session left to expire is a smaller problem than a command that reports
// failure after doing what was asked.
func (s *session) close(ctx context.Context) error {
	return s.client.DoWithCookie(ctx, http.MethodDelete, "/api/v1/ui/session", s.cookie, nil, nil)
}

// replaceToken revokes the token this machine minted before, so a fresh one can take its name.
//
// Revoked rather than reused: the secret is shown once and is not stored anywhere this can
// read it, so an existing token by this name is one nothing holds. Leaving it would be a valid
// credential nobody has, which is worse than one more entry in the audit trail.
func (s *session) replaceToken(ctx context.Context, name string) error {
	var out struct {
		Tokens []struct {
			ID   string `json:"token_id"`
			Name string `json:"name"`
		} `json:"tokens"`
	}
	if err := s.client.DoWithCookie(ctx, http.MethodGet, "/api/v1/me/tokens", s.cookie, nil, &out); err != nil {
		return fmt.Errorf("listing your tokens to replace the one named %q: %w", name, err)
	}
	for _, token := range out.Tokens {
		if token.Name != name {
			continue
		}
		if err := s.client.DoWithCookie(ctx, http.MethodDelete,
			"/api/v1/me/tokens/"+token.ID, s.cookie, nil, nil); err != nil {
			return fmt.Errorf("revoking the previous token named %q: %w", name, err)
		}
		return nil
	}
	// The name is taken and nothing by that name is listed. Not something to work around by
	// inventing another name: it means this and the control plane disagree about what
	// exists, and choosing a different name would leave the disagreement in place.
	return fmt.Errorf("the control plane says %q is taken and does not list it", name)
}

// revokeToken takes a token away, as the person who owns it.
func (s *session) revokeToken(ctx context.Context, id string) error {
	return s.client.DoWithCookie(ctx, http.MethodDelete, "/api/v1/me/tokens/"+id, s.cookie, nil, nil)
}
