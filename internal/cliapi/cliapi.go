// Package cliapi is the CLI's client for a control plane.
//
// Separate from internal/enrollclient and internal/sessionclient, which are the *device*
// talking about itself. This is a person administering a deployment, and the two carry
// different credentials for different reasons (ADR-0031).
package cliapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/meshpnet/meshp/internal/controlurl"
)

// Client talks to one control plane as one person.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// New returns a client for a control plane.
//
// The URL is validated here rather than trusted, so a mistyped address is reported by the
// command that was mistyped rather than as a connection failure later.
func New(baseURL, token string) (*Client, error) {
	validated, err := controlurl.Validate(baseURL)
	if err != nil {
		return nil, err
	}
	return &Client{
		baseURL: strings.TrimSuffix(validated, "/"),
		token:   token,
		// A person is waiting at a terminal. Long enough for a control plane under load,
		// short enough that a black-holed address does not look like a hang.
		http: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// Error is what the control plane said went wrong.
//
// Carries the status and the server's own code, so a caller can tell an expired credential
// from a network that has gone away without matching on prose.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("the control plane returned %d", e.Status)
}

// Unauthorised reports whether the credential was refused, which is the one failure with a
// specific answer: sign in again.
func (e *Error) Unauthorised() bool { return e.Status == http.StatusUnauthorized }

// Do makes one request, decoding a JSON response into out when out is not nil.
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("cliapi: encoding the request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("cliapi: building the request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	res, err := c.http.Do(req)
	if err != nil {
		// The browser's own wording describes the call this package made rather than what
		// went wrong, which is not what somebody watching a deployment needs.
		return fmt.Errorf("cannot reach %s: %w", c.baseURL, err)
	}
	defer func() { _ = res.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("cliapi: reading the response: %w", err)
	}

	if res.StatusCode >= 400 {
		apiErr := &Error{Status: res.StatusCode}
		var problem struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &problem) == nil {
			apiErr.Code, apiErr.Message = problem.Error, problem.Message
		}
		return apiErr
	}

	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("cliapi: the control plane's answer was not what this expected: %w", err)
	}
	return nil
}

// OpenSession signs in as a person and returns the session cookie.
//
// Used once, by `meshp login`, to reach the endpoint that mints a token. The cookie is never
// written down: a session has a sliding idle window and a fixed ceiling, so a CLI holding one
// would sign out during a long afternoon, and it carries a CSRF story that exists for browsers
// (ADR-0031).
func (c *Client) OpenSession(ctx context.Context, email, password string) (string, error) {
	body := map[string]string{"email": email, "password": password}
	encoded, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("cliapi: encoding the sign-in: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/ui/session",
		bytes.NewReader(encoded))
	if err != nil {
		return "", fmt.Errorf("cliapi: building the sign-in: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot reach %s: %w", c.baseURL, err)
	}
	defer func() { _ = res.Body.Close() }()

	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 400 {
		apiErr := &Error{Status: res.StatusCode}
		var problem struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &problem) == nil {
			apiErr.Code, apiErr.Message = problem.Error, problem.Message
		}
		return "", apiErr
	}

	for _, cookie := range res.Cookies() {
		if cookie.Value != "" {
			return cookie.Name + "=" + cookie.Value, nil
		}
	}
	return "", fmt.Errorf("cliapi: %s accepted the sign-in and set no session cookie", c.baseURL)
}

// DoWithCookie makes one request carrying a session cookie rather than a token.
//
// Only login uses this, and only to mint the token that replaces it. The Origin header is sent
// because the control plane requires one on an unsafe method authenticated by cookie — a
// defence written for browsers that a CLI has to satisfy anyway (ADR-0022 §5).
func (c *Client) DoWithCookie(ctx context.Context, method, path, cookie string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("cliapi: encoding the request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("cliapi: building the request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Origin", c.baseURL)

	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach %s: %w", c.baseURL, err)
	}
	defer func() { _ = res.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("cliapi: reading the response: %w", err)
	}
	if res.StatusCode >= 400 {
		apiErr := &Error{Status: res.StatusCode}
		var problem struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &problem) == nil {
			apiErr.Code, apiErr.Message = problem.Error, problem.Message
		}
		return apiErr
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("cliapi: the control plane's answer was not what this expected: %w", err)
	}
	return nil
}
