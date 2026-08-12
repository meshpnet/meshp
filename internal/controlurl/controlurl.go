// Package controlurl validates the address of a control plane.
//
// It exists because of what a control URL is trusted with. `meshp join` sends an
// enrolment token to whatever address it is given, and the agent then holds a session
// there. A URL pasted from the wrong place — a message, a wiki, a screenshot — hands a
// working token to somebody else. The token is single-use and short-lived, which limits
// the damage but does not remove it.
//
// CodeQL reports the requests these URLs feed as go/request-forgery. That model is about
// a server fetching an address an attacker supplied, which lets the attacker reach
// services only the server can see. This is the other shape: a client reaching an address
// its own operator configured, where the operator could equally have run curl. The
// escalation the rule is looking for is not available here.
//
// The rule still points at something real, which is that nothing was checked at all. So
// this narrows what a control URL may be, and the reason to do it is the pasted-URL
// mistake rather than the reported one.
package controlurl

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrInvalid means the string is not usable as a control-plane address.
var ErrInvalid = errors.New("controlurl: not a usable control plane address")

// Validate checks a control URL and returns it normalised, without a trailing slash.
func Validate(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("%w: it is empty", ErrInvalid)
	}

	// Checked on the raw string, before parsing, because url.Parse reads
	// "control.example:8080" as the scheme "control.example" with the opaque part "8080".
	// Reporting that as an unsupported scheme is technically what happened and useless to
	// whoever typed a host and a port, which is a very likely thing to type.
	if !strings.Contains(trimmed, "://") {
		return "", fmt.Errorf("%w: %q has no scheme; write http:// or https://", ErrInvalid, trimmed)
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalid, err)
	}

	switch parsed.Scheme {
	case "http", "https":
	default:
		// Guessing http for anything else would silently send an enrolment token in the
		// clear, so it is refused rather than assumed.
		return "", fmt.Errorf("%w: scheme %q is not supported; use http or https", ErrInvalid, parsed.Scheme)
	}

	if parsed.Host == "" {
		return "", fmt.Errorf("%w: %q names no host", ErrInvalid, trimmed)
	}

	// Embedded credentials are a phishing shape: in http://control.example@evil.test the
	// host is evil.test, and a reader's eye stops at the first name it recognises.
	if parsed.User != nil {
		return "", fmt.Errorf("%w: it must not contain credentials", ErrInvalid)
	}

	// A control URL is a base that paths are appended to, so anything after the host is
	// either a mistake or an attempt to make the resulting request point somewhere else.
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%w: it must not carry a query or fragment", ErrInvalid)
	}
	if path := strings.Trim(parsed.Path, "/"); path != "" {
		return "", fmt.Errorf("%w: it must be a scheme and host only, with no path (%q)", ErrInvalid, parsed.Path)
	}

	// Rebuilt from the parsed parts rather than trimmed from the input, so what is
	// returned is exactly what was validated.
	return parsed.Scheme + "://" + parsed.Host, nil
}

// MustValidate is Validate for constants in tests and defaults.
func MustValidate(raw string) string {
	out, err := Validate(raw)
	if err != nil {
		panic(err)
	}
	return out
}
