package controlurl

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateAccepts(t *testing.T) {
	tests := []struct{ in, want string }{
		{"http://localhost:8080", "http://localhost:8080"},
		{"https://control.example", "https://control.example"},
		{"https://control.example:8443", "https://control.example:8443"},
		{"http://127.0.0.1:8099", "http://127.0.0.1:8099"},
		{"http://[::1]:8080", "http://[::1]:8080"},
		// A trailing slash is what a browser's address bar gives you.
		{"https://control.example/", "https://control.example"},
		{"  https://control.example  ", "https://control.example"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := Validate(tt.in)
			if err != nil {
				t.Fatalf("Validate(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("Validate(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestValidateRejects(t *testing.T) {
	tests := []struct {
		name, in, wantMention string
	}{
		{"empty", "", "empty"},
		{"whitespace only", "   ", "empty"},
		{"no scheme", "control.example:8080", "no scheme"},
		{"bare host", "control.example", "no scheme"},
		{"unsupported scheme", "ftp://control.example", "not supported"},
		{"file scheme", "file:///etc/passwd", "not supported"},
		{"no host", "http://", "no host"},
		// The phishing shape: the host here is evil.test, and a reader's eye stops at the
		// first name it recognises.
		{"embedded credentials", "http://control.example@evil.test", "credentials"},
		{"embedded user and password", "https://user:pass@evil.test", "credentials"},
		{"carries a query", "https://control.example?next=http://evil.test", "query"},
		{"carries a fragment", "https://control.example#x", "query"},
		{"carries a path", "https://control.example/api/v1", "no path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Validate(tt.in)
			if err == nil {
				t.Fatalf("Validate(%q) was accepted", tt.in)
			}
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("error = %v, want ErrInvalid", err)
			}
			// The message has to say what to do about it: whoever hits this is holding a
			// token and a terminal.
			if !strings.Contains(err.Error(), tt.wantMention) {
				t.Errorf("error %q does not mention %q", err, tt.wantMention)
			}
		})
	}
}

// A validated URL must survive a second pass unchanged, or normalising somewhere in the
// call chain would keep changing what was already checked.
func TestValidateIsIdempotent(t *testing.T) {
	for _, in := range []string{"http://localhost:8080", "https://control.example/", "http://[::1]:9"} {
		once, err := Validate(in)
		if err != nil {
			t.Fatal(err)
		}
		twice, err := Validate(once)
		if err != nil {
			t.Fatalf("Validate(%q) rejected its own output: %v", once, err)
		}
		if once != twice {
			t.Errorf("Validate is not idempotent: %q then %q", once, twice)
		}
	}
}

func TestMustValidatePanicsOnBadInput(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("MustValidate accepted an invalid URL")
		}
	}()
	MustValidate("not a url at all")
}

func FuzzValidate(f *testing.F) {
	f.Add("http://localhost:8080")
	f.Add("https://control.example@evil.test")
	f.Add("")
	f.Add("://")

	f.Fuzz(func(t *testing.T, in string) {
		out, err := Validate(in)
		if err != nil {
			return
		}
		// Whatever is accepted must be a plain scheme-and-host, because everything
		// downstream appends a path to it.
		if !strings.HasPrefix(out, "http://") && !strings.HasPrefix(out, "https://") {
			t.Fatalf("accepted %q and returned %q", in, out)
		}
		rest := strings.SplitN(strings.TrimPrefix(strings.TrimPrefix(out, "https://"), "http://"), "/", 2)
		if len(rest) > 1 && rest[1] != "" {
			t.Fatalf("accepted %q and returned something with a path: %q", in, out)
		}
		if strings.ContainsAny(out, "?#") {
			t.Fatalf("accepted %q and returned %q", in, out)
		}
		if strings.Contains(out, "@") {
			t.Fatalf("accepted %q and returned credentials: %q", in, out)
		}
	})
}

// Everything a control URL carries is worth stealing: an enrolment token grants a device a
// place in the network, and a session challenge and its signature are how a device proves
// who it is. Over plaintext to a remote host, all of it is readable in transit.
func TestPlaintextIsRefusedToRemoteHosts(t *testing.T) {
	for _, raw := range []string{
		"http://control.example",
		"http://control.example:8080",
		"http://203.0.113.10",
		"http://[2001:db8::1]:8080",
		// A name is not evidence, whatever it resolves to today.
		"http://localhost.evil.test",
	} {
		if _, err := Validate(raw); err == nil {
			t.Errorf("accepted plaintext to a remote host: %q", raw)
		}
	}
}

// Loopback is exempt: it cannot leave the machine, and it is what local development and an
// SSH tunnel to a control plane both look like. A rule that refused it would push people
// towards turning verification off entirely.
func TestPlaintextIsAllowedToThisMachine(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1:8080",
		"http://localhost:8080",
		"http://LOCALHOST:8080",
		"http://[::1]:8080",
		"http://127.5.5.5:8080",
	} {
		if _, err := Validate(raw); err != nil {
			t.Errorf("refused loopback %q: %v", raw, err)
		}
	}
}

// https is accepted everywhere, which is the point of the rule.
func TestHTTPSIsAcceptedAnywhere(t *testing.T) {
	for _, raw := range []string{
		"https://control.example",
		"https://control.example:8443",
		"https://203.0.113.10",
		"https://127.0.0.1:8443",
	} {
		if _, err := Validate(raw); err != nil {
			t.Errorf("refused %q: %v", raw, err)
		}
	}
}
