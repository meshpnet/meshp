// Package tlsconf builds the TLS configuration a control plane serves with.
//
// Two ways to get a certificate, because the two kinds of operator want different things.
// Someone running this behind their own infrastructure has a certificate already and wants
// to point at it; someone standing up a control plane on a fresh host wants one to appear.
// Both are supported and neither is the default, because a control plane that guessed would
// either fetch a certificate nobody asked for or serve plaintext when TLS was intended.
package tlsconf

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

// Options are the ways to obtain a certificate. At most one may be set.
type Options struct {
	// CertFile and KeyFile are a certificate and its private key on disk.
	CertFile string
	KeyFile  string

	// ACMEDomains are the names to obtain a certificate for automatically. Requires the
	// host to be reachable on port 443 from the internet under those names.
	ACMEDomains []string

	// ACMECacheDir is where issued certificates are kept between restarts.
	//
	// Not optional when ACME is used. Without it every restart asks the certificate
	// authority again, and Let's Encrypt's rate limits are low enough that a crash loop
	// would exhaust a week's allowance in an afternoon and leave the deployment with no
	// certificate at all.
	ACMECacheDir string
}

// ErrNoTLS means no certificate was configured.
//
// A condition rather than a failure: a deployment reached only over a tunnel, or through
// something else that terminates TLS, is a legitimate way to run this. The caller decides
// what to do about it, and says so in its log, rather than this package guessing.
var ErrNoTLS = errors.New("tlsconf: no certificate is configured")

// Config builds a TLS configuration, or ErrNoTLS when none was asked for.
//
// The returned handler wrapper is nil except with ACME, where it is what answers the
// HTTP-01 challenge on port 80.
func Config(opts Options) (*tls.Config, func(http.Handler) http.Handler, error) {
	files := opts.CertFile != "" || opts.KeyFile != ""
	acme := len(opts.ACMEDomains) > 0

	switch {
	case files && acme:
		// Refused rather than ranked. Both were configured deliberately by somebody, and
		// picking one would silently ignore what the other person meant.
		return nil, nil, errors.New(
			"tlsconf: both a certificate file and automatic certificates were configured; choose one")

	case files:
		if opts.CertFile == "" || opts.KeyFile == "" {
			return nil, nil, errors.New("tlsconf: a certificate needs both a certificate and a key file")
		}
		// Loaded now rather than on the first connection. A path that is wrong, or a key
		// that does not match its certificate, should stop a deployment starting — not
		// surface as a handshake failure to the first agent that tries to enrol.
		cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("tlsconf: loading the certificate: %w", err)
		}
		cfg := baseConfig()
		cfg.Certificates = []tls.Certificate{cert}
		return cfg, nil, nil

	case acme:
		if opts.ACMECacheDir == "" {
			return nil, nil, errors.New(
				"tlsconf: automatic certificates need a cache directory, or every restart asks the " +
					"certificate authority again and a crash loop exhausts its rate limit")
		}
		if err := os.MkdirAll(opts.ACMECacheDir, 0o700); err != nil {
			return nil, nil, fmt.Errorf("tlsconf: preparing the certificate cache: %w", err)
		}
		for _, domain := range opts.ACMEDomains {
			if strings.TrimSpace(domain) == "" || strings.Contains(domain, "/") {
				return nil, nil, fmt.Errorf("tlsconf: %q is not a domain name", domain)
			}
		}

		manager := &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			// The host allowlist is what stops this becoming a certificate-issuing service
			// for whoever points a DNS name at it: without it, any name resolving here
			// makes the deployment ask a certificate authority on that name's behalf.
			HostPolicy: autocert.HostWhitelist(opts.ACMEDomains...),
			Cache:      autocert.DirCache(opts.ACMECacheDir),
		}
		cfg := baseConfig()
		cfg.GetCertificate = manager.GetCertificate
		// TLS-ALPN-01 needs this offered, and it is what lets a certificate be obtained
		// without anything listening on port 80.
		cfg.NextProtos = append(cfg.NextProtos, acmeALPNProto)
		return cfg, manager.HTTPHandler, nil

	default:
		return nil, nil, ErrNoTLS
	}
}

// acmeALPNProto is the protocol name the TLS-ALPN-01 challenge is answered under.
const acmeALPNProto = "acme-tls/1"

// baseConfig is what every certificate source shares.
func baseConfig() *tls.Config {
	return &tls.Config{
		// 1.2 is the floor rather than 1.3, because agents are the only clients and they
		// are all this codebase — but a self-hoster's reverse proxy or monitoring may not
		// be, and 1.2 with modern suites is not the weak link in anything here.
		MinVersion: tls.VersionTLS12,
		// http/1.1 explicitly alongside h2: without a list, a Go server negotiates h2 and
		// the WebSocket upgrade the control channel depends on is not available over it.
		NextProtos: []string{"h2", "http/1.1"},
	}
}
