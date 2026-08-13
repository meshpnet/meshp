package tlsconf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeCert puts a self-signed certificate and key in a directory and returns their paths.
func writeCert(t *testing.T, host string) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: host},
		DNSNames:              []string{host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// No certificate is a condition, not a failure: a deployment behind a tunnel or behind
// something else terminating TLS is a legitimate way to run this.
func TestNoCertificateIsItsOwnAnswer(t *testing.T) {
	_, _, err := Config(Options{})
	if !errors.Is(err, ErrNoTLS) {
		t.Fatalf("error = %v, want ErrNoTLS", err)
	}
}

// The whole point: a server built from this actually completes a handshake.
func TestAConfiguredCertificateServesTLS(t *testing.T) {
	certPath, keyPath := writeCert(t, "control.example")

	cfg, wrap, err := Config(Options{CertFile: certPath, KeyFile: keyPath})
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if wrap != nil {
		t.Error("a file-based certificate asked for an ACME challenge handler")
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = cfg
	srv.StartTLS()
	defer srv.Close()

	// Verified against the certificate rather than skipped, so this proves the chain the
	// server presented is the one that was configured.
	pool := x509.NewCertPool()
	pem, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("the certificate did not parse")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    pool,
		ServerName: "control.example",
		MinVersion: tls.VersionTLS12,
	}}}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("the handshake failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		t.Errorf("negotiated %v, want at least TLS 1.2", resp.TLS)
	}
}

// A path that is wrong, or a key that does not match its certificate, must stop a
// deployment starting rather than surfacing as a handshake failure to the first agent that
// tries to enrol.
func TestABadCertificateIsRefusedAtStartup(t *testing.T) {
	certPath, keyPath := writeCert(t, "control.example")
	otherCert, _ := writeCert(t, "other.example")

	for _, tc := range []struct{ name, cert, key, wants string }{
		{"a missing file", filepath.Join(t.TempDir(), "nope.pem"), keyPath, "certificate"},
		{"a certificate with no key", certPath, "", "key file"},
		{"a key with no certificate", "", keyPath, "key file"},
		{"a key that does not match", otherCert, keyPath, "certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Config(Options{CertFile: tc.cert, KeyFile: tc.key})
			if err == nil {
				t.Fatal("accepted a certificate it cannot serve")
			}
			if errors.Is(err, ErrNoTLS) {
				t.Fatal("a broken certificate was reported as no certificate at all")
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("error %q does not mention %q", err, tc.wants)
			}
		})
	}
}

// Both configured means two people meant two different things, and picking one would
// silently ignore the other.
func TestFilesAndAutomaticCertificatesTogetherAreRefused(t *testing.T) {
	certPath, keyPath := writeCert(t, "control.example")
	_, _, err := Config(Options{
		CertFile: certPath, KeyFile: keyPath,
		ACMEDomains: []string{"control.example"}, ACMECacheDir: t.TempDir(),
	})
	if err == nil {
		t.Fatal("accepted both a certificate file and automatic certificates")
	}
}

// Without a cache, every restart asks the certificate authority again, and Let's Encrypt's
// rate limits are low enough that a crash loop exhausts a week's allowance in an afternoon.
func TestAutomaticCertificatesNeedACache(t *testing.T) {
	_, _, err := Config(Options{ACMEDomains: []string{"control.example"}})
	if err == nil {
		t.Fatal("accepted automatic certificates with nowhere to cache them")
	}
	if !strings.Contains(err.Error(), "rate limit") {
		t.Errorf("the error does not say why it matters: %v", err)
	}
}

func TestAutomaticCertificatesAreConfigured(t *testing.T) {
	cfg, wrap, err := Config(Options{
		ACMEDomains: []string{"control.example"}, ACMECacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if cfg.GetCertificate == nil {
		t.Error("no certificate source was installed")
	}
	if wrap == nil {
		t.Error("no challenge handler was returned, so port 80 would answer nothing")
	}
	// TLS-ALPN-01 needs this offered, and it is what lets a certificate be obtained
	// without anything listening on port 80 at all.
	if !containsProto(cfg.NextProtos, "acme-tls/1") {
		t.Errorf("NextProtos = %v, missing the ALPN challenge protocol", cfg.NextProtos)
	}
	if !containsProto(cfg.NextProtos, "http/1.1") {
		t.Errorf("NextProtos = %v: without http/1.1 the control channel's WebSocket upgrade "+
			"is unavailable", cfg.NextProtos)
	}
}

func TestADomainThatIsNotOneIsRefused(t *testing.T) {
	for _, bad := range []string{" ", "control.example/path"} {
		if _, _, err := Config(Options{
			ACMEDomains: []string{bad}, ACMECacheDir: t.TempDir(),
		}); err == nil {
			t.Errorf("accepted %q as a domain", bad)
		}
	}
}

// Without http/1.1 offered, a Go server negotiates h2 and the WebSocket upgrade the
// control channel depends on is not available over it.
func TestHTTP11IsAlwaysOffered(t *testing.T) {
	certPath, keyPath := writeCert(t, "control.example")
	cfg, _, err := Config(Options{CertFile: certPath, KeyFile: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	if !containsProto(cfg.NextProtos, "http/1.1") {
		t.Errorf("NextProtos = %v", cfg.NextProtos)
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want at least TLS 1.2", cfg.MinVersion)
	}
}

func containsProto(protos []string, want string) bool {
	for _, p := range protos {
		if p == want {
			return true
		}
	}
	return false
}
