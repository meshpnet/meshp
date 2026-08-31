// Package deploycheck holds one test: that the units in deploy/systemd can do what the
// binaries they start will actually try to do.
//
// It exists because they could not. The control plane's unit carried
// CAP_NET_BIND_SERVICE — put there so it could hold 443 and serve HTTPS — alongside
// ProtectSystem=strict, which leaves the whole filesystem read-only, and no StateDirectory.
// So a self-hoster following docs/self-hosting.md set MESHP_TLS_DOMAINS and got a control
// plane that bound 443 and then could not save the certificate it was issued.
//
// Nothing caught it because the two halves live in different files and neither is Go. The
// unit is data to the compiler and the default is a string in a flag call, and they were
// only ever checked against each other by somebody deploying. This is that person, once,
// written down.
package deploycheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/meshpnet/meshp/internal/tlsconf"
)

// unitDir is deploy/systemd, from this package.
const unitDir = "../../deploy/systemd"

// A certificate the control plane cannot save is worse than one it never asked for: autocert
// obtains a new one on every restart, and Let's Encrypt's rate limits are low enough that a
// crash loop exhausts a week's allowance in an afternoon.
func TestTheControlPlaneCanWriteTheCertificatesItObtains(t *testing.T) {
	unit := readUnit(t, "meshp-control.service")

	if !strings.Contains(unit, "ProtectSystem=strict") {
		// The hardening is what makes this a question at all. If it is ever relaxed, this
		// test is measuring nothing and should be reconsidered rather than left passing.
		t.Fatal("the unit no longer sets ProtectSystem=strict, so this test proves nothing")
	}

	writable := stateDirectories(unit)
	if len(writable) == 0 {
		t.Fatal("the unit declares no StateDirectory, so nothing under /var is writable and " +
			"an automatically obtained certificate cannot be saved")
	}

	if !underAny(tlsconf.DefaultCacheDir, writable) {
		t.Errorf("certificates default to %s, which is not inside any of the unit's writable "+
			"directories %v — the control plane will bind 443 and then fail to save what it "+
			"is issued", tlsconf.DefaultCacheDir, writable)
	}
}

// The two services are separate programs run by separate units, and systemd gives a
// StateDirectory to the user its unit names. One writing inside the other's directory works
// on a host running only one of them and breaks on a host running both — which is what a
// small self-hoster does, and what this project's own deployment does.
func TestTheControlPlaneDoesNotWriteIntoTheAgentsStateDirectory(t *testing.T) {
	agentState := stateDirFlag(t, readUnit(t, "meshpd.service"))

	if under(tlsconf.DefaultCacheDir, agentState) {
		t.Errorf("certificates default to %s, which is inside the agent's state directory %s; "+
			"a host running both services has one writing into the other's",
			tlsconf.DefaultCacheDir, agentState)
	}
}

func readUnit(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(unitDir, name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(raw)
}

// stateDirectories returns the absolute paths systemd will make writable.
//
// StateDirectory= names are relative to /var/lib and may be space-separated.
func stateDirectories(unit string) []string {
	var dirs []string
	for _, line := range directives(unit, "StateDirectory") {
		for _, name := range strings.Fields(line) {
			dirs = append(dirs, filepath.Join("/var/lib", name))
		}
	}
	return dirs
}

// stateDirFlag reads the --state-dir the agent's unit passes, which is the directory the
// agent owns whatever the binary's own default happens to be.
func stateDirFlag(t *testing.T, unit string) string {
	t.Helper()
	for _, line := range directives(unit, "ExecStart") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "--state-dir" && i+1 < len(fields) {
				return fields[i+1]
			}
		}
	}
	t.Fatal("the agent's unit no longer passes --state-dir, so this test cannot tell which " +
		"directory belongs to it")
	return ""
}

// directives returns the values of every occurrence of a key, ignoring comments.
func directives(unit, key string) []string {
	var out []string
	for _, line := range strings.Split(unit, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if value, ok := strings.CutPrefix(line, key+"="); ok {
			out = append(out, value)
		}
	}
	return out
}

// under reports whether path is dir or inside it. Compared as path elements, so
// /var/lib/meshp-control is not "inside" /var/lib/meshp.
func under(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

func underAny(path string, dirs []string) bool {
	for _, dir := range dirs {
		if under(path, dir) {
			return true
		}
	}
	return false
}
