// Package envcheck holds one test: that .env.example only names settings the code reads.
//
// It exists because four keys in that file were read by nothing. An operator could set
// MESHP_RELAY_LISTEN_ADDR, watch the relay listen somewhere else, and have no way to find
// out why — the file is the documentation for how to configure this, and it was wrong.
//
// This is the same hazard ADR-0018 describes, in the place people look first: a setting
// that reaches nothing. A comment asking the next person to keep the file in step would
// have been ignored, so it is a test instead.
package envcheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// envName matches a MESHP_ setting wherever it appears.
var envName = regexp.MustCompile(`MESHP_[A-Z0-9_]+`)

// declared reads the names .env.example sets, ignoring the ones it only mentions in prose.
//
// A commented-out assignment counts as declared: it is there to be uncommented, so it is a
// promise like any other. A name inside a sentence does not.
func declared(t *testing.T, path string) map[string]struct{} {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]struct{}{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#"))
		name, _, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if envName.FindString(name) == name && name != "" {
			out[name] = struct{}{}
		}
	}
	return out
}

// read walks the Go source for names the binaries actually look up.
func read(t *testing.T, roots ...string) map[string]struct{} {
	t.Helper()
	out := map[string]struct{}{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			// Only quoted names: a MESHP_ mentioned in a comment is prose, not a lookup.
			for _, m := range regexp.MustCompile(`"MESHP_[A-Z0-9_]+"`).FindAllString(string(src), -1) {
				out[strings.Trim(m, `"`)] = struct{}{}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestEveryDocumentedSettingIsRead(t *testing.T) {
	root := filepath.Join("..", "..")
	want := read(t, filepath.Join(root, "cmd"), filepath.Join(root, "internal"))

	for name := range declared(t, filepath.Join(root, ".env.example")) {
		if _, ok := want[name]; !ok {
			t.Errorf("%s is set in .env.example and read by nothing: an operator can "+
				"configure it, see no effect, and have no way to find out why", name)
		}
	}
}

// The compose file is the other place a setting is promised, and `docker compose up` is
// the first impression of the project.
func TestEveryComposeSettingIsRead(t *testing.T) {
	root := filepath.Join("..", "..")
	want := read(t, filepath.Join(root, "cmd"), filepath.Join(root, "internal"))

	raw, err := os.ReadFile(filepath.Join(root, "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		name, _, ok := strings.Cut(trimmed, ":")
		if !ok || envName.FindString(name) != name {
			continue
		}
		if _, ok := want[name]; !ok {
			t.Errorf("docker-compose.yml passes %s to a container that reads no such "+
				"setting", name)
		}
	}
}
