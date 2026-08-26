// Package platformcheck holds one test: every package whose behaviour depends on the
// operating system is tested on macOS in CI, not only on Linux.
//
// It exists because CI reported a change as good when it was not. #156 makes `meshp doctor`
// stop recommending `systemctl` where there is no systemd, and it breaks a test that asserts
// the exact command reaches the screen — on macOS. Every job that runs cmd/meshp is on
// ubuntu-latest, so the failure was invisible, and a contributor was told their change
// passed.
//
// That is worse than no coverage: it teaches people to trust a signal that is not watching.
//
// The alternative to this test was a list of packages in the workflow and a comment asking
// the next person to keep it in step. #128 and the .env.example that prompted internal/
// envcheck are two records of how well that works. So the list is derived from the code:
// a package that starts branching on runtime.GOOS, or gains a file built for one platform,
// is a package this test starts requiring in the macOS job.
package platformcheck

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// repoRoot is where the module lives, from this package's directory.
const repoRoot = "../.."

// macOSJobPackages finds the packages a `go test` line runs.
//
// Read out of the workflow rather than duplicated here, because a copy would be one more
// thing to keep in step and this test exists because that does not work.
//
// Applied to the macOS job's block alone, which the first version of this got wrong: run
// against the whole file it also matched the Linux job, so internal/nftables and
// internal/pathprobe counted as covered on macOS while being tested only on Linux — the
// exact thing this is here to catch, satisfied by the thing it is checking against.
var macOSJobPackages = regexp.MustCompile(`go test ((?:\./[^\s]+/ )+)-count=1`)

// macOSJob is the block of the workflow belonging to the macOS job.
//
// By indentation, because that is what YAML gives us and pulling in a parser for one field
// would be a dependency for a test. A job ends where the next one at the same indentation
// begins.
func macOSJob(t *testing.T, workflow string) string {
	t.Helper()
	const header = "\n  dataplane-macos:\n"
	start := strings.Index(workflow, header)
	if start < 0 {
		t.Fatal("no dataplane-macos job in the workflow; if it was renamed, this test needs " +
			"to learn the new name rather than be deleted")
	}
	rest := workflow[start+len(header):]

	// The next line that starts a sibling job: two spaces, a name, a colon.
	nextJob := regexp.MustCompile(`(?m)^  [a-z][a-z0-9-]*:$`)
	if end := nextJob.FindStringIndex(rest); end != nil {
		return rest[:end[0]]
	}
	return rest
}

// platformSensitive reports the packages whose behaviour depends on the operating system.
//
// Two ways a package qualifies, and both are things a compiler already understands:
//
//   - it names runtime.GOOS, so it decides something at run time from the platform;
//   - it has a file built for one platform, by name or by build tag, so it decides
//     something at compile time.
//
// Test files count. A test that branches on the platform is a test whose result depends on
// where it ran, which is exactly what this is about.
func platformSensitive(t *testing.T) map[string]bool {
	t.Helper()

	platformFile := regexp.MustCompile(`_(darwin|windows|linux)(_test)?\.go$`)
	buildTag := regexp.MustCompile(`^//go:build.*\b(darwin|windows|linux)\b`)

	out := map[string]bool{}
	err := filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Neither ours nor built: generated protobuf carries build tags of its own,
			// and a worktree is a copy of the repository inside the repository.
			switch d.Name() {
			case ".git", ".claude", "node_modules", "gen", "bin", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		pkg := filepath.ToSlash(filepath.Dir(strings.TrimPrefix(path, repoRoot+"/")))
		if platformFile.MatchString(d.Name()) {
			out[pkg] = true
			return nil
		}

		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(line, "package ") {
				break
			}
			if buildTag.MatchString(line) {
				out[pkg] = true
				return nil
			}
		}
		if usesGOOS(path) {
			out[pkg] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repository: %v", err)
	}
	return out
}

// usesGOOS reports whether a file genuinely reads runtime.GOOS.
//
// Parsed rather than searched for as text, which the first version of this did — and which
// made this very package detect itself, because it names runtime.GOOS in a comment and in
// the sentence you are reading. A test that flags itself is one somebody silences with a
// special case, and a special case in the detection is how a guard stops guarding.
func usesGOOS(path string) bool {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		// Unparseable Go is somebody else's failure — the build, or a linter — and not
		// something for this test to have an opinion about.
		return false
	}

	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "GOOS" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "runtime" {
			found = true
			return false
		}
		return true
	})
	return found
}

// hasTests reports whether a package has any test files at all.
//
// A package that branches on the platform and has no tests is a real gap and a different
// one: there is nothing for a job to run, so naming it in the workflow would fail the job
// rather than test anything. Worth knowing about, and not this test's business.
func hasTests(t *testing.T, pkg string) bool {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(repoRoot, pkg))
	if err != nil {
		t.Fatalf("reading %s: %v", pkg, err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), "_test.go") {
			return true
		}
	}
	return false
}

func TestEveryPlatformSensitivePackageIsTestedOnMacOS(t *testing.T) {
	workflow, err := os.ReadFile(filepath.Join(repoRoot, ".github/workflows/ci.yml"))
	if err != nil {
		t.Fatalf("reading the workflow: %v", err)
	}

	// The macOS job runs the same package list twice, privileged and not. Either occurrence
	// answers the question; taking the union means a package named in only one of them
	// still counts, which is right — it ran somewhere on macOS.
	matches := macOSJobPackages.FindAllStringSubmatch(macOSJob(t, string(workflow)), -1)
	if len(matches) == 0 {
		t.Fatal("found no `go test ./pkg/ ... -count=1` line in the workflow; if the macOS " +
			"job changed shape, this test needs to learn the new one rather than be deleted")
	}
	tested := map[string]bool{}
	for _, match := range matches {
		for _, pkg := range strings.Fields(match[1]) {
			tested[strings.Trim(pkg, "./")] = true
		}
	}

	for pkg := range platformSensitive(t) {
		if !hasTests(t, pkg) {
			// Reported rather than passed over in silence. A package that decides something
			// from the platform and has nothing to run is a real gap; it is a different
			// one, and naming it in the workflow would fail the job rather than test
			// anything. Somebody reading this output should still know it exists.
			t.Logf("%s decides something from the operating system and has no tests at all", pkg)
			continue
		}
		if !tested[pkg] {
			t.Errorf("%s decides something from the operating system and is not run by the "+
				"macOS job in .github/workflows/ci.yml.\n"+
				"Add ./%s/ to both `go test` lines there, or explain here why it does not "+
				"need to run on macOS.", pkg, pkg)
		}
	}
}

// The detection is what this rests on, so it is checked against a package known to qualify
// and one known not to.
//
// Without this the test could pass by finding nothing — which is what it would do if the
// walk broke, and it would keep passing forever while watching nothing.
func TestTheDetectionFindsWhatItShould(t *testing.T) {
	found := platformSensitive(t)

	// Has _linux.go and _other.go files, so it decides at compile time.
	if !found["internal/wglink"] {
		t.Error("internal/wglink was not detected, so the walk is not finding platform files")
	}
	// Names runtime.GOOS, so it decides at run time.
	if !found["internal/version"] {
		t.Error("internal/version was not detected, so the walk is not finding runtime.GOOS")
	}
	// Neither. If this starts failing, either the package changed or the detection has
	// become too eager — both worth looking at rather than adjusting the expectation.
	if found["internal/authz"] {
		t.Error("internal/authz was detected as platform-sensitive, which it is not")
	}
}
