package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestStringIncludesBuildIdentity(t *testing.T) {
	got := String("meshpd")

	for _, want := range []string{"meshpd", Version(), Commit(), runtime.GOOS, runtime.Version()} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, missing %q", got, want)
		}
	}
}

func TestDefaultsAreNotEmpty(t *testing.T) {
	// An unstamped build must still identify itself. A binary that reports an
	// empty version is indistinguishable from a broken one in a bug report.
	if Version() == "" {
		t.Error("Version() is empty")
	}
	if Commit() == "" {
		t.Error("Commit() is empty")
	}
}
