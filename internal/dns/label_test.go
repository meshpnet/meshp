package dns

import "testing"

// The rule has to match the one the database enforces, because a label that gets past one
// and not the other is an enrolment that fails for a reason nobody can see.
func TestLabelsAreGuessable(t *testing.T) {
	for display, want := range map[string]string{
		"fileserver":            "fileserver",
		"FileServer":            "fileserver",
		"Dave's laptop (spare)": "dave-s-laptop-spare",
		"branch-router-2":       "branch-router-2",
		"  padded  ":            "padded",
		"a.b.c":                 "a-b-c",
		"---dashes---":          "dashes",
		"under_score":           "under-score",
		"héllo":                 "h-llo",
		"!!!":                   "",
		"":                      "",
		"-":                     "",
	} {
		if got := Label(display); got != want {
			t.Errorf("Label(%q) = %q, want %q", display, got, want)
		}
	}
}

// Whatever Label produces must be something DNS can carry, or the constraint rejects it and
// the enrolment fails.
func TestLabelAlwaysProducesAValidLabelOrNothing(t *testing.T) {
	for _, display := range []string{
		"fileserver", "Dave's laptop", "!!!", "", "----",
		"averyveryveryveryveryveryveryveryveryveryveryverylongdevicenamethatgoeson",
		"ends-with-punctuation!!!",
		"a" + string(make([]byte, 200)),
	} {
		got := Label(display)
		if got != "" && !ValidLabel(got) {
			t.Errorf("Label(%q) = %q, which is not a valid label", display, got)
		}
	}
}

// A long name that collides must still produce something the database will take.
func TestSuffixingStaysInsideTheLimit(t *testing.T) {
	long := Label(string(make([]byte, 0)) + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if len(long) != MaxLabel {
		t.Fatalf("setup: base is %d bytes, want %d", len(long), MaxLabel)
	}
	for _, n := range []int{2, 10, 100, 1000} {
		got := Suffixed(long, n)
		if !ValidLabel(got) {
			t.Errorf("Suffixed(%d) = %q, which is not a valid label", n, got)
		}
	}
	if got := Suffixed("short", 2); got != "short-2" {
		t.Errorf("Suffixed(short, 2) = %q", got)
	}
}

func TestValidLabelRejectsWhatDNSCannotCarry(t *testing.T) {
	for _, bad := range []string{
		"", "-leading", "trailing-", "Upper", "under_score", "has space", "dot.dot",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 65
	} {
		if ValidLabel(bad) {
			t.Errorf("ValidLabel(%q) = true", bad)
		}
	}
	for _, good := range []string{"a", "a-b", "fileserver", "x9", "branch-router-2"} {
		if !ValidLabel(good) {
			t.Errorf("ValidLabel(%q) = false", good)
		}
	}
}
