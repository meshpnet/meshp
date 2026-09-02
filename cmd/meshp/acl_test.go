package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/meshpnet/meshp/internal/acl"
)

func TestDiffShowsOnlyWhatChanged(t *testing.T) {
	before := "a\nb\nc\n"
	after := "a\nB\nc\n"

	got := diff(before, after)
	want := []string{"  a", "- b", "+ B", "  c"}
	for _, line := range want {
		if !strings.Contains(got, line+"\n") {
			t.Errorf("the diff has no %q line:\n%s", line, got)
		}
	}
	// The unchanged lines are context, not noise: two of three survive unmarked, and exactly
	// one line is removed and one added.
	removed, added, kept := countDiff(got)
	if removed != 1 || added != 1 || kept != 2 {
		t.Errorf("removed=%d added=%d kept=%d, want 1/1/2:\n%s", removed, added, kept, got)
	}
}

// countDiff counts the three kinds of line in a rendered diff.
func countDiff(out string) (removed, added, kept int) {
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "- "):
			removed++
		case strings.HasPrefix(line, "+ "):
			added++
		case strings.HasPrefix(line, "  "):
			kept++
		}
	}
	return removed, added, kept
}

func TestDiffOnAFirstPolicyIsAllAdditions(t *testing.T) {
	got := diff("", "{\n  \"version\": 1\n}\n")
	if strings.Contains(got, "\n- ") || strings.HasPrefix(got, "- ") {
		t.Errorf("a first policy removed something:\n%s", got)
	}
	if !strings.Contains(got, `+   "version": 1`) {
		t.Errorf("the new line is not marked as added:\n%s", got)
	}
}

func TestDiffOfAnUnchangedDocumentMarksNothing(t *testing.T) {
	doc := "{\n  \"version\": 1\n}\n"
	got := diff(doc, doc)
	for _, mark := range []string{"\n- ", "\n+ "} {
		if strings.Contains(got, mark) {
			t.Errorf("an unchanged document produced a change:\n%s", got)
		}
	}
}

// A rule inserted in the middle must read as an insertion rather than as every line below
// it having been rewritten — which is the whole reason this is a subsequence diff and not a
// line-by-line comparison.
func TestDiffOfAnInsertionDoesNotRewriteTheRest(t *testing.T) {
	before := "one\ntwo\nthree\n"
	after := "one\nINSERTED\ntwo\nthree\n"

	got := diff(before, after)
	if strings.Contains(got, "- two") || strings.Contains(got, "- three") {
		t.Errorf("an insertion was shown as rewriting what followed:\n%s", got)
	}
	if !strings.Contains(got, "+ INSERTED") {
		t.Errorf("the inserted line is not marked:\n%s", got)
	}
}

func TestLongestCommonFindsTheSharedRun(t *testing.T) {
	got := longestCommon([]string{"a", "b", "c", "d"}, []string{"a", "x", "c", "d"})
	want := []string{"a", "c", "d"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// The starter is what somebody edits from when a network has never had a policy, so it has
// to be a document the control plane would accept — otherwise the first thing an editor
// shows is something that cannot be published.
func TestTheStarterPolicyIsAValidPolicy(t *testing.T) {
	if _, err := acl.Parse([]byte(starterPolicy)); err != nil {
		t.Fatalf("the starter policy does not parse: %v", err)
	}
}

// The same policy written two ways must canonicalise to one thing.
//
// A policy is stored parsed, so what comes back is canonical however it was typed. Diffing
// a hand-written file against that showed every line as changed the moment the two
// disagreed about whitespace: applying a byte-identical file a second time produced a
// twenty-line diff, and a diff nobody can read for what moved is not a diff.
func TestFormattingDoesNotShowAsAChange(t *testing.T) {
	compact := []byte(`{"version":1,"rules":[{"src":["*"],"dst":["tag:db"],"protocol":"tcp","ports":["5432"]}]}`)
	spread := []byte(`{
	  "version": 1,
	  "rules": [
	    {
	      "src": [ "*" ],
	      "dst": [ "tag:db" ],
	      "protocol": "tcp",
	      "ports": [ "5432" ]
	    }
	  ]
	}`)

	one, err := acl.Parse(compact)
	if err != nil {
		t.Fatalf("compact: %v", err)
	}
	two, err := acl.Parse(spread)
	if err != nil {
		t.Fatalf("spread: %v", err)
	}

	a, err := canonical(one)
	if err != nil {
		t.Fatal(err)
	}
	b, err := canonical(two)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Errorf("the same policy canonicalised two ways:\n%s\n---\n%s", a, b)
	}
	if d := diff(string(a), string(b)); strings.Contains(d, "\n+ ") || strings.Contains(d, "\n- ") {
		t.Errorf("identical policies produced a diff:\n%s", d)
	}
}

// And a real change still shows, so the normalisation has not flattened everything.
func TestARealChangeStillShows(t *testing.T) {
	before, err := acl.Parse([]byte(`{"version":1,"rules":[{"src":["*"],"dst":["tag:db"],"protocol":"any"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	after, err := acl.Parse([]byte(`{"version":1,"rules":[{"src":["*"],"dst":["tag:web"],"protocol":"any"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := canonical(before)
	b, _ := canonical(after)

	d := diff(string(a), string(b))
	if !strings.Contains(d, `- `) || !strings.Contains(d, `+ `) {
		t.Errorf("a changed destination did not show:\n%s", d)
	}
	if !strings.Contains(d, "tag:web") {
		t.Errorf("the new value is not in the diff:\n%s", d)
	}
}

// The subsequence is O(n*m) in time and memory over a file somebody named on the command
// line. Trimming the shared ends means an ordinary edit never reaches it, and the cap means
// two wholly different documents cannot make the CLI allocate without bound — which is what
// CodeQL objected to, and it was right to.
func TestAnEditOnlyComparesWhatChanged(t *testing.T) {
	// Far more lines than the cap, differing in exactly one of them.
	var before, after strings.Builder
	for i := 0; i < maxDiffLines*3; i++ {
		fmt.Fprintf(&before, "line %d\n", i)
		if i == maxDiffLines {
			after.WriteString("CHANGED\n")
			continue
		}
		fmt.Fprintf(&after, "line %d\n", i)
	}

	got := diff(before.String(), after.String())
	if strings.Contains(got, "too much to show as a diff") {
		t.Fatal("a one-line change was treated as a wholesale replacement")
	}
	removed, added, _ := countDiff(got)
	if removed != 1 || added != 1 {
		t.Errorf("removed=%d added=%d, want 1/1", removed, added)
	}
}

func TestTwoWhollyDifferentDocumentsAreSummarisedRatherThanCompared(t *testing.T) {
	var before, after strings.Builder
	for i := 0; i < maxDiffLines+10; i++ {
		fmt.Fprintf(&before, "old %d\n", i)
		fmt.Fprintf(&after, "new %d\n", i)
	}

	got := diff(before.String(), after.String())
	if !strings.Contains(got, "too much to show as a diff") {
		t.Errorf("an unbounded comparison was attempted:\n%s", got[:200])
	}
	// And it says how big the two sides were, so the summary is an answer rather than a
	// refusal.
	if !strings.Contains(got, fmt.Sprintf("%d lines replaced by %d", maxDiffLines+10, maxDiffLines+10)) {
		t.Errorf("the summary does not say how much changed:\n%s", got)
	}
}
