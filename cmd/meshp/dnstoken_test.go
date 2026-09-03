package main

import (
	"strings"
	"testing"
	"time"
)

// --- names -------------------------------------------------------------------------------

func TestFindRecordTakesEitherFormItPrinted(t *testing.T) {
	records := []dnsRecord{
		{ID: "r1", Name: "db", FQDN: "db.hq.meshp.internal", Value: "10.0.0.2"},
		{ID: "r2", Name: "web", FQDN: "web.hq.meshp.internal", Value: "10.0.0.3"},
	}
	// `dns add` takes the short name and `dns list` prints the long one; requiring somebody
	// to convert between two things the tool showed them is friction the curl did not have.
	for _, want := range []string{"db", "db.hq.meshp.internal", "DB", "r1"} {
		got, err := findRecord(records, want)
		if err != nil {
			t.Fatalf("findRecord(%q): %v", want, err)
		}
		if got.ID != "r1" {
			t.Errorf("findRecord(%q) = %s, want r1", want, got.ID)
		}
	}
}

// One name can carry several records — two A records for a pair of machines is the ordinary
// way to say "either of these" — and removing whichever came back first takes away half an
// answer.
func TestFindRecordRefusesANameThatCarriesSeveral(t *testing.T) {
	records := []dnsRecord{
		{ID: "r1", Name: "db", FQDN: "db.hq.meshp.internal", Value: "10.0.0.2"},
		{ID: "r2", Name: "db", FQDN: "db.hq.meshp.internal", Value: "10.0.0.3"},
	}
	_, err := findRecord(records, "db")
	if err == nil {
		t.Fatal("an ambiguous name resolved")
	}
	if !strings.Contains(err.Error(), "--ids") {
		t.Errorf("the error does not say how to get the ids: %v", err)
	}
}

func TestFindRecordSaysWhenThereIsNoSuchName(t *testing.T) {
	_, err := findRecord([]dnsRecord{{Name: "db"}}, "web")
	if err == nil || !strings.Contains(err.Error(), "web") {
		t.Errorf("want an error naming what was asked for, got %v", err)
	}
}

// --- tokens ------------------------------------------------------------------------------

func TestFindTokenTakesANameOrAnId(t *testing.T) {
	tokens := []apiToken{{ID: "t1", Name: "ci"}, {ID: "t2", Name: "laptop"}}
	for _, want := range []string{"ci", "CI", "t1"} {
		got, err := findToken(tokens, want)
		if err != nil {
			t.Fatalf("findToken(%q): %v", want, err)
		}
		if got.ID != "t1" {
			t.Errorf("findToken(%q) = %s, want t1", want, got.ID)
		}
	}
}

// Names are unique per person only among tokens that are live (migration 0016), so a name
// somebody reuses after revoking matches both — and the live one is the one they mean.
func TestFindTokenPrefersTheLiveOneOverItsRevokedNamesakes(t *testing.T) {
	tokens := []apiToken{
		{ID: "old", Name: "ci", Revoked: true},
		{ID: "new", Name: "ci"},
		{ID: "older", Name: "ci", Revoked: true},
	}
	got, err := findToken(tokens, "ci")
	if err != nil {
		t.Fatalf("findToken: %v", err)
	}
	if got.ID != "new" {
		t.Errorf("resolved to %s, want the live one", got.ID)
	}
}

func TestFindTokenRefusesWhenSeveralAreLive(t *testing.T) {
	tokens := []apiToken{{ID: "a", Name: "ci"}, {ID: "b", Name: "ci"}}
	if _, err := findToken(tokens, "ci"); err == nil {
		t.Fatal("two live tokens of the same name resolved")
	}
}

func TestFindTokenSaysWhenYouHoldNoSuchThing(t *testing.T) {
	_, err := findToken([]apiToken{{Name: "ci"}}, "deploy")
	if err == nil || !strings.Contains(err.Error(), "deploy") {
		t.Errorf("want an error naming what was asked for, got %v", err)
	}
}

// The column exists to answer "is anything still using this". The control plane records the
// timestamp only when it has drifted by more than a minute, so a precise rendering would
// invite reading it as a precision it does not have.
func TestLastUsedIsCoarseAndSaysNeverWhenItNeverWas(t *testing.T) {
	if got := lastUsed(nil); got != "never" {
		t.Errorf("lastUsed(nil) = %q, want never", got)
	}
	recent := time.Now().Add(-10 * time.Minute)
	if got := lastUsed(&recent); got != "within the hour" {
		t.Errorf("ten minutes ago = %q", got)
	}
	yesterday := time.Now().Add(-30 * time.Hour)
	if got := lastUsed(&yesterday); !strings.HasSuffix(got, "d ago") {
		t.Errorf("thirty hours ago = %q, want days", got)
	}
}
