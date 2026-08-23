package store

import (
	"testing"

	"github.com/google/uuid"
)

// An audited action that does not say who acted is refused rather than recorded.
//
// The guard is the point of the type. Four subsystems write audit events and every one of
// them recorded `api_token` with no id, so the trail could say that something happened and
// never who — and nothing failed, which is why it stayed that way from the first migration
// until now.
func TestAnActorThatSaysNothingIsRefused(t *testing.T) {
	id := uuid.New()

	for _, tc := range []struct {
		name  string
		actor Actor
		valid bool
	}{
		{"nothing at all", Actor{}, false},
		{"a kind and nothing else", Actor{Kind: "user"}, false},
		{"a kind the schema does not allow", Actor{Kind: "robot", Label: "hal"}, false},
		{"a label with no id", BootstrapActor(), true},
		{"an id and a label", UserActor(User{ID: id, Email: "alice@example.com"}), true},
		{"a device", DeviceActor(id, "hq-gateway"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.actor.Valid(); got != tc.valid {
				t.Errorf("Valid() = %v, want %v", got, tc.valid)
			}
		})
	}
}

// A person is named by their email, not their display name. An audit line is read months
// later by somebody trying to reach whoever did it, and a display name is not a way to
// reach anyone.
func TestAPersonIsNamedByTheirAddress(t *testing.T) {
	actor := UserActor(User{ID: uuid.New(), Email: "alice@example.com", Name: "Alice"})
	if actor.Kind != "user" {
		t.Errorf("kind = %q, want user", actor.Kind)
	}
	if actor.Label != "alice@example.com" {
		t.Errorf("label = %q, want the address", actor.Label)
	}
	if actor.ID == nil {
		t.Error("a person has no id in the trail")
	}
}

// The bootstrap secret is nobody in particular, and says so. It still cannot name a person —
// a shared secret has no identity, which is ADR-0024's whole argument — but "somebody used
// the root credential" becomes visible rather than inferred from an empty column.
func TestTheBootstrapSecretNamesItself(t *testing.T) {
	actor := BootstrapActor()
	if actor.ID != nil {
		t.Error("the bootstrap secret claims to be a particular somebody")
	}
	if actor.Label == "" {
		t.Error("the bootstrap secret is anonymous, which is what this was fixing")
	}
	if !actor.Valid() {
		t.Error("the bootstrap secret cannot write an audit event")
	}
}
