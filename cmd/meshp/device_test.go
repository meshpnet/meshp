package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/meshpnet/meshp/internal/cliapi"
)

func TestFindDeviceByEitherIdOrName(t *testing.T) {
	devices := []membership{
		{MembershipID: "m-1", DeviceID: "d-1", DeviceName: "laptop"},
		{MembershipID: "m-2", DeviceID: "d-2", DeviceName: "Gateway"},
	}

	for _, tc := range []struct{ name, want, wantID string }{
		{"by membership id", "m-2", "d-2"},
		{"by device id", "d-1", "d-1"},
		{"by name", "laptop", "d-1"},
		// Names are what a person has; the case they typed it in is not a second fact.
		{"by name, whatever case", "GATEWAY", "d-2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := findDevice(devices, tc.want)
			if err != nil {
				t.Fatalf("findDevice(%q): %v", tc.want, err)
			}
			if got.DeviceID != tc.wantID {
				t.Errorf("got %s, want %s", got.DeviceID, tc.wantID)
			}
		})
	}
}

// An id is checked before a name, so a device perversely named after another's id resolves
// to the one actually being addressed.
func TestFindDevicePrefersAnIdOverAName(t *testing.T) {
	devices := []membership{
		{MembershipID: "m-1", DeviceID: "d-1", DeviceName: "spare"},
		{MembershipID: "m-2", DeviceID: "d-2", DeviceName: "d-1"},
	}
	got, err := findDevice(devices, "d-1")
	if err != nil {
		t.Fatalf("findDevice: %v", err)
	}
	if got.MembershipID != "m-1" {
		t.Errorf("resolved to %s, want the device whose id that is", got.MembershipID)
	}
}

// Picking one of two devices called "laptop" to revoke is the wrong kind of helpful.
func TestFindDeviceRefusesAnAmbiguousName(t *testing.T) {
	devices := []membership{
		{MembershipID: "m-1", DeviceID: "d-1", DeviceName: "laptop"},
		{MembershipID: "m-2", DeviceID: "d-2", DeviceName: "laptop"},
	}
	_, err := findDevice(devices, "laptop")
	if err == nil {
		t.Fatal("an ambiguous name resolved")
	}
	if !strings.Contains(err.Error(), "id") {
		t.Errorf("the error does not say what to do instead: %v", err)
	}
}

func TestFindDeviceSaysWhenThereIsNoSuchThing(t *testing.T) {
	_, err := findDevice([]membership{{DeviceName: "laptop"}}, "desktop")
	if err == nil || !strings.Contains(err.Error(), "desktop") {
		t.Errorf("want an error naming what was asked for, got %v", err)
	}
}

// networksServing answers GET /api/v1/networks with the rows given.
func networksServing(t *testing.T, rows ...network) *cliapi.Client {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/networks" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"networks": rows})
	}))
	t.Cleanup(ts.Close)
	client, err := cliapi.New(ts.URL, "a-token")
	if err != nil {
		t.Fatalf("cliapi.New: %v", err)
	}
	return client
}

func TestChooseNetworkInfersTheOnlyOne(t *testing.T) {
	client := networksServing(t, network{ID: "n-1", Slug: "hq", OrganizationSlug: "acme"})
	got, err := chooseNetwork(context.Background(), client, "")
	if err != nil {
		t.Fatalf("chooseNetwork: %v", err)
	}
	if got.ID != "n-1" {
		t.Errorf("got %s, want n-1", got.ID)
	}
}

// Guessing among several would put the blast radius of `device revoke` on whichever
// network happened to sort first.
func TestChooseNetworkRefusesToGuessAmongSeveral(t *testing.T) {
	client := networksServing(t,
		network{ID: "n-1", Slug: "hq", OrganizationSlug: "acme"},
		network{ID: "n-2", Slug: "branch", OrganizationSlug: "acme"})

	_, err := chooseNetwork(context.Background(), client, "")
	if err == nil {
		t.Fatal("it picked one")
	}
	// The error has to be actionable: which flag, and what the answers are.
	for _, want := range []string{"--network", "acme/hq", "acme/branch"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}

func TestChooseNetworkTakesASlugOrAQualifiedName(t *testing.T) {
	client := networksServing(t,
		network{ID: "n-1", Slug: "hq", OrganizationSlug: "acme"},
		network{ID: "n-2", Slug: "branch", OrganizationSlug: "acme"})

	for _, want := range []string{"branch", "acme/branch", "n-2"} {
		got, err := chooseNetwork(context.Background(), client, want)
		if err != nil {
			t.Fatalf("chooseNetwork(%q): %v", want, err)
		}
		if got.ID != "n-2" {
			t.Errorf("chooseNetwork(%q) = %s, want n-2", want, got.ID)
		}
	}
}

func TestChooseNetworkSaysWhenThereIsNoSuchNetwork(t *testing.T) {
	client := networksServing(t, network{ID: "n-1", Slug: "hq", OrganizationSlug: "acme"})
	if _, err := chooseNetwork(context.Background(), client, "nope"); err == nil {
		t.Fatal("an unknown network resolved")
	}
}

func TestChooseNetworkSaysWhenThereAreNone(t *testing.T) {
	client := networksServing(t)
	if _, err := chooseNetwork(context.Background(), client, ""); err == nil {
		t.Fatal("no networks resolved to something")
	}
}
