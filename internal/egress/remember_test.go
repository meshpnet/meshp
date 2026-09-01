package egress

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
)

func addrs(t *testing.T, list ...string) []netip.Addr {
	t.Helper()
	var out []netip.Addr
	for _, s := range list {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

var errNoDNS = errors.New("no DNS today")

// The whole point: a name that resolved once is still answerable when DNS has stopped.
//
// #204 — a claimed full tunnel carries DNS, so disturbing the claim takes DNS with it, and
// the carve-out needed to rebuild the claim cannot be computed without resolving the control
// plane. A device sat in that cycle with no network until somebody typed `meshp down`.
func TestANameResolvedOnceIsAnsweredWhenDNSStops(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolved")
	working := true
	resolve := Remembering(func(context.Context, string) ([]netip.Addr, error) {
		if working {
			return addrs(t, "168.144.85.34"), nil
		}
		return nil, errNoDNS
	}, path)

	got, err := resolve(context.Background(), "control.meshp.net")
	if err != nil {
		t.Fatalf("with DNS working: %v", err)
	}
	if len(got) != 1 || got[0].String() != "168.144.85.34" {
		t.Fatalf("got %v", got)
	}

	working = false
	got, err = resolve(context.Background(), "control.meshp.net")
	if err != nil {
		t.Fatalf("DNS is down and the name was remembered, yet: %v", err)
	}
	if len(got) != 1 || got[0].String() != "168.144.85.34" {
		t.Errorf("got %v, want the address this name had when it last resolved", got)
	}
}

// A name never seen before is still a failure. Inventing an answer would be worse than
// refusing: the carve-out would pin a route to an address nobody chose.
func TestANameNeverResolvedIsStillAFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolved")
	resolve := Remembering(func(context.Context, string) ([]netip.Addr, error) {
		return nil, errNoDNS
	}, path)

	if _, err := resolve(context.Background(), "control.meshp.net"); !errors.Is(err, errNoDNS) {
		t.Errorf("err = %v, want the resolver's own failure", err)
	}
}

// A later answer replaces an earlier one, or a control plane that moves is never followed.
func TestTheLatestAnswerIsTheOneRemembered(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolved")
	answer := addrs(t, "168.144.85.34")
	working := true
	resolve := Remembering(func(context.Context, string) ([]netip.Addr, error) {
		if working {
			return answer, nil
		}
		return nil, errNoDNS
	}, path)

	if _, err := resolve(context.Background(), "control.meshp.net"); err != nil {
		t.Fatal(err)
	}
	answer = addrs(t, "203.0.113.9")
	if _, err := resolve(context.Background(), "control.meshp.net"); err != nil {
		t.Fatal(err)
	}

	working = false
	got, err := resolve(context.Background(), "control.meshp.net")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].String() != "203.0.113.9" {
		t.Errorf("got %v, want the address from the most recent successful lookup", got)
	}
}

// The record outlives the process, because a daemon that restarts while a claim is in place
// is exactly the case that needs it: the claim survives, DNS is still broken, and a cache
// held only in memory would be gone.
func TestWhatWasRememberedSurvivesTheProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolved")

	first := Remembering(func(context.Context, string) ([]netip.Addr, error) {
		return addrs(t, "168.144.85.34"), nil
	}, path)
	if _, err := first(context.Background(), "control.meshp.net"); err != nil {
		t.Fatal(err)
	}

	// A different Remembering over the same path, as a restarted daemon would build.
	second := Remembering(func(context.Context, string) ([]netip.Addr, error) {
		return nil, errNoDNS
	}, path)
	got, err := second(context.Background(), "control.meshp.net")
	if err != nil {
		t.Fatalf("a restarted daemon could not recall the address: %v", err)
	}
	if len(got) != 1 || got[0].String() != "168.144.85.34" {
		t.Errorf("got %v", got)
	}
}

// One name failing must not cost another that was remembered. Relays and the control plane
// go through the same resolver.
func TestOneNameIsNotAnother(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolved")
	working := true
	resolve := Remembering(func(_ context.Context, host string) ([]netip.Addr, error) {
		if !working {
			return nil, errNoDNS
		}
		switch host {
		case "control.meshp.net":
			return addrs(t, "168.144.85.34"), nil
		case "relay1.meshp.net":
			return addrs(t, "203.0.113.7"), nil
		}
		return nil, errNoDNS
	}, path)

	for _, host := range []string{"control.meshp.net", "relay1.meshp.net"} {
		if _, err := resolve(context.Background(), host); err != nil {
			t.Fatalf("%s: %v", host, err)
		}
	}

	working = false
	control, err := resolve(context.Background(), "control.meshp.net")
	if err != nil {
		t.Fatal(err)
	}
	if control[0].String() != "168.144.85.34" {
		t.Errorf("control.meshp.net recalled %v", control)
	}
	relay, err := resolve(context.Background(), "relay1.meshp.net")
	if err != nil {
		t.Fatal(err)
	}
	if relay[0].String() != "203.0.113.7" {
		t.Errorf("relay1.meshp.net recalled %v, which is another name's address", relay)
	}
}

// A resolver answering with nothing is a failure, not an empty success: Compute reads an
// empty answer as "this name has no addresses" and refuses the whole carve-out over it.
func TestAnEmptyAnswerIsNotAnAnswer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolved")
	resolve := Remembering(func(context.Context, string) ([]netip.Addr, error) {
		return nil, nil
	}, path)

	if _, err := resolve(context.Background(), "control.meshp.net"); err == nil {
		t.Error("an empty answer was passed on as a success")
	}
}

// The reconciler and the control channel both resolve.
func TestConcurrentLookupsDoNotCorruptTheRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolved")
	resolve := Remembering(func(_ context.Context, host string) ([]netip.Addr, error) {
		return addrs(t, "168.144.85.34"), nil
	}, path)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if _, err := resolve(context.Background(), "control.meshp.net"); err != nil {
					t.Errorf("resolve: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	if got := recall(path, "control.meshp.net"); len(got) != 1 {
		t.Errorf("the record holds %v after concurrent writes", got)
	}
}
