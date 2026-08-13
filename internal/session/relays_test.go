package session

import "testing"

func TestParsingADeploymentsRelays(t *testing.T) {
	cfg, err := ParseRelays("relay1=relay1.meshp.net:3478,relay1.meshp.net:443")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.GetRelays()) != 1 {
		t.Fatalf("%d relays, want 1", len(cfg.GetRelays()))
	}
	relay := cfg.GetRelays()[0]
	if relay.GetId() != "relay1" {
		t.Errorf("id is %q", relay.GetId())
	}
	// Order matters: it is the order an agent tries, so the port most likely to work leads.
	want := []string{"relay1.meshp.net:3478", "relay1.meshp.net:443"}
	if len(relay.GetEndpoints()) != len(want) {
		t.Fatalf("%d endpoints, want %d", len(relay.GetEndpoints()), len(want))
	}
	for i, w := range want {
		if relay.GetEndpoints()[i] != w {
			t.Errorf("endpoint %d is %q, want %q", i, relay.GetEndpoints()[i], w)
		}
	}
	if cfg.GetPreferredRelayId() != "relay1" {
		t.Errorf("preferred relay is %q", cfg.GetPreferredRelayId())
	}
}

func TestSeveralRelays(t *testing.T) {
	cfg, err := ParseRelays("blr=a.meshp.net:3478; fra=b.meshp.net:3478,b.meshp.net:443")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.GetRelays()) != 2 {
		t.Fatalf("%d relays, want 2", len(cfg.GetRelays()))
	}
	if cfg.GetRelays()[1].GetId() != "fra" {
		t.Errorf("second relay is %q", cfg.GetRelays()[1].GetId())
	}
}

func TestNoRelaysConfiguredIsNotAnError(t *testing.T) {
	for _, spec := range []string{"", "   "} {
		cfg, err := ParseRelays(spec)
		if err != nil {
			t.Errorf("%q gave %v", spec, err)
		}
		if cfg != nil {
			t.Errorf("%q produced a config", spec)
		}
	}
}

// A typo belongs where it was written, not as a device somewhere failing to reach a relay
// that never existed.
func TestMalformedRelaysAreRefusedAtConfiguration(t *testing.T) {
	for _, spec := range []string{
		"relay1.meshp.net:3478",        // no id
		"=relay1.meshp.net:3478",       // empty id
		"relay1=",                      // no addresses
		"relay1=relay1.meshp.net",      // no port
		"relay1=relay1.meshp.net:",     // empty port
		"relay1=relay1.meshp.net:http", // not a number
		"relay1=:3478",                 // no host
	} {
		if _, err := ParseRelays(spec); err == nil {
			t.Errorf("%q was accepted", spec)
		}
	}
}

// A literal address is as valid as a name, since a small deployment may not have DNS for it.
func TestLiteralAddressesAreAccepted(t *testing.T) {
	for _, spec := range []string{
		"relay1=203.0.113.9:3478",
		"relay1=[2001:db8::9]:3478",
	} {
		cfg, err := ParseRelays(spec)
		if err != nil {
			t.Errorf("%q gave %v", spec, err)
			continue
		}
		if len(cfg.GetRelays()[0].GetEndpoints()) != 1 {
			t.Errorf("%q produced %d endpoints", spec, len(cfg.GetRelays()[0].GetEndpoints()))
		}
	}
}
