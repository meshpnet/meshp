package session

import (
	"fmt"
	"net/netip"
	"strings"

	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// ParseRelays reads a deployment's relay list.
//
// The form is `id=host:port[,host:port...]`, several relays separated by semicolons:
//
//	relay1=relay1.meshp.net:3478,relay1.meshp.net:443
//
// Several addresses per relay because one port is not enough: UDP 443 looks like the
// friendliest choice and is the one most likely to be filtered, since it carries QUIC and
// networks that inspect HTTP block it. The order is the order an agent tries them in, so put
// the port most likely to work first.
//
// Configuration is still where relays are named — a deployment with one relay should not
// need a migration to name it, which is why this has not become an API — but it is no longer
// the whole story. What this produces seeds the `relays` table at startup, and the state
// builder reads that table on every build, so an operator can take one relay out of service
// without editing this string and restarting (#128).
//
// The division: configuration owns which relays exist and where they are, refreshed on every
// boot. The table owns whether each is taking new sessions, and a restart deliberately does
// not reset it.
func ParseRelays(spec string) (*meshpv1.RelayConfig, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}

	cfg := &meshpv1.RelayConfig{}
	for _, entry := range strings.Split(spec, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		id, addresses, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("session: relay %q has no id; expected id=host:port", entry)
		}
		id = strings.TrimSpace(id)
		if id == "" {
			return nil, fmt.Errorf("session: relay %q has an empty id", entry)
		}

		relay := &meshpv1.RelayConfig_Relay{Id: id}
		for _, addr := range strings.Split(addresses, ",") {
			addr = strings.TrimSpace(addr)
			if addr == "" {
				continue
			}
			// Validated here rather than at the agent, because a typo in a deployment's
			// configuration should be an error where it is written, not a device somewhere
			// failing to connect to a relay that never existed.
			if err := validRelayAddress(addr); err != nil {
				return nil, fmt.Errorf("session: relay %s: %w", id, err)
			}
			relay.Endpoints = append(relay.Endpoints, addr)
		}
		if len(relay.Endpoints) == 0 {
			return nil, fmt.Errorf("session: relay %s has no addresses", id)
		}
		cfg.Relays = append(cfg.Relays, relay)
	}

	if len(cfg.Relays) == 0 {
		return nil, nil
	}
	cfg.PreferredRelayId = cfg.Relays[0].GetId()
	return cfg, nil
}

// validRelayAddress accepts host:port, where the host may be a name or an address.
//
// A name is normal — relays are reached by DNS so they can move — so this cannot simply parse
// an AddrPort.
func validRelayAddress(addr string) error {
	host, port, ok := strings.Cut(addr, ":")
	if !ok {
		return fmt.Errorf("%q has no port; a relay is reached at host:port", addr)
	}
	if host == "" {
		return fmt.Errorf("%q has no host", addr)
	}
	if _, err := netip.ParseAddrPort(addr); err == nil {
		return nil // a literal address, already checked
	}
	// Not a literal, so the host is a name and only the port can be checked here.
	if port == "" {
		return fmt.Errorf("%q has an empty port", addr)
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return fmt.Errorf("%q does not end in a port number", addr)
		}
	}
	return nil
}
