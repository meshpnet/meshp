//go:build windows

package resolved

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/sys/windows/registry"
)

// ErrUnsupported means this platform has no resolver meshp knows how to configure safely.
//
// Declared here as well as in the unsupported build because Windows has an implementation
// and does not build that file.
var ErrUnsupported = errors.New("resolved: no supported resolver on this platform")

// policyPath is where the Name Resolution Policy Table lives.
//
// The mechanism ADR-0029 chose, and the only one on this platform that routes by name rather
// than by interface. Interface DNS — what winipcfg.SetDNS writes — makes Windows pick servers
// by interface metric, so a nameserver on the tunnel adapter takes queries for names that
// have nothing to do with meshp. That is the capture-everything behaviour ADR-0021 refuses.
const policyPath = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`

// meshpRules names the rules meshp owns.
//
// Each rule is a subkey named for a GUID, and meshp has to find its own again to remove them.
// A marker value rather than a name pattern, because Dnscache is entitled to expect a GUID
// there and a prefix of ours would not be one — and because reading a value is exact where
// matching a name is a guess about somebody else's convention.
const meshpRules = "MeshpInterface"

// ruleNamespace makes a rule's key name a function of what it is for.
//
// A deterministic GUID, so configuring the same domain twice writes the same key rather than
// accumulating one per reconcile. The namespace is arbitrary and fixed; what matters is that
// it is meshp's and never changes, or a release would orphan every rule the last one made.
var ruleNamespace = uuid.MustParse("6f1d1a2e-8f0f-4d5b-9a3c-2b0d7e5c4a11")

// System points Windows' resolver at meshp for the names meshp owns.
type System struct{}

// New returns a configurer for this host, or nil where the policy table cannot be written.
//
// Opened for writing rather than assumed, because that is what decides the answer: the table
// is under HKLM and an agent without administrative rights cannot touch it. ADR-0021 wants a
// host that cannot configure its resolver to say so and leave the system's DNS alone, and
// finding out here rather than per reconcile is what makes that a capability rather than a
// recurring failure.
func New(context.Context) *System {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, policyPath, registry.WRITE)
	if err != nil {
		// The parent exists on every Windows that has a DNS client, but the leaf is created
		// by the first rule anybody adds, so its absence is ordinary rather than fatal.
		created, _, createErr := registry.CreateKey(registry.LOCAL_MACHINE, policyPath, registry.WRITE)
		if createErr != nil {
			return nil
		}
		_ = created.Close()
		return &System{}
	}
	_ = key.Close()
	return &System{}
}

// Configure sends queries for these domains, on this interface, to this address.
//
// Called on every reconcile and idempotent: the key for a domain is a function of the domain,
// so re-asserting writes the same values to the same place.
//
// The port is checked rather than carried, and refusing is the whole of why. Windows names a
// DNS server by address alone; handed "127.0.0.1:15353" it accepts the rule, stores an empty
// server list, and black-holes the namespace while reporting success (ADR-0029). A resolver
// on any other port must therefore be refused here, or meshp would break the names it was
// asked to resolve and report that it had configured them.
func (s *System) Configure(ctx context.Context, iface string, server netip.AddrPort, domains []string) error {
	if server.Port() != 53 {
		return fmt.Errorf("%w: this platform names a DNS server by address alone, and meshp's "+
			"resolver is on port %d — a rule naming a port is accepted and silently black-holes "+
			"the domain (ADR-0029)", ErrUnsupported, server.Port())
	}
	wanted := cleanDomains(domains)
	if len(wanted) == 0 {
		return s.Revert(ctx, iface)
	}

	// Whatever this interface had before, so a domain that has gone away takes its rule with
	// it rather than outliving the network that asked for it.
	existing, err := s.rulesFor(iface)
	if err != nil {
		return err
	}
	keep := make(map[string]bool, len(wanted))

	for _, domain := range wanted {
		name := ruleKeyName(iface, domain)
		keep[name] = true
		if err := writeRule(name, iface, domain, server.Addr()); err != nil {
			return err
		}
	}
	for _, name := range existing {
		if !keep[name] {
			_ = registry.DeleteKey(registry.LOCAL_MACHINE, policyPath+`\`+name)
		}
	}
	return nil
}

// Revert removes every rule meshp made for this interface.
//
// Safe for an interface that was never configured: finding nothing is the ordinary answer for
// a device that never had names, and a teardown that failed on it would report an error for
// removing something that was never there.
func (s *System) Revert(_ context.Context, iface string) error {
	names, err := s.rulesFor(iface)
	if err != nil {
		return err
	}
	var errs []error
	for _, name := range names {
		if err := registry.DeleteKey(registry.LOCAL_MACHINE, policyPath+`\`+name); err != nil {
			errs = append(errs, fmt.Errorf("resolved: removing the rule for %s: %w", iface, err))
		}
	}
	return errors.Join(errs...)
}

// rulesFor lists the rule keys meshp made for one interface.
//
// By reading the marker out of each rule rather than by recomputing the names meshp would
// have chosen. Recomputing needs the domains, and Revert is called when they are already
// gone — by a membership that has left, which is exactly when a rule left behind would
// black-hole a name nobody is serving any more.
func (s *System) rulesFor(iface string) ([]string, error) {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, policyPath, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("resolved: reading the name resolution policy table: %w", err)
	}
	defer func() { _ = root.Close() }()

	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("resolved: listing name resolution policies: %w", err)
	}

	var mine []string
	for _, name := range names {
		rule, err := registry.OpenKey(registry.LOCAL_MACHINE, policyPath+`\`+name, registry.QUERY_VALUE)
		if err != nil {
			// Somebody else's rule that this process cannot read is somebody else's rule.
			continue
		}
		owner, _, readErr := rule.GetStringValue(meshpRules)
		_ = rule.Close()
		if readErr == nil && owner == iface {
			mine = append(mine, name)
		}
	}
	sort.Strings(mine)
	return mine, nil
}

// writeRule creates or replaces one policy.
//
// Read back before it is believed. ADR-0029 records why: Windows accepts a rule it cannot
// use and reports success, so the only way to know a namespace is served rather than
// black-holed is to ask what was stored. This is the third time on these platforms that a
// call has succeeded having done nothing — route(8) on macOS was the first.
func writeRule(name, iface, domain string, server netip.Addr) error {
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, policyPath+`\`+name, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("resolved: creating a name resolution policy for %s: %w", domain, err)
	}
	defer func() { _ = key.Close() }()

	if err := errors.Join(
		key.SetDWordValue("Version", 2),
		key.SetStringsValue("Name", []string{domain}),
		key.SetStringValue("GenericDNSServers", server.String()),
		// 0x8 is "this rule names DNS servers". Without it the rule matches the namespace
		// and directs it nowhere, which is the black hole described above wearing a
		// different cause.
		key.SetDWordValue("ConfigOptions", 0x8),
		key.SetStringValue(meshpRules, iface),
	); err != nil {
		return fmt.Errorf("resolved: writing the policy for %s: %w", domain, err)
	}

	stored, _, err := key.GetStringValue("GenericDNSServers")
	if err != nil || stored != server.String() {
		return fmt.Errorf("resolved: the policy for %s names %q rather than %s, so that "+
			"domain would resolve to nothing: %w", domain, stored, server, ErrUnsupported)
	}
	return nil
}

// ruleKeyName is the registry key one domain's rule lives under.
//
// Braced and upper case, which is the form every rule Windows itself creates uses. Nothing is
// known to require it, and matching what the platform does costs nothing and avoids finding
// out that something did.
func ruleKeyName(iface, domain string) string {
	id := uuid.NewSHA1(ruleNamespace, []byte(iface+"\x00"+domain))
	return "{" + strings.ToUpper(id.String()) + "}"
}

// cleanDomains puts the domains in the form a policy takes.
//
// A leading dot is what makes a rule match a suffix rather than one exact name, and it is the
// difference between resolving everything under a network's domain and resolving only the
// domain itself. Sorted and deduplicated so the same set configures the same way twice.
func cleanDomains(in []string) []string {
	seen := make(map[string]bool, len(in))
	var out []string
	for _, domain := range in {
		trimmed := strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
		if trimmed == "" {
			continue
		}
		suffix := "." + trimmed
		if seen[suffix] {
			continue
		}
		seen[suffix] = true
		out = append(out, suffix)
	}
	sort.Strings(out)
	return out
}
