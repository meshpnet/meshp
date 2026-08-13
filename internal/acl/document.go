// Package acl is the policy language and its compiler.
//
// One versioned JSON document per network describes who may reach what. The control plane
// compiles it into a per-device PacketFilter and the agent enforces that inbound, at the
// destination, as the authoritative check (ADR-0007). Nothing here talks to a database or a
// kernel: a policy is a value, compiling it is a pure function, and both can be wrong in
// ways that no amount of integration testing would find reliably.
//
// Two decisions shape the language.
//
// **Rules only allow.** There is no deny rule, and the default is to deny. Order therefore
// never matters, nothing shadows anything, and "why can this device reach that one" always
// has exactly one answer: some rule permits it. A language with both allow and deny needs a
// precedence story, and every precedence story produces policies whose author is surprised
// by them — which for a security control is the whole problem.
//
// **Tags are resolved here, not on the device.** A compiled filter names concrete prefixes,
// because a device evaluating its own tags would be deciding its own access, and a device
// is exactly the thing whose word cannot be taken for that. It is why Peer.tags is marked
// as context and never authoritative.
package acl

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Version is the only document version this build understands.
//
// Refused rather than assumed when it does not match: a control plane reading a policy it
// only partly understands would compile a filter that is not the policy anyone wrote, and
// the failure would be silent and in the direction of granting access.
const Version = 1

// Document is a network's policy.
type Document struct {
	Version int    `json:"version"`
	Rules   []Rule `json:"rules"`

	// Comment carries the author's own note. Kept so a policy round-trips through storage
	// and review unchanged; never interpreted.
	Comment string `json:"comment,omitempty"`
}

// Rule permits traffic from anything matching Src to anything matching Dst.
type Rule struct {
	Src []Selector `json:"src"`
	Dst []Selector `json:"dst"`

	// Protocol is "tcp", "udp", "icmp" or "any". Empty means "any".
	Protocol string `json:"protocol,omitempty"`

	// Ports are single ports or inclusive ranges: "22", "8000-8100". Empty means every
	// port. Meaningful only for tcp and udp — a policy naming ports for icmp is a mistake
	// about what the rule does, so it is refused rather than quietly ignored.
	Ports []string `json:"ports,omitempty"`

	Comment string `json:"comment,omitempty"`
}

// Selector picks devices or addresses.
//
// Three forms, deliberately few:
//
//   - every device in the network
//     tag:<name>    every device carrying that tag
//     <cidr>        a literal prefix, for anything that is not a device
//
// A bare address is accepted and read as a single host, because "100.90.0.5" meaning
// "100.90.0.5/32" is what everyone means and refusing it teaches nothing.
type Selector string

const (
	// Everything selects every device in the network.
	Everything Selector = "*"

	tagPrefix = "tag:"
)

// IsEverything reports whether this selector matches every device.
func (s Selector) IsEverything() bool { return s == Everything }

// Tag returns the tag this selector names, if it names one.
func (s Selector) Tag() (string, bool) {
	rest, ok := strings.CutPrefix(string(s), tagPrefix)
	return rest, ok
}

// Prefix returns the literal prefix this selector names, if it names one.
func (s Selector) Prefix() (netip.Prefix, bool) {
	if s.IsEverything() {
		return netip.Prefix{}, false
	}
	if _, isTag := s.Tag(); isTag {
		return netip.Prefix{}, false
	}
	return parsePrefix(string(s))
}

// parsePrefix reads a CIDR or a bare address, which is read as a single host.
func parsePrefix(s string) (netip.Prefix, bool) {
	if strings.Contains(s, "/") {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		// Masked, so 100.90.0.5/24 does not silently become a rule about one host that is
		// written like a rule about 256 of them.
		return prefix.Masked(), true
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), true
}

// Protocols the language understands.
const (
	ProtoAny  = "any"
	ProtoTCP  = "tcp"
	ProtoUDP  = "udp"
	ProtoICMP = "icmp"
)

// PortRange is an inclusive range of ports. A single port is a range of one.
type PortRange struct {
	From, To uint16
}

func (p PortRange) String() string {
	if p.From == p.To {
		return strconv.Itoa(int(p.From))
	}
	return strconv.Itoa(int(p.From)) + "-" + strconv.Itoa(int(p.To))
}

// Parse reads a policy document and validates it.
//
// Unknown fields are refused. A policy is written by a person and applied to a security
// boundary, so a misspelled key must not be read as an absent one: "protocols": "tcp" would
// otherwise compile to a rule permitting every protocol, which is the opposite of what was
// written and impossible to see in a diff.
func Parse(data []byte) (Document, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()

	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return Document{}, fmt.Errorf("acl: reading the policy: %w", err)
	}
	if err := doc.Validate(); err != nil {
		return Document{}, err
	}
	return doc, nil
}

// Validate reports whether a document is one this build can compile faithfully.
func (d Document) Validate() error {
	if d.Version != Version {
		return fmt.Errorf("acl: this policy is version %d; this build understands version %d",
			d.Version, Version)
	}
	for i, rule := range d.Rules {
		if err := rule.validate(); err != nil {
			return fmt.Errorf("acl: rule %d: %w", i, err)
		}
	}
	return nil
}

func (r Rule) validate() error {
	if len(r.Src) == 0 {
		return fmt.Errorf("names no source; a rule that permits nothing is more likely a mistake than an intention")
	}
	if len(r.Dst) == 0 {
		return fmt.Errorf("names no destination")
	}
	for _, s := range append(append([]Selector{}, r.Src...), r.Dst...) {
		if err := s.validate(); err != nil {
			return err
		}
	}

	proto, err := r.protocol()
	if err != nil {
		return err
	}
	if len(r.Ports) > 0 && proto != ProtoTCP && proto != ProtoUDP {
		// Refused rather than ignored. A rule reading "icmp ports 22" means its author
		// believed something false, and honouring the protocol while dropping the ports
		// would give them a working rule that is not the one they wrote.
		return fmt.Errorf("names ports with protocol %q; only tcp and udp have ports", proto)
	}
	if _, err := r.PortRanges(); err != nil {
		return err
	}
	return nil
}

func (s Selector) validate() error {
	if s == "" {
		return fmt.Errorf("has an empty selector")
	}
	if s.IsEverything() {
		return nil
	}
	if tag, ok := s.Tag(); ok {
		if tag == "" {
			return fmt.Errorf("has a %q selector naming no tag", tagPrefix)
		}
		return nil
	}
	if _, ok := s.Prefix(); ok {
		return nil
	}
	return fmt.Errorf("selector %q is not %q, %q or an address", string(s), Everything, tagPrefix+"<name>")
}

// protocol returns the rule's protocol in canonical form.
func (r Rule) protocol() (string, error) {
	switch strings.ToLower(strings.TrimSpace(r.Protocol)) {
	case "", ProtoAny:
		return ProtoAny, nil
	case ProtoTCP:
		return ProtoTCP, nil
	case ProtoUDP:
		return ProtoUDP, nil
	case ProtoICMP:
		return ProtoICMP, nil
	default:
		return "", fmt.Errorf("protocol %q is not one of any, tcp, udp, icmp", r.Protocol)
	}
}

// CanonicalProtocol returns the protocol in the form the compiler uses, defaulting to any.
//
// Only meaningful on a validated rule; an unparseable protocol reads as any here and is
// refused by Validate, which is the only place that decides whether a policy is usable.
func (r Rule) CanonicalProtocol() string {
	proto, err := r.protocol()
	if err != nil {
		return ProtoAny
	}
	return proto
}

// PortRanges parses the rule's ports.
//
// An empty list means every port, which is different from a list that failed to parse —
// so a malformed port is an error rather than an empty result that would silently widen
// the rule to everything.
func (r Rule) PortRanges() ([]PortRange, error) {
	out := make([]PortRange, 0, len(r.Ports))
	for _, spec := range r.Ports {
		spec = strings.TrimSpace(spec)
		from, to, isRange := strings.Cut(spec, "-")
		lo, err := parsePort(from)
		if err != nil {
			return nil, fmt.Errorf("port %q: %w", spec, err)
		}
		hi := lo
		if isRange {
			hi, err = parsePort(to)
			if err != nil {
				return nil, fmt.Errorf("port %q: %w", spec, err)
			}
		}
		if hi < lo {
			return nil, fmt.Errorf("port range %q ends before it begins", spec)
		}
		out = append(out, PortRange{From: lo, To: hi})
	}

	// Sorted so two compilations of the same policy produce identical output. Everything
	// downstream diffs this, and an unstable ordering would make every recomputation look
	// like a policy change to every agent.
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		return out[i].To < out[j].To
	})
	return out, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("is not a number")
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("is outside 1-65535")
	}
	return uint16(n), nil
}
