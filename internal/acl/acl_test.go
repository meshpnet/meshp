package acl

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

func device(key string, addr string, tags ...string) Device {
	return Device{
		Key:       key,
		Addresses: []netip.Prefix{netip.MustParsePrefix(addr)},
		Tags:      tags,
	}
}

func doc(rules ...Rule) Document {
	return Document{Version: Version, Rules: rules}
}

// allowed reports whether any rule in the list permits src to reach dst.
func allowed(rules []*meshpv1.PacketFilter_Rule, src, dst string) bool {
	for _, r := range rules {
		if slices.Contains(r.GetSrcPrefixes(), src) && slices.Contains(r.GetDstPrefixes(), dst) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The document

func TestParseRejectsWhatItCannotCompileFaithfully(t *testing.T) {
	for _, tc := range []struct{ name, json, wants string }{
		{"a future version", `{"version":2,"rules":[]}`, "version"},
		{"no version at all", `{"rules":[]}`, "version"},
		{
			// The reason unknown fields are refused: this compiles to a rule permitting
			// every protocol, which is the opposite of what was written and invisible in a
			// diff.
			"a misspelled key",
			`{"version":1,"rules":[{"src":["*"],"dst":["*"],"protocols":"tcp"}]}`,
			"protocols",
		},
		{"a rule with no source", `{"version":1,"rules":[{"dst":["*"]}]}`, "source"},
		{"a rule with no destination", `{"version":1,"rules":[{"src":["*"]}]}`, "destination"},
		{"an unknown protocol", `{"version":1,"rules":[{"src":["*"],"dst":["*"],"protocol":"sctp"}]}`, "sctp"},
		{
			// Honouring the protocol and dropping the ports would hand someone a working
			// rule that is not the one they wrote.
			"ports on a protocol without ports",
			`{"version":1,"rules":[{"src":["*"],"dst":["*"],"protocol":"icmp","ports":["22"]}]}`,
			"ports",
		},
		{"a port that is not a number", `{"version":1,"rules":[{"src":["*"],"dst":["*"],"protocol":"tcp","ports":["ssh"]}]}`, "number"},
		{"a port out of range", `{"version":1,"rules":[{"src":["*"],"dst":["*"],"protocol":"tcp","ports":["70000"]}]}`, "65535"},
		{"a backwards range", `{"version":1,"rules":[{"src":["*"],"dst":["*"],"protocol":"tcp","ports":["100-20"]}]}`, "ends before"},
		{"an empty selector", `{"version":1,"rules":[{"src":[""],"dst":["*"]}]}`, "empty"},
		{"a tag naming nothing", `{"version":1,"rules":[{"src":["tag:"],"dst":["*"]}]}`, "tag"},
		{"a selector that is nothing recognisable", `{"version":1,"rules":[{"src":["engineering"],"dst":["*"]}]}`, "not"},
		{"a malformed prefix", `{"version":1,"rules":[{"src":["100.90.0.0/33"],"dst":["*"]}]}`, "not"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.json))
			if err == nil {
				t.Fatalf("accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("error %q does not mention %q", err, tc.wants)
			}
		})
	}
}

func TestParseAcceptsAPolicySomeoneWouldWrite(t *testing.T) {
	parsed, err := Parse([]byte(`{
	  "version": 1,
	  "comment": "hq",
	  "rules": [
	    {"src": ["tag:laptop"], "dst": ["tag:server"], "protocol": "tcp", "ports": ["22", "8000-8100"],
	     "comment": "engineers reach the build servers"},
	    {"src": ["*"], "dst": ["100.64.0.0/10"], "protocol": "any"}
	  ]
	}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(parsed.Rules) != 2 {
		t.Fatalf("%d rules, want 2", len(parsed.Rules))
	}
	if parsed.Comment != "hq" {
		t.Errorf("the author's comment was lost")
	}
	ranges, err := parsed.Rules[0].PortRanges()
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 2 || ranges[0].String() != "22" || ranges[1].String() != "8000-8100" {
		t.Errorf("ports = %v", ranges)
	}
}

// A prefix written with host bits set means the range, not the host. Reading it the other
// way would make a rule about 256 addresses behave like a rule about one.
func TestAPrefixIsMasked(t *testing.T) {
	s := Selector("100.90.0.5/24")
	prefix, ok := s.Prefix()
	if !ok {
		t.Fatal("not read as a prefix")
	}
	if prefix.String() != "100.90.0.0/24" {
		t.Errorf("prefix = %s, want 100.90.0.0/24", prefix)
	}
}

func TestABareAddressIsASingleHost(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"100.90.0.5", "100.90.0.5/32"},
		{"fd7c::1", "fd7c::1/128"},
	} {
		prefix, ok := Selector(tc.in).Prefix()
		if !ok || prefix.String() != tc.want {
			t.Errorf("%q read as %v (ok=%v), want %s", tc.in, prefix, ok, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Compiling

// The ordinary case, and the one the whole feature exists for.
func TestOnlyWhatARulePermitsIsAllowed(t *testing.T) {
	server := device("server", "100.90.0.1/32", "server")
	laptop := device("laptop", "100.90.0.2/32", "laptop")
	printer := device("printer", "100.90.0.3/32", "printer")

	policy := doc(Rule{
		Src: []Selector{"tag:laptop"}, Dst: []Selector{"tag:server"},
		Protocol: "tcp", Ports: []string{"22"},
	})

	filter, err := Compile(policy, server, []Device{laptop, printer, server})
	if err != nil {
		t.Fatal(err)
	}
	if !filter.GetDefaultDeny() {
		t.Fatal("a compiled filter does not default to deny; everything would be permitted")
	}
	if !allowed(filter.GetInbound(), "100.90.0.2/32", "100.90.0.1/32") {
		t.Error("the laptop cannot reach the server it was granted")
	}
	if allowed(filter.GetInbound(), "100.90.0.3/32", "100.90.0.1/32") {
		t.Error("the printer reaches the server with no rule permitting it")
	}
	if got := filter.GetInbound()[0].GetPorts(); !slices.Equal(got, []string{"22"}) {
		t.Errorf("ports = %v, want [22]", got)
	}
	if got := filter.GetInbound()[0].GetProtocol(); got != ProtoTCP {
		t.Errorf("protocol = %q", got)
	}
}

// The printer is in the network and no rule mentions it, so it receives a filter that
// permits nothing rather than one that permits everything. An empty allow set and an absent
// filter must not be the same thing.
func TestADeviceNoRuleMentionsGetsAnEmptyAllowSet(t *testing.T) {
	server := device("server", "100.90.0.1/32", "server")
	laptop := device("laptop", "100.90.0.2/32", "laptop")
	printer := device("printer", "100.90.0.3/32", "printer")

	policy := doc(Rule{Src: []Selector{"tag:laptop"}, Dst: []Selector{"tag:server"}})

	filter, err := Compile(policy, printer, []Device{laptop, printer, server})
	if err != nil {
		t.Fatal(err)
	}
	if len(filter.GetInbound()) != 0 || len(filter.GetOutbound()) != 0 {
		t.Fatalf("an unmentioned device got rules: %+v", filter)
	}
	if !filter.GetDefaultDeny() {
		t.Fatal("an unmentioned device got a filter that permits everything")
	}
}

// Inbound is the authoritative check and outbound only mirrors it, so a device that is a
// source gets the outbound half and a device that is a destination gets the inbound half.
func TestBothDirectionsAreCompiled(t *testing.T) {
	server := device("server", "100.90.0.1/32", "server")
	laptop := device("laptop", "100.90.0.2/32", "laptop")
	peers := []Device{laptop, server}
	policy := doc(Rule{Src: []Selector{"tag:laptop"}, Dst: []Selector{"tag:server"}})

	fromLaptop, err := Compile(policy, laptop, peers)
	if err != nil {
		t.Fatal(err)
	}
	if len(fromLaptop.GetOutbound()) == 0 {
		t.Error("the sender got no outbound rule, so a denied connection would hang rather than fail")
	}
	if len(fromLaptop.GetInbound()) != 0 {
		t.Error("the sender got an inbound rule it was never granted")
	}

	atServer, err := Compile(policy, server, peers)
	if err != nil {
		t.Fatal(err)
	}
	if len(atServer.GetInbound()) == 0 {
		t.Error("the destination got no inbound rule, and inbound is the security boundary")
	}
}

// A rule written about a prefix has to survive the prefix containing no meshp device: that
// is exactly the case where a gateway is carrying the subnet.
func TestALiteralPrefixSurvivesHavingNoDevicesInIt(t *testing.T) {
	gateway := device("gateway", "100.90.0.1/32", "gateway")
	laptop := device("laptop", "100.90.0.2/32", "laptop")

	policy := doc(Rule{Src: []Selector{"tag:laptop"}, Dst: []Selector{"192.168.1.0/24"}})
	filter, err := Compile(policy, laptop, []Device{laptop, gateway})
	if err != nil {
		t.Fatal(err)
	}
	if !allowed(filter.GetOutbound(), "100.90.0.2/32", "192.168.1.0/24") {
		t.Fatalf("the office subnet was dropped from the rule: %+v", filter.GetOutbound())
	}
}

// permits reports whether a rule set actually allows an address to reach another, matching
// by prefix containment the way the kernel will.
//
// Distinct from allowed, which compares the rendered strings. A rule naming 100.90.0.0/24
// permits 100.90.0.2 without ever mentioning it, so a test that only compared strings would
// call that a denial — and would push the compiler towards expanding prefixes into host
// addresses, which is longer, more brittle, and drops every address in the range that is
// not a device.
func permits(rules []*meshpv1.PacketFilter_Rule, src, dst netip.Addr) bool {
	covers := func(prefixes []string, addr netip.Addr) bool {
		for _, s := range prefixes {
			p, err := netip.ParsePrefix(s)
			if err == nil && p.Contains(addr) {
				return true
			}
		}
		return false
	}
	for _, r := range rules {
		if covers(r.GetSrcPrefixes(), src) && covers(r.GetDstPrefixes(), dst) {
			return true
		}
	}
	return false
}

// A device inside a prefix a rule names is covered by it. Otherwise a policy's meaning
// would depend on whether an address happened to belong to a device.
func TestAPrefixCoversTheDevicesInsideIt(t *testing.T) {
	server := device("server", "100.90.0.1/32", "server")
	laptop := device("laptop", "100.90.0.2/32", "laptop")

	policy := doc(Rule{Src: []Selector{"100.90.0.0/24"}, Dst: []Selector{"tag:server"}})
	filter, err := Compile(policy, server, []Device{laptop, server})
	if err != nil {
		t.Fatal(err)
	}
	if !permits(filter.GetInbound(), netip.MustParseAddr("100.90.0.2"), netip.MustParseAddr("100.90.0.1")) {
		t.Errorf("a device inside a permitted prefix was not permitted: %+v", filter.GetInbound())
	}

	// The prefix is carried through as written rather than expanded into the devices
	// inside it, which is what keeps a rule about a subnet covering the addresses in it
	// that are not devices.
	if !allowed(filter.GetInbound(), "100.90.0.0/24", "100.90.0.1/32") {
		t.Errorf("the prefix was expanded away: %+v", filter.GetInbound())
	}
}

// A device outside every named prefix stays outside.
func TestAPrefixDoesNotCoverWhatIsOutsideIt(t *testing.T) {
	server := device("server", "100.90.0.1/32", "server")
	stranger := device("stranger", "100.91.0.9/32")

	policy := doc(Rule{Src: []Selector{"100.90.0.0/24"}, Dst: []Selector{"tag:server"}})
	filter, err := Compile(policy, server, []Device{stranger, server})
	if err != nil {
		t.Fatal(err)
	}
	if permits(filter.GetInbound(), netip.MustParseAddr("100.91.0.9"), netip.MustParseAddr("100.90.0.1")) {
		t.Error("a device outside the permitted prefix was permitted")
	}
}

func TestADeviceWithNoAddressesIsRefused(t *testing.T) {
	_, err := Compile(doc(), Device{Key: "nobody"}, nil)
	if err == nil {
		t.Fatal("compiled a filter for a device with nowhere to send anything")
	}
}

func TestAnInvalidDocumentIsRefusedAtCompileToo(t *testing.T) {
	// Not only at Parse: a document can reach the compiler from storage, where it was
	// written by an older build with a different idea of what is valid.
	bad := Document{Version: 99}
	if _, err := Compile(bad, device("a", "100.90.0.1/32"), nil); err == nil {
		t.Fatal("compiled a document this build does not understand")
	}
}

// ---------------------------------------------------------------------------
// Properties

func randomDevices(rng *rand.Rand, n int) []Device {
	tags := []string{"laptop", "server", "printer", "gateway"}
	out := make([]Device, 0, n)
	for i := range n {
		var carried []string
		for _, tag := range tags {
			if rng.IntN(3) == 0 {
				carried = append(carried, tag)
			}
		}
		out = append(out, device(fmt.Sprintf("key-%d", i),
			fmt.Sprintf("100.90.%d.%d/32", i/250, i%250+1), carried...))
	}
	return out
}

func randomRule(rng *rand.Rand) Rule {
	pick := func() Selector {
		switch rng.IntN(4) {
		case 0:
			return Everything
		case 1:
			return Selector("tag:laptop")
		case 2:
			return Selector("tag:server")
		default:
			return Selector("100.90.0.0/16")
		}
	}
	r := Rule{Src: []Selector{pick()}, Dst: []Selector{pick()}}
	switch rng.IntN(3) {
	case 0:
		r.Protocol = ProtoTCP
		r.Ports = []string{"22"}
	case 1:
		r.Protocol = ProtoUDP
	}
	return r
}

// Everything downstream diffs a compiled filter to decide whether a device's policy
// changed. An unstable ordering would make every recomputation look like a change and be
// pushed to every agent in the network, forever.
func TestPropertyCompilingTwiceGivesTheSameFilter(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))

	for range 300 {
		devices := randomDevices(rng, 1+rng.IntN(12))
		rules := make([]Rule, 0, 4)
		for range rng.IntN(4) {
			rules = append(rules, randomRule(rng))
		}
		policy := doc(rules...)
		self := devices[rng.IntN(len(devices))]

		first, err := Compile(policy, self, devices)
		if err != nil {
			t.Fatal(err)
		}
		second, err := Compile(policy, self, devices)
		if err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(first, second) {
			t.Fatalf("two compilations differ:\n%v\n%v", first, second)
		}

		// And the peer order it was given must not matter either: the control plane's
		// listing order is not something a policy should depend on.
		shuffled := append([]Device(nil), devices...)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		third, err := Compile(policy, self, shuffled)
		if err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(first, third) {
			t.Fatalf("the peer order changed the filter:\n%v\n%v", first, third)
		}
	}
}

// The language allows only. Adding a rule can therefore never take access away, and that is
// the property that makes a policy reviewable: a diff that only adds rules cannot break
// anything that worked.
func TestPropertyAddingARuleNeverRemovesAccess(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))

	for range 300 {
		devices := randomDevices(rng, 2+rng.IntN(8))
		self := devices[rng.IntN(len(devices))]

		var rules []Rule
		for range 1 + rng.IntN(3) {
			rules = append(rules, randomRule(rng))
		}
		before, err := Compile(doc(rules...), self, devices)
		if err != nil {
			t.Fatal(err)
		}

		after, err := Compile(doc(append(rules, randomRule(rng))...), self, devices)
		if err != nil {
			t.Fatal(err)
		}

		// Every pair permitted before must still be permitted.
		for _, rule := range before.GetInbound() {
			for _, src := range rule.GetSrcPrefixes() {
				for _, dst := range rule.GetDstPrefixes() {
					if !allowedWithProtocol(after.GetInbound(), src, dst, rule.GetProtocol(), rule.GetPorts()) {
						t.Fatalf("adding a rule removed inbound access %s -> %s (%s %v)",
							src, dst, rule.GetProtocol(), rule.GetPorts())
					}
				}
			}
		}
	}
}

// allowedWithProtocol is allowed, but also requiring the same protocol and ports, so the
// monotonicity property cannot be satisfied by a rule that permits something narrower.
func allowedWithProtocol(rules []*meshpv1.PacketFilter_Rule, src, dst, protocol string, ports []string) bool {
	for _, r := range rules {
		if !slices.Contains(r.GetSrcPrefixes(), src) || !slices.Contains(r.GetDstPrefixes(), dst) {
			continue
		}
		if r.GetProtocol() != protocol {
			continue
		}
		if !slices.Equal(r.GetPorts(), ports) {
			continue
		}
		return true
	}
	return false
}

// A filter always denies by default, whatever the policy says. There is no document that
// compiles to "permit anything not mentioned" — that is the property the whole language
// rests on, and it must not be reachable by any combination of rules.
func TestPropertyEveryFilterDefaultsToDeny(t *testing.T) {
	rng := rand.New(rand.NewPCG(5, 6))

	for range 300 {
		devices := randomDevices(rng, 1+rng.IntN(10))
		var rules []Rule
		for range rng.IntN(5) {
			rules = append(rules, randomRule(rng))
		}
		filter, err := Compile(doc(rules...), devices[rng.IntN(len(devices))], devices)
		if err != nil {
			t.Fatal(err)
		}
		if !filter.GetDefaultDeny() {
			t.Fatal("a policy compiled to a filter that permits the unmentioned")
		}
		for _, r := range append(filter.GetInbound(), filter.GetOutbound()...) {
			if !r.GetAllow() {
				t.Fatal("a compiled rule denies; the language has no way to express that")
			}
		}
	}
}
