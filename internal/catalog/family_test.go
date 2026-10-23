package catalog

import (
	"strings"
	"testing"
)

func TestAddressFamilyParsingAndClassification(t *testing.T) {
	for _, test := range []struct {
		input string
		want  AddressFamily
	}{
		{input: "", want: FamilyAuto},
		{input: "auto", want: FamilyAuto},
		{input: "4", want: Family4},
		{input: "6", want: Family6},
		{input: " BOTH ", want: FamilyBoth},
	} {
		got, err := ParseAddressFamily(test.input)
		if err != nil || got != test.want {
			t.Fatalf("ParseAddressFamily(%q) = %q/%v, want %q", test.input, got, err, test.want)
		}
	}
	if _, err := ParseAddressFamily("5"); err == nil {
		t.Fatal("expected unsupported family error")
	}

	if family, ok := AddressFamilyForAddress("192.0.2.1"); !ok || family != Family4 {
		t.Fatalf("IPv4 family = %q/%v", family, ok)
	}
	if family, ok := AddressFamilyForAddress("[2001:db8::1]"); !ok || family != Family6 {
		t.Fatalf("IPv6 family = %q/%v", family, ok)
	}
	if family, ok := AddressFamilyForAddress("dns.example"); ok || family != "" {
		t.Fatalf("hostname classification = %q/%v", family, ok)
	}
	if family, ok := AddressFamilyForAddress(" fe80::1%en0 "); !ok || family != Family6 {
		t.Fatalf("zoned IPv6 family = %q/%v", family, ok)
	}
	if family, ok := AddressFamilyForAddress("[fe80::1%en0]"); !ok || family != Family6 {
		t.Fatalf("bracketed zoned IPv6 family = %q/%v", family, ok)
	}
	if family, ok := AddressFamilyForAddress("::ffff:192.0.2.1"); !ok || family != Family4 {
		t.Fatalf("IPv4-mapped IPv6 family = %q/%v", family, ok)
	}
}

// A loopback stub is answered by the host's own stack, so auto detection of
// external routes must not filter it out.
func TestFilterProfilesByFamilyKeepsLoopbackUnderAuto(t *testing.T) {
	stub := ResolverProfile{
		ID: "system-stub", Name: "System DNS stub", Owner: "local stub/forwarder",
		Addresses:  []string{"::1"},
		Transports: map[Protocol]TransportSpec{UDP: {Port: 53}},
	}
	profiles, err := FilterProfilesByFamily([]ResolverProfile{stub}, FamilyAuto, map[AddressFamily]bool{Family4: true})
	if err != nil || len(profiles) != 1 || profiles[0].Addresses[0] != "::1" {
		t.Fatalf("IPv6 loopback under auto = %#v/%v", profiles, err)
	}

	stub.ID = "system-stub-v4"
	stub.Addresses = []string{"127.0.0.53"}
	profiles, err = FilterProfilesByFamily([]ResolverProfile{stub}, FamilyAuto, map[AddressFamily]bool{Family6: true})
	if err != nil || len(profiles) != 1 || profiles[0].Addresses[0] != "127.0.0.53" {
		t.Fatalf("IPv4 loopback under auto = %#v/%v", profiles, err)
	}

	// A routable address of an undetected family is still filtered, and an
	// explicit family selection stays an exact filter for loopback too.
	routable := stub
	routable.ID = "routable"
	routable.Addresses = []string{"192.0.2.1"}
	if profiles, err := FilterProfilesByFamily([]ResolverProfile{routable}, FamilyAuto, map[AddressFamily]bool{Family6: true}); err != nil || len(profiles) != 0 {
		t.Fatalf("routable address under auto = %#v/%v", profiles, err)
	}
	if profiles, err := FilterProfilesByFamily([]ResolverProfile{stub}, Family6, nil); err != nil || len(profiles) != 0 {
		t.Fatalf("IPv4 loopback under --family 6 = %#v/%v", profiles, err)
	}
}

func TestFilterProfilesByFamily(t *testing.T) {
	literal := ResolverProfile{
		ID: "mixed", Name: "Mixed", Owner: "Test", Policy: "unfiltered",
		Addresses:  []string{"192.0.2.1", "2001:db8::1"},
		Transports: map[Protocol]TransportSpec{UDP: {Port: 53}},
	}

	for _, test := range []struct {
		name      string
		family    AddressFamily
		available map[AddressFamily]bool
		want      []string
	}{
		{name: "ipv4", family: Family4, want: []string{"192.0.2.1"}},
		{name: "ipv6", family: Family6, want: []string{"2001:db8::1"}},
		{name: "both", family: FamilyBoth, want: []string{"192.0.2.1", "2001:db8::1"}},
		{name: "auto ipv4", family: FamilyAuto, available: map[AddressFamily]bool{Family4: true}, want: []string{"192.0.2.1"}},
		{name: "auto ipv6", family: FamilyAuto, available: map[AddressFamily]bool{Family6: true}, want: []string{"2001:db8::1"}},
		{name: "auto fallback", family: FamilyAuto, want: []string{"192.0.2.1", "2001:db8::1"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			profiles, err := FilterProfilesByFamily([]ResolverProfile{literal}, test.family, test.available)
			if err != nil || len(profiles) != 1 || strings.Join(profiles[0].Addresses, ",") != strings.Join(test.want, ",") {
				t.Fatalf("FilterProfilesByFamily() = %#v/%v, want %#v", profiles, err, test.want)
			}
		})
	}

	hostname := literal
	hostname.ID = "hostname"
	hostname.Addresses = []string{"resolver.example"}
	for _, family := range []AddressFamily{Family4, Family6} {
		if _, err := FilterProfilesByFamily([]ResolverProfile{hostname}, family, nil); err == nil || !strings.Contains(err.Error(), "not an IP literal") {
			t.Fatalf("hostname family %s error = %v", family, err)
		}
	}
	for _, family := range []AddressFamily{FamilyAuto, FamilyBoth} {
		profiles, err := FilterProfilesByFamily([]ResolverProfile{hostname}, family, nil)
		if err != nil || len(profiles) != 1 || profiles[0].Addresses[0] != "resolver.example" {
			t.Fatalf("hostname family %s result = %#v/%v", family, profiles, err)
		}
	}

	if profiles, err := FilterProfilesByFamily([]ResolverProfile{literal}, Family6, nil); err != nil || len(profiles) != 1 {
		t.Fatalf("IPv6 filtering without detector = %#v/%v", profiles, err)
	}
	if profiles, err := FilterProfilesByFamily([]ResolverProfile{literal}, AddressFamily("invalid"), nil); err == nil || profiles != nil {
		t.Fatalf("invalid family result = %#v/%v", profiles, err)
	}
	if profiles, err := FilterProfilesByFamily([]ResolverProfile{literal}, Family4, nil); err != nil || profiles[0].Addresses[0] != "192.0.2.1" || len(literal.Addresses) != 2 {
		t.Fatalf("filtered profile mutated or incorrect = %#v/%v", profiles, err)
	}

	onlyIPv4 := literal
	onlyIPv4.ID = "only-v4"
	onlyIPv4.Addresses = []string{"192.0.2.1"}
	if profiles, err := FilterProfilesByFamily([]ResolverProfile{onlyIPv4}, Family6, nil); err != nil || len(profiles) != 0 {
		t.Fatalf("empty family selection = %#v/%v", profiles, err)
	}
}

// TestFilterProfilesByFamilyFiltersBootstrapCandidates covers #234. The filter
// used to look at profile addresses only, while an encrypted transport with
// bootstrap_addresses dials those candidates and never the target address. A
// row labelled 2001:db8::53 could then measure 192.0.2.53 in a run whose
// provenance said --family 6.
func TestFilterProfilesByFamilyFiltersBootstrapCandidates(t *testing.T) {
	input := `version: 1
resolvers:
  - id: dual
    name: Dual
    addresses: [192.0.2.53, "2001:db8::53"]
    transports:
      udp: {}
      dot: {server_name: dns.example, bootstrap_addresses: [192.0.2.53]}
      doh: {url: "https://dns.example/dns-query", bootstrap_addresses: [192.0.2.53, "2001:db8::1"]}
      doq: {server_name: dns.example, bootstrap_addresses: ["2001:DB8::1", 192.0.2.1, "2001:db8::1", "::ffff:192.0.2.1"]}
`
	loaded, err := LoadYAML(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	original := loaded[0].Transports[DoQ].BootstrapAddresses
	if strings.Join(original, ",") != "2001:DB8::1,192.0.2.1" {
		t.Fatalf("DoQ bootstrap after canonical de-duplication = %#v", original)
	}

	// candidates returns what a target actually dials: its bootstrap
	// candidates when it has any, otherwise its own address.
	candidates := func(target Target) []string {
		if len(target.Spec.BootstrapAddresses) > 0 {
			return target.Spec.BootstrapAddresses
		}
		return []string{target.Address}
	}
	for _, test := range []struct {
		family    AddressFamily
		available map[AddressFamily]bool
		forbidden AddressFamily
		want      map[Protocol]string
	}{
		{family: Family6, forbidden: Family4, want: map[Protocol]string{UDP: "", DoH: "2001:db8::1", DoQ: "2001:DB8::1"}},
		{family: Family4, forbidden: Family6, want: map[Protocol]string{UDP: "", DoT: "192.0.2.53", DoH: "192.0.2.53", DoQ: "192.0.2.1"}},
		{family: FamilyAuto, available: map[AddressFamily]bool{Family6: true}, forbidden: Family4, want: map[Protocol]string{UDP: "", DoH: "2001:db8::1", DoQ: "2001:DB8::1"}},
	} {
		t.Run(string(test.family), func(t *testing.T) {
			profiles, err := FilterProfilesByFamily(loaded, test.family, test.available)
			if err != nil || len(profiles) != 1 {
				t.Fatalf("FilterProfilesByFamily(%s) = %#v/%v", test.family, profiles, err)
			}
			if len(profiles[0].Transports) != len(test.want) {
				t.Fatalf("--family %s transports = %#v, want %v", test.family, profiles[0].Transports, test.want)
			}
			for protocol, want := range test.want {
				spec, ok := profiles[0].Transports[protocol]
				if !ok || strings.Join(spec.BootstrapAddresses, ",") != want {
					t.Fatalf("--family %s %s bootstrap = %#v, want %q", test.family, protocol, spec.BootstrapAddresses, want)
				}
			}
			// No target dials a candidate of the other family, and no two
			// rows of one transport share a dial plan.
			plans := make(map[string]string)
			for _, target := range Expand(profiles, nil) {
				for _, candidate := range candidates(target) {
					if family, _ := AddressFamilyForAddress(candidate); family == test.forbidden {
						t.Fatalf("--family %s target %s dials %s", test.family, target.ID(), candidate)
					}
				}
				plan := string(target.Protocol) + " " + strings.Join(candidates(target), ",")
				if previous, shared := plans[plan]; shared {
					t.Fatalf("--family %s targets %s and %s share the dial plan %q", test.family, previous, target.ID(), plan)
				}
				plans[plan] = target.ID()
			}
		})
	}

	// both keeps every candidate, and the input is never modified.
	profiles, err := FilterProfilesByFamily(loaded, FamilyBoth, nil)
	if err != nil || len(profiles) != 1 || len(profiles[0].Transports) != 4 || len(profiles[0].Transports[DoH].BootstrapAddresses) != 2 {
		t.Fatalf("--family both = %#v/%v", profiles, err)
	}
	if len(loaded[0].Transports) != 4 || strings.Join(loaded[0].Transports[DoQ].BootstrapAddresses, ",") != "2001:DB8::1,192.0.2.1" ||
		strings.Join(loaded[0].Transports[DoT].BootstrapAddresses, ",") != "192.0.2.53" || len(loaded[0].Addresses) != 2 {
		t.Fatalf("filtering modified its input: %#v", loaded[0])
	}

	// A profile whose only transport has no candidate left is dropped, never
	// fallen back to the target address.
	onlyDoT := loaded[0]
	onlyDoT.Transports = map[Protocol]TransportSpec{DoT: loaded[0].Transports[DoT]}
	if profiles, err := FilterProfilesByFamily([]ResolverProfile{onlyDoT}, Family6, nil); err != nil || len(profiles) != 0 {
		t.Fatalf("--family 6 over an IPv4-only bootstrap = %#v/%v", profiles, err)
	}

	// Auto keeps a loopback candidate whatever the detected families, as it
	// does for a loopback address.
	loopback := ResolverProfile{
		ID: "loopback", Name: "Loopback", Addresses: []string{"::1"},
		Transports: map[Protocol]TransportSpec{DoT: {ServerName: "localhost", BootstrapAddresses: []string{"127.0.0.1", "192.0.2.9"}}},
	}
	profiles, err = FilterProfilesByFamily([]ResolverProfile{loopback}, FamilyAuto, map[AddressFamily]bool{Family6: true})
	if err != nil || len(profiles) != 1 || strings.Join(profiles[0].Transports[DoT].BootstrapAddresses, ",") != "127.0.0.1" {
		t.Fatalf("loopback bootstrap under auto = %#v/%v", profiles, err)
	}
}
