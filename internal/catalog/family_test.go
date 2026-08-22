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
