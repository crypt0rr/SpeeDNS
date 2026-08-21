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
