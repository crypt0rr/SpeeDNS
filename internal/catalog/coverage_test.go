package catalog

import (
	"strings"
	"testing"
)

func minimalProfile(id string) ResolverProfile {
	return ResolverProfile{ID: id, Name: "Name", Owner: "Owner", Policy: "policy", Addresses: []string{"192.0.2.1"}, Transports: map[Protocol]TransportSpec{UDP: {Port: 53}}}
}

func TestProtocolParsingAndTargetFormatting(t *testing.T) {
	for _, value := range []string{"udp", "TCP", " doh ", "DoT", "doq"} {
		if _, err := ParseProtocol(value); err != nil {
			t.Fatalf("ParseProtocol(%q): %v", value, err)
		}
	}
	if _, err := ParseProtocol("invalid"); err == nil {
		t.Fatal("expected unsupported protocol")
	}
	target := Target{Resolver: ResolverProfile{ID: "id", Name: "Name"}, Protocol: DoH, Address: "dns.example"}
	if target.ID() != "id@dns.example/doh" || target.DisplayName() != "Name" {
		t.Fatalf("target formatting = %q/%q", target.ID(), target.DisplayName())
	}
	target.Resolver.Name = ""
	if target.DisplayName() != "id" {
		t.Fatalf("empty display name = %q", target.DisplayName())
	}
}

func TestLoadYAMLValidationAndDefaults(t *testing.T) {
	valid := `version: 1
resolvers:
  - id: example
    name: Example
    owner: Owner
    policy: unfiltered
    addresses: [192.0.2.53]
    transports:
      udp: {}
      tcp: {}
      doh:
        url: https://dns.example/dns-query
      dot:
        server_name: dns.example
      doq:
        server_name: dns.example
`
	profiles, err := LoadYAML(strings.NewReader(valid))
	if err != nil {
		t.Fatal(err)
	}
	if profiles[0].Transports[UDP].Port != 53 || profiles[0].Transports[DoH].Port != 443 || profiles[0].Transports[DoT].Port != 853 || profiles[0].Transports[DoQ].Port != 853 {
		t.Fatalf("default ports = %#v", profiles[0].Transports)
	}
	for _, input := range []string{"[", "version: 2\nresolvers: []\n", "version: 1\nresolvers: []\n"} {
		if _, err := LoadYAML(strings.NewReader(input)); err == nil {
			t.Fatalf("expected YAML input to fail: %q", input)
		}
	}
	if _, err := LoadYAML(strings.NewReader("version: 1\nresolvers:\n  - id: x\n")); err == nil {
		t.Fatal("expected validation error from YAML")
	}
}

func TestValidateRejectsInvalidProfiles(t *testing.T) {
	cases := []struct {
		name    string
		profile ResolverProfile
	}{
		{"empty id", ResolverProfile{Name: "name", Addresses: []string{"1.1.1.1"}}},
		{"empty name", ResolverProfile{ID: "id", Addresses: []string{"1.1.1.1"}}},
		{"no addresses", ResolverProfile{ID: "id", Name: "name"}},
		{"blank address", ResolverProfile{ID: "id", Name: "name", Addresses: []string{" "}}},
		{"unknown protocol", ResolverProfile{ID: "id", Name: "name", Addresses: []string{"1.1.1.1"}, Transports: map[Protocol]TransportSpec{"bogus": {Port: 53}}}},
		{"low port", ResolverProfile{ID: "id", Name: "name", Addresses: []string{"1.1.1.1"}, Transports: map[Protocol]TransportSpec{UDP: {Port: -1}}}},
		{"high port", ResolverProfile{ID: "id", Name: "name", Addresses: []string{"1.1.1.1"}, Transports: map[Protocol]TransportSpec{UDP: {Port: 65536}}}},
		{"bad doh syntax", ResolverProfile{ID: "id", Name: "name", Addresses: []string{"1.1.1.1"}, Transports: map[Protocol]TransportSpec{DoH: {URL: "https://dns.example/%zz"}}}},
		{"wrong doh scheme", ResolverProfile{ID: "id", Name: "name", Addresses: []string{"1.1.1.1"}, Transports: map[Protocol]TransportSpec{DoH: {URL: "http://dns.example/dns-query"}}}},
		{"missing doh host", ResolverProfile{ID: "id", Name: "name", Addresses: []string{"1.1.1.1"}, Transports: map[Protocol]TransportSpec{DoH: {URL: "https:///dns-query"}}}},
		{"missing doh path", ResolverProfile{ID: "id", Name: "name", Addresses: []string{"1.1.1.1"}, Transports: map[Protocol]TransportSpec{DoH: {URL: "https://dns.example"}}}},
		{"missing dot name", ResolverProfile{ID: "id", Name: "name", Addresses: []string{"1.1.1.1"}, Transports: map[Protocol]TransportSpec{DoT: {Port: 853}}}},
		{"missing doq name", ResolverProfile{ID: "id", Name: "name", Addresses: []string{"1.1.1.1"}, Transports: map[Protocol]TransportSpec{DoQ: {Port: 853}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Validate([]ResolverProfile{tc.profile}); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	duplicate := minimalProfile("same")
	if err := Validate([]ResolverProfile{duplicate, duplicate}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate validation error = %v", err)
	}

	trimmed := ResolverProfile{ID: " id ", Name: " name ", Owner: " owner ", Policy: " policy ", Addresses: []string{" 192.0.2.1 "}, Transports: map[Protocol]TransportSpec{UDP: {}}}
	if err := Validate([]ResolverProfile{trimmed}); err != nil {
		t.Fatal(err)
	}
	if trimmed.ID != " id " {
		t.Fatal("Validate should mutate the profile supplied by slice, not a copy")
	}
	// Validate normalizes through the slice element; use an addressable slice to inspect it.
	profiles := []ResolverProfile{{ID: " id ", Name: " name ", Owner: " owner ", Policy: " policy ", Addresses: []string{" 192.0.2.1 "}, Transports: map[Protocol]TransportSpec{UDP: {}}}}
	if err := Validate(profiles); err != nil {
		t.Fatal(err)
	}
	if profiles[0].ID != "id" || profiles[0].Name != "name" || profiles[0].Addresses[0] != "192.0.2.1" || profiles[0].Transports[UDP].Port != 53 {
		t.Fatalf("normalized profile = %#v", profiles[0])
	}
}

func TestDefaultPortsAndKnownProtocols(t *testing.T) {
	for _, protocol := range []Protocol{UDP, TCP, DoH, DoT, DoQ} {
		if got := defaultPort(protocol); got == 0 {
			t.Fatalf("default port for %s is zero", protocol)
		}
		if !isKnownProtocol(protocol) {
			t.Fatalf("%s should be known", protocol)
		}
	}
	if defaultPort("unknown") != 0 || isKnownProtocol("unknown") {
		t.Fatal("unknown protocol should have no default and should not be known")
	}
}

func TestExpandUsesSelectionAndSortsTargets(t *testing.T) {
	profiles := []ResolverProfile{
		{ID: "b", Name: "B", Addresses: []string{"192.0.2.2", "192.0.2.1"}, Transports: map[Protocol]TransportSpec{UDP: {Port: 53}, TCP: {Port: 53}}},
		{ID: "a", Name: "A", Addresses: []string{"192.0.2.3"}, Transports: map[Protocol]TransportSpec{UDP: {Port: 53}}},
	}
	targets := Expand(profiles, nil)
	if len(targets) != 5 {
		t.Fatalf("all-protocol expansion count = %d", len(targets))
	}
	if targets[0].Protocol != TCP || targets[0].Resolver.ID != "b" || targets[2].Protocol != UDP || targets[2].Resolver.ID != "a" {
		t.Fatalf("sorted expansion = %#v", targets)
	}
	if got := Expand(profiles, []Protocol{DoH}); len(got) != 0 {
		t.Fatalf("unsupported selection count = %d", len(got))
	}
	selected := Expand(profiles, []Protocol{TCP})
	if len(selected) != 2 || selected[0].Spec.Port != 53 {
		t.Fatalf("selected expansion = %#v", selected)
	}
}

func TestParseResolverFlagAllSchemesAndErrors(t *testing.T) {
	cases := []struct {
		value    string
		protocol Protocol
		port     int
	}{
		{"u=udp://dns.example", UDP, 53},
		{"t=tcp://dns.example:5300", TCP, 5300},
		{"h=https://dns.example/dns-query", DoH, 443},
		{"l=tls://dns.example", DoT, 853},
		{"q=quic://dns.example:8853", DoQ, 8853},
	}
	for _, tc := range cases {
		profile, err := ParseResolverFlag(tc.value)
		if err != nil {
			t.Fatalf("ParseResolverFlag(%q): %v", tc.value, err)
		}
		spec := profile.Transports[tc.protocol]
		if spec.Port != tc.port || profile.ID != "custom-"+strings.Split(tc.value, "=")[0] {
			t.Fatalf("parsed profile = %#v", profile)
		}
	}
	if got, err := ParseResolverFlag("h=https://dns.example/dns-query"); err != nil || got.Transports[DoH].ServerName != "dns.example" || got.Transports[DoH].URL == "" {
		t.Fatalf("DoH fields = %#v/%v", got, err)
	}
	if got, err := ParseResolverFlag("l=tls://dns.example"); err != nil || got.Transports[DoT].ServerName != "dns.example" {
		t.Fatalf("DoT fields = %#v/%v", got, err)
	}
	if got, err := ParseResolverFlag("q=quic://dns.example"); err != nil || got.Transports[DoQ].ServerName != "dns.example" {
		t.Fatalf("DoQ fields = %#v/%v", got, err)
	}
	for _, value := range []string{"invalid", "=udp://dns.example", "name=", "name=udp:///path", "name=udp://dns.example/%zz", "name=http://dns.example/path", "name=bogus://dns.example", "name=udp://dns.example:not-a-port", "name=udp://dns.example:99999"} {
		if _, err := ParseResolverFlag(value); err == nil {
			t.Fatalf("expected resolver flag error for %q", value)
		}
	}
}
