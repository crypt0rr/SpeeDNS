package catalog

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestDefaultResolversAreCorrectedAndProfiled(t *testing.T) {
	resolvers := DefaultResolvers()
	if len(resolvers) != 10 {
		t.Fatalf("default resolver count = %d, want 10", len(resolvers))
	}
	if err := Validate(resolvers); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	addressCount := 0
	doqCount := 0
	for _, resolver := range resolvers {
		if len(resolver.Addresses) != 2 {
			t.Fatalf("resolver %s addresses = %#v, want IPv4 and IPv6", resolver.ID, resolver.Addresses)
		}
		for _, address := range resolver.Addresses {
			addressCount++
			if seen[address] {
				t.Fatalf("duplicate default address %q", address)
			}
			seen[address] = true
		}
		if _, ok := resolver.Transports[DoQ]; ok {
			doqCount++
		}
	}
	if seen["8.8.8.4"] {
		t.Fatal("incorrect Google secondary address is present")
	}
	if addressCount != 20 || !seen["2001:4860:4860::8888"] || !seen["2620:fe::10"] || !seen["2606:4700:4700::1112"] || !seen["2a13:1001::86:54:11:100"] {
		t.Fatalf("bundled IPv6 addresses = %d/%v", addressCount, seen)
	}
	if doqCount != 2 {
		t.Fatalf("DoQ profile count = %d, want Quad9's two profiles", doqCount)
	}
}

func TestDefaultResolverTransportMetadata(t *testing.T) {
	// DoH and DoT identities are tracked separately: a provider may publish a
	// different TLS name for each. Cloudflare authenticates DoT as
	// one.one.one.one while its DoH endpoint is cloudflare-dns.com, and the
	// DoH handshake must match the URL authority the request is addressed to.
	// dotServer defaults to dohServer when a provider uses one name for both.
	expected := map[string]struct {
		server    string
		dotServer string
		dohURL    string
		doq       bool
	}{
		"google-8888":     {server: "dns.google", dohURL: "https://dns.google/dns-query"},
		"google-8844":     {server: "dns.google", dohURL: "https://dns.google/dns-query"},
		"quad9-9999":      {server: "dns.quad9.net", dohURL: "https://dns.quad9.net/dns-query", doq: true},
		"quad9-99910":     {server: "dns10.quad9.net", dohURL: "https://dns10.quad9.net/dns-query", doq: true},
		"cloudflare-1111": {server: "cloudflare-dns.com", dotServer: "one.one.one.one", dohURL: "https://cloudflare-dns.com/dns-query"},
		"cloudflare-1112": {server: "security.cloudflare-dns.com", dohURL: "https://security.cloudflare-dns.com/dns-query"},
		"dns4eu-111":      {server: "protective.joindns4.eu", dohURL: "https://protective.joindns4.eu/dns-query"},
		"dns4eu-1112":     {server: "child.joindns4.eu", dohURL: "https://child.joindns4.eu/dns-query"},
		"dns4eu-1113":     {server: "noads.joindns4.eu", dohURL: "https://noads.joindns4.eu/dns-query"},
		"dns4eu-11100":    {server: "unfiltered.joindns4.eu", dohURL: "https://unfiltered.joindns4.eu/dns-query"},
	}
	for _, resolver := range DefaultResolvers() {
		want, ok := expected[resolver.ID]
		if !ok {
			t.Fatalf("unexpected resolver %q", resolver.ID)
		}
		for _, protocol := range []Protocol{UDP, TCP} {
			if resolver.Transports[protocol].Port != 53 {
				t.Fatalf("%s %s port = %d, want 53", resolver.ID, protocol, resolver.Transports[protocol].Port)
			}
		}
		doh := resolver.Transports[DoH]
		if doh.Port != 443 || doh.ServerName != want.server || doh.URL != want.dohURL {
			t.Fatalf("%s DoH metadata = %#v, want server=%q URL=%q", resolver.ID, doh, want.server, want.dohURL)
		}
		wantDoT := want.dotServer
		if wantDoT == "" {
			wantDoT = want.server
		}
		for _, protocol := range []Protocol{DoT} {
			if resolver.Transports[protocol].Port != 853 || resolver.Transports[protocol].ServerName != wantDoT {
				t.Fatalf("%s %s metadata = %#v, want server=%q", resolver.ID, protocol, resolver.Transports[protocol], wantDoT)
			}
		}
		_, hasDoQ := resolver.Transports[DoQ]
		if hasDoQ != want.doq {
			t.Fatalf("%s DoQ presence = %t, want %t", resolver.ID, hasDoQ, want.doq)
		}
		if hasDoQ && (resolver.Transports[DoQ].Port != 853 || resolver.Transports[DoQ].ServerName != want.server) {
			t.Fatalf("%s DoQ metadata = %#v", resolver.ID, resolver.Transports[DoQ])
		}
	}
}

func TestDefaultResolversFailClosedWhenEmbeddedAssetIsInvalid(t *testing.T) {
	oldCatalog := defaultResolverCatalog
	t.Cleanup(func() { defaultResolverCatalog = oldCatalog })
	defaultResolverCatalog = func() string { return "version: 2\nresolvers: []\n" }
	defer func() {
		recovered, ok := recover().(string)
		if !ok || !strings.Contains(recovered, "embedded resolver catalog is invalid") {
			t.Fatalf("invalid embedded catalog panic = %v", recovered)
		}
	}()
	_ = DefaultResolvers()
}

func TestLoadYAMLRejectsUnknownFields(t *testing.T) {
	_, err := LoadYAML(strings.NewReader("version: 1\nresolvers: []\nunknown: true\n"))
	if err == nil {
		t.Fatal("expected unknown YAML field to be rejected")
	}
}

func TestLoadYAMLRejectsMultipleDocuments(t *testing.T) {
	valid := `version: 1
resolvers:
  - id: example
    name: Example
    owner: Example
    policy: unfiltered
    addresses: [192.0.2.53]
    transports:
      udp: {port: 53}
`
	for _, suffix := range []string{
		"---\nversion: 1\nresolvers: []\n",
		"---\n# an explicit empty second document\n",
	} {
		t.Run(strings.TrimSpace(suffix), func(t *testing.T) {
			_, err := LoadYAML(strings.NewReader(valid + suffix))
			if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
				t.Fatalf("multiple-document error = %v", err)
			}
		})
	}

	profiles, err := LoadYAML(strings.NewReader(valid + "\n# trailing comment only\n"))
	if err != nil || len(profiles) != 1 {
		t.Fatalf("single-document trailing comment = %#v/%v", profiles, err)
	}
	if _, err := LoadYAML(strings.NewReader(valid + "\n---\n: [\n")); err == nil || !strings.Contains(err.Error(), "decode resolver file") {
		t.Fatalf("malformed second document error = %v", err)
	}
}

func TestValidateRejectsDuplicateAddresses(t *testing.T) {
	tests := []struct {
		name      string
		addresses []string
	}{
		{name: "exact duplicate", addresses: []string{"1.1.1.1", "1.1.1.1"}},
		{name: "trimmed duplicate", addresses: []string{"1.1.1.1", " 1.1.1.1 "}},
		{name: "equivalent IPv6 literals", addresses: []string{"2001:0db8:0:0:0:0:0:1", "[2001:db8::1]"}},
		{name: "case and root dot hostname", addresses: []string{"DNS.Example.", "dns.example"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile := minimalProfile("duplicate")
			profile.Addresses = test.addresses
			if err := Validate([]ResolverProfile{profile}); err == nil || !strings.Contains(err.Error(), "duplicates address") {
				t.Fatalf("duplicate validation error = %v", err)
			}
		})
	}

	first := minimalProfile("first")
	first.Addresses = []string{"dns.example"}
	second := minimalProfile("second")
	second.Addresses = []string{"dns.example"}
	if err := Validate([]ResolverProfile{first, second}); err != nil {
		t.Fatalf("same address across profiles rejected: %v", err)
	}
}

func TestYAMLDoHPortInheritance(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		port     string
		wantPort int
		wantErr  bool
	}{
		{name: "explicit URL port", url: "https://dns.example:8443/dns-query", wantPort: 8443},
		{name: "URL default", url: "https://dns.example/dns-query", wantPort: 443},
		{name: "explicit profile override", url: "https://dns.example:8443/dns-query", port: "9443", wantPort: 9443},
		{name: "zero URL port", url: "https://dns.example:0/dns-query", wantErr: true},
		{name: "invalid URL port", url: "https://dns.example:99999/dns-query", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			portLine := ""
			if test.port != "" {
				portLine = fmt.Sprintf("        port: %s\n", test.port)
			}
			input := fmt.Sprintf(`version: 1
resolvers:
  - id: example
    name: Example
    owner: Owner
    policy: unfiltered
    addresses: [192.0.2.53]
    transports:
      doh:
        url: %s
%s`, test.url, portLine)
			profiles, err := LoadYAML(strings.NewReader(input))
			if test.wantErr {
				if err == nil {
					t.Fatal("invalid URL port unexpectedly succeeded")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := profiles[0].Transports[DoH].Port; got != test.wantPort {
				t.Fatalf("DoH port = %d, want %d", got, test.wantPort)
			}
		})
	}
}

func TestParseResolverFlag(t *testing.T) {
	profile, err := ParseResolverFlag("private=https://dns.example/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	if profile.Transports[DoH].URL != "https://dns.example/dns-query" {
		t.Fatalf("unexpected DoH URL %q", profile.Transports[DoH].URL)
	}
	if _, err := ParseResolverFlag("invalid"); err == nil {
		t.Fatal("expected malformed resolver flag to fail")
	}
}

// TestBundledDoHServerNamesMatchTheirURLHost guards the TLS identity of the
// bundled DoH endpoints. Because doHFactory.Open supplies its own
// DialTLSContext, http.Transport performs no verification of its own and the
// handshake is checked solely against server_name. A server_name that differs
// from the URL authority therefore authenticates a different name than the one
// the request is addressed to, which is not what RFC 8484 expects.
//
// A custom resolver file may still set a different server_name deliberately -
// METHODOLOGY.md documents that as the supported way to opt into another TLS
// identity - so this is a property of the bundled catalog, not a validation
// rule imposed on user configuration.
func TestBundledDoHServerNamesMatchTheirURLHost(t *testing.T) {
	for _, profile := range DefaultResolvers() {
		spec, ok := profile.Transports[DoH]
		if !ok {
			continue
		}
		endpoint, err := url.Parse(spec.URL)
		if err != nil {
			t.Fatalf("resolver %q has an unparsable DoH URL %q: %v", profile.ID, spec.URL, err)
		}
		if spec.ServerName != endpoint.Hostname() {
			t.Errorf("resolver %q DoH server_name = %q, want the URL host %q",
				profile.ID, spec.ServerName, endpoint.Hostname())
		}
	}
}
