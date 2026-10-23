package catalog

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/crypt0rr/SpeeDNS/internal/safetext"
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

func TestValidateAddressSyntax(t *testing.T) {
	accepted := []struct {
		name    string
		address string
	}{
		{name: "IPv4 literal", address: "192.0.2.53"},
		{name: "IPv6 literal", address: "2001:db8::53"},
		{name: "bracketed IPv6 literal", address: "[2001:db8::53]"},
		{name: "zoned link-local literal", address: "fe80::1%eth0"},
		{name: "bracketed zoned link-local literal", address: "[fe80::1%eth0]"},
		{name: "hostname", address: "dns.example"},
		{name: "hostname with trailing dot", address: "DNS.Example."},
		{name: "single label hostname", address: "localhost"},
		{name: "hostname with hyphen", address: "dns-1.example"},
		{name: "surrounding whitespace", address: " 192.0.2.53 "},
	}
	for _, test := range accepted {
		t.Run("accept "+test.name, func(t *testing.T) {
			profile := minimalProfile("accept")
			profile.Addresses = []string{test.address}
			if err := Validate([]ResolverProfile{profile}); err != nil {
				t.Fatalf("Validate(%q) = %v, want accepted", test.address, err)
			}
		})
	}

	rejected := []struct {
		name    string
		address string
		want    string
	}{
		{name: "IPv4 with port", address: "192.0.2.53:5353", want: "set the port in the transport spec"},
		{name: "bracketed IPv6 with port", address: "[2001:db8::53]:853", want: "set the port in the transport spec"},
		{name: "hostname with port", address: "dns.example:53", want: "set the port in the transport spec"},
		{name: "hostname with empty port", address: "dns.example:", want: "set the port in the transport spec"},
		{name: "empty", address: "   ", want: "is empty"},
		{name: "bracketed hostname", address: "[dns.example]", want: "not an IPv6 literal"},
		{name: "unterminated bracket", address: "[2001:db8::53", want: "not an IP literal or a valid hostname"},
		{name: "truncated IPv4", address: "192.0.2", want: "not an IP literal or a valid hostname"},
		{name: "out of range IPv4", address: "10.0.0.256", want: "not an IP literal or a valid hostname"},
		{name: "malformed IPv6", address: "2001:db8::zz", want: "not an IP literal or a valid hostname"},
		{name: "empty label", address: "dns..example", want: "not an IP literal or a valid hostname"},
		{name: "root only", address: ".", want: "not an IP literal or a valid hostname"},
		{name: "leading hyphen label", address: "-dns.example", want: "not an IP literal or a valid hostname"},
		{name: "trailing hyphen label", address: "dns-.example", want: "not an IP literal or a valid hostname"},
		{name: "underscore label", address: "dns_1.example", want: "not an IP literal or a valid hostname"},
		{name: "space inside hostname", address: "dns example", want: "not an IP literal or a valid hostname"},
		{name: "oversized label", address: strings.Repeat("a", 64) + ".example", want: "not an IP literal or a valid hostname"},
		{name: "oversized hostname", address: strings.TrimSuffix(strings.Repeat(strings.Repeat("a", 63)+".", 5), ".") + ".example", want: "not an IP literal or a valid hostname"},
	}
	for _, test := range rejected {
		t.Run("reject "+test.name, func(t *testing.T) {
			profile := minimalProfile("reject")
			profile.Addresses = []string{test.address}
			err := Validate([]ResolverProfile{profile})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate(%q) = %v, want error containing %q", test.address, err, test.want)
			}
		})
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

// The --resolver flag and the YAML catalog must derive the same default port
// for every protocol, so a changed or added default cannot leave one path
// dialling the old port.
func TestResolverFlagAndCatalogAgreeOnDefaultPorts(t *testing.T) {
	schemes := map[Protocol]string{UDP: "udp", TCP: "tcp", DoH: "https", DoT: "tls", DoQ: "quic"}
	for _, protocol := range AllProtocols {
		t.Run(protocol.String(), func(t *testing.T) {
			scheme, known := schemes[protocol]
			if !known {
				t.Fatalf("protocol %q has no --resolver URI scheme", protocol)
			}
			want := defaultPort(protocol)
			if want == 0 {
				t.Fatalf("defaultPort(%q) is unset", protocol)
			}
			uri := scheme + "://dns.example"
			if protocol == DoH {
				uri += "/dns-query"
			}
			flagProfile, err := ParseResolverFlag("custom=" + uri)
			if err != nil {
				t.Fatal(err)
			}
			flagSpec, supported := flagProfile.Transports[protocol]
			if !supported {
				t.Fatalf("--resolver %q produced transports %v", uri, flagProfile.Transports)
			}
			if flagSpec.Port != want {
				t.Fatalf("--resolver %q port = %d, want defaultPort %d", uri, flagSpec.Port, want)
			}

			catalogSpec := TransportSpec{}
			switch protocol {
			case DoH:
				catalogSpec.URL = "https://dns.example/dns-query"
			case DoT, DoQ:
				catalogSpec.ServerName = "dns.example"
			}
			profiles := []ResolverProfile{{
				ID:         "custom",
				Name:       "Custom",
				Addresses:  []string{"192.0.2.1"},
				Transports: map[Protocol]TransportSpec{protocol: catalogSpec},
			}}
			if err := Validate(profiles); err != nil {
				t.Fatal(err)
			}
			if got := profiles[0].Transports[protocol].Port; got != want {
				t.Fatalf("catalog default port = %d, want defaultPort %d", got, want)
			}
		})
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

// TestCacheKeysNameTheServerNotTheProfile pins what cache-miss mode compares
// to decide that two profiles reach one cache: every address, the DoH URL host,
// and the server_name of each encrypted transport, canonicalized so spelling
// cannot split one server into two. A server_name on UDP or TCP is never sent,
// so it identifies nothing and is left out.
func TestCacheKeysNameTheServerNotTheProfile(t *testing.T) {
	profile := ResolverProfile{
		ID:        "lab",
		Addresses: []string{"192.0.2.1", "[2001:DB8::1]", "Resolver.Example.TEST."},
		Transports: map[Protocol]TransportSpec{
			UDP: {Port: 53, ServerName: "ignored.example.test"},
			TCP: {Port: 53},
			DoH: {Port: 443, URL: "https://DoH.Example.test/dns-query", ServerName: "doh-tls.example.test"},
			DoT: {Port: 853, ServerName: " DoT.example.test "},
			DoQ: {Port: 853, ServerName: "dot.example.test"},
		},
	}
	want := []string{
		"host:doh-tls.example.test", "host:doh.example.test", "host:dot.example.test",
		"host:resolver.example.test", "ip:192.0.2.1", "ip:2001:db8::1",
	}
	if got := profile.CacheKeys(); !slices.Equal(got, want) {
		t.Fatalf("CacheKeys() = %q, want %q", got, want)
	}

	// Without a configured server_name the DoH URL host is the identity. An
	// unparsable URL contributes nothing rather than a key no server has;
	// Validate rejects it before a run, so only a hand-built profile has one.
	bare := ResolverProfile{Addresses: []string{"192.0.2.2"}, Transports: map[Protocol]TransportSpec{
		DoH: {URL: "https://[2001:db8::2]/dns-query"},
	}}
	if got := bare.CacheKeys(); !slices.Equal(got, []string{"ip:192.0.2.2", "ip:2001:db8::2"}) {
		t.Fatalf("DoH URL host key = %q", got)
	}
	broken := ResolverProfile{Addresses: []string{"192.0.2.3"}, Transports: map[Protocol]TransportSpec{
		DoH: {URL: "https://bad host/dns-query"},
	}}
	if got := broken.CacheKeys(); !slices.Equal(got, []string{"ip:192.0.2.3"}) {
		t.Fatalf("unparsable DoH URL keys = %q", got)
	}
}

// TestBundledCacheKeysJoinOnlyTheGooglePair records which bundled profiles
// cache-miss mode treats as one cache. google-8888 and google-8844 share the
// DoH URL host and DoT server_name dns.google, so they are one service; every
// other bundled profile answers on its own addresses and names, and treating
// those as shared would be guesswork. A catalog change that joins another
// pair changes what a default cache-miss run measures and what CACHE_MISS.md
// says it sends, so this test makes that a deliberate edit.
func TestBundledCacheKeysJoinOnlyTheGooglePair(t *testing.T) {
	owners := map[string]string{}
	var shared []string
	for _, profile := range DefaultResolvers() {
		for _, key := range profile.CacheKeys() {
			if owner, seen := owners[key]; seen {
				shared = append(shared, fmt.Sprintf("%s+%s:%s", owner, profile.ID, key))
				continue
			}
			owners[key] = profile.ID
		}
	}
	want := []string{"google-8888+google-8844:host:dns.google"}
	if !slices.Equal(shared, want) {
		t.Fatalf("bundled profiles sharing a cache key = %q, want %q", shared, want)
	}
}

// TestValidateRejectsUnprintableResolverText pins the resolver-ID part of
// #252. Every report sink escapes control, bidirectional and invisible
// characters, so a configured ID carrying one printed differently from the ID
// an --assert subject or a consumer joining report sections would use, and a
// name or owner carrying an invisible character looked identical to another.
// The error names the field and the code point and never prints the
// character itself.
func TestValidateRejectsUnprintableResolverText(t *testing.T) {
	// Each character sits inside the value, because Validate trims
	// surrounding whitespace first and U+0085 is whitespace to TrimSpace.
	unsafe := []struct {
		name  string
		value string
		want  string
	}{
		{"escape", "ev\x1b[2Kil", "contains the control or invisible character U+001B"},
		{"delete", "ev\x7fil", "contains the control or invisible character U+007F"},
		{"C1 next line", "ev\u0085il", "contains the control or invisible character U+0085"},
		{"right-to-left override", "ev\U0000202Eil", "contains the control or invisible character U+202E"},
		{"first strong isolate", "ev\U00002068il", "contains the control or invisible character U+2068"},
		{"zero width space", "ev\U0000200Bil", "contains the control or invisible character U+200B"},
		{"byte order mark", "ev\U0000FEFFil", "contains the control or invisible character U+FEFF"},
		{"invalid UTF-8", "ev\xffil", "is not valid UTF-8"},
	}
	fields := []struct {
		field string
		set   func(*ResolverProfile, string)
		want  string
	}{
		{"id", func(profile *ResolverProfile, value string) { profile.ID = value }, "resolver 1 id "},
		{"name", func(profile *ResolverProfile, value string) { profile.Name = value }, `resolver "printable" name `},
		{"owner", func(profile *ResolverProfile, value string) { profile.Owner = value }, `resolver "printable" owner `},
		{"zoned address", func(profile *ResolverProfile, value string) { profile.Addresses = []string{"fe80::1%" + value} }, `resolver "printable" address 1 `},
	}
	for _, field := range fields {
		for _, test := range unsafe {
			t.Run(field.field+" "+test.name, func(t *testing.T) {
				profile := minimalProfile("printable")
				field.set(&profile, test.value)
				err := Validate([]ResolverProfile{profile})
				if err == nil || !strings.Contains(err.Error(), field.want+test.want) {
					t.Fatalf("Validate(%s=%q) = %v, want an error containing %q", field.field, test.value, err, field.want+test.want)
				}
				if strings.Contains(err.Error(), test.value) || safetext.Escape(err.Error()) != err.Error() {
					t.Fatalf("error for %s=%q prints the rejected character: %q", field.field, test.value, err)
				}
			})
		}
	}

	// Printable Unicode stays valid, including a genuine U+FFFD and the soft
	// hyphen, which safetext leaves as written.
	for _, value := range []string{"Résolveur Ünïcode", "名前", "replacement \U0000FFFD", "soft\U000000ADhyphen"} {
		profile := minimalProfile(value)
		profile.Name, profile.Owner = value, value
		if err := Validate([]ResolverProfile{profile}); err != nil {
			t.Fatalf("Validate(%q) rejected printable text: %v", value, err)
		}
	}

	// A resolver file reaches the same check through YAML escapes.
	yamlFile := "version: 1\nresolvers:\n  - id: \"evil\\e\"\n    name: Evil\n    addresses: [192.0.2.1]\n    transports:\n      udp: {}\n"
	if _, err := LoadYAML(strings.NewReader(yamlFile)); err == nil || !strings.Contains(err.Error(), "resolver 1 id contains the control or invisible character U+001B") {
		t.Fatalf("LoadYAML with an escape in the id = %v", err)
	}
	yamlFile = "version: 1\nresolvers:\n  - id: bidi\n    name: \"a\\u202Eb\"\n    addresses: [192.0.2.1]\n    transports:\n      udp: {}\n"
	if _, err := LoadYAML(strings.NewReader(yamlFile)); err == nil || !strings.Contains(err.Error(), `resolver "bidi" name contains the control or invisible character U+202E`) {
		t.Fatalf("LoadYAML with a bidi override in the name = %v", err)
	}

	// The --resolver NAME is checked where it is parsed, so the message names
	// the flag rather than a derived ID and a position in the combined list.
	for _, test := range unsafe {
		profile, err := ParseResolverFlag(test.value + "=udp://192.0.2.53")
		if err == nil || !strings.Contains(err.Error(), "resolver NAME "+test.want) || !reflect.DeepEqual(profile, ResolverProfile{}) {
			t.Fatalf("ParseResolverFlag(%q) = %#v/%v, want a NAME error containing %q", test.value, profile, err, test.want)
		}
	}
	// Validate still covers a flag profile on its own, so a profile built
	// any other way cannot bypass the rule.
	profile, err := ParseResolverFlag("plain=udp://192.0.2.53")
	if err != nil {
		t.Fatal(err)
	}
	profile.Name = "plain\x1b"
	if err := Validate([]ResolverProfile{profile}); err == nil || !strings.Contains(err.Error(), `resolver "custom-plain" name contains`) {
		t.Fatalf("Validate of a flag profile with an unsafe name = %v", err)
	}
}

// TestValidateRejectsProfilesWithoutTransports covers #244. A profile with no
// transports expands into no target, so it surfaced only as the misleading
// "no resolver supports the selected protocol(s)" or as a silent gap in JSON
// and CSV.
func TestValidateRejectsProfilesWithoutTransports(t *testing.T) {
	for name, transports := range map[string]string{
		"missing key": "",
		"empty map":   "    transports: {}\n",
		"null":        "    transports:\n",
	} {
		t.Run(name, func(t *testing.T) {
			input := "version: 1\nresolvers:\n  - id: bare\n    name: Bare\n    addresses: [192.0.2.1]\n" + transports
			profiles, err := LoadYAML(strings.NewReader(input))
			if err == nil || profiles != nil || !strings.Contains(err.Error(), `resolver "bare" has no transports`) {
				t.Fatalf("LoadYAML(%q) = %#v/%v, want a no-transports error", input, profiles, err)
			}
		})
	}
	// A null spec still declares the transport and takes its defaults.
	profiles, err := LoadYAML(strings.NewReader("version: 1\nresolvers:\n  - id: null-spec\n    name: NullSpec\n    addresses: [192.0.2.1]\n    transports:\n      udp:\n"))
	if err != nil || profiles[0].Transports[UDP].Port != 53 {
		t.Fatalf("null udp spec = %#v/%v", profiles, err)
	}
}

// TestValidateRejectsFieldsTheProtocolNeverReads covers #244. Strict decoding
// rejected unknown keys but accepted known ones the protocol ignores, so
// `url: tls://dns.example:8853` under dot looked like it set a port and
// changed nothing. Each field gets its own error, following the existing
// bootstrap_addresses rule for udp and tcp.
func TestValidateRejectsFieldsTheProtocolNeverReads(t *testing.T) {
	for _, test := range []struct {
		name string
		spec string
		want string
	}{
		{"url on dot", "dot: {server_name: dns.example, url: \"tls://dns.example:8853\"}", `protocol "dot" cannot use url; only doh takes a url, so set port: to choose a port`},
		{"url on doq", "doq: {server_name: dns.example, url: \"quic://dns.example\"}", `protocol "doq" cannot use url`},
		{"url on udp", "udp: {url: \"udp://192.0.2.1\"}", `protocol "udp" cannot use url`},
		{"url on tcp", "tcp: {url: \" \"}", `protocol "tcp" cannot use url`},
		{"server_name on udp", "udp: {server_name: dns.example}", `protocol "udp" cannot use server_name`},
		{"server_name on tcp", "tcp: {server_name: dns.example}", `protocol "tcp" cannot use server_name`},
		{"blank server_name on doh", "doh: {url: \"https://dns.example/dns-query\", server_name: \" \"}", `protocol "doh" has a blank server_name`},
		{"blank server_name on dot", "dot: {server_name: \"   \"}", `protocol "dot" has a blank server_name`},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := "version: 1\nresolvers:\n  - id: misplaced\n    name: Misplaced\n    addresses: [192.0.2.1]\n    transports:\n      " + test.spec + "\n"
			if _, err := LoadYAML(strings.NewReader(input)); err == nil || !strings.Contains(err.Error(), `resolver "misplaced" `+test.want) {
				t.Fatalf("LoadYAML(%s) = %v, want an error containing %q", test.spec, err, test.want)
			}
		})
	}

	// The documented examples still load with their values unchanged.
	example, err := os.Open(filepath.Join("..", "..", "resolvers.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	defer example.Close()
	profiles, err := LoadYAML(example)
	if err != nil || len(profiles) != 1 {
		t.Fatalf("resolvers.example.yaml = %#v/%v", profiles, err)
	}
	transports := profiles[0].Transports
	if transports[DoT].ServerName != "dns.example" || transports[DoT].Port != 853 ||
		transports[DoH].URL != "https://dns.example/dns-query" || transports[DoH].Port != 443 ||
		transports[DoQ].ServerName != "dns.example" || transports[UDP].Port != 53 {
		t.Fatalf("resolvers.example.yaml transports = %#v", transports)
	}
}

// TestValidateStoresTrimmedServerName covers #244: the transport hands
// server_name to the TLS handshake, so storing it untrimmed made a quoted
// " dns.google " fail verification while the report showed "dns.google".
func TestValidateStoresTrimmedServerName(t *testing.T) {
	input := `version: 1
resolvers:
  - id: padded
    name: Padded
    addresses: [192.0.2.53]
    transports:
      dot: {server_name: " dns.google "}
      doq: {server_name: "	dns.google	"}
      doh: {url: "https://dns.google/dns-query", server_name: " alias.example "}
`
	profiles, err := LoadYAML(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	for protocol, want := range map[Protocol]string{DoT: "dns.google", DoQ: "dns.google", DoH: "alias.example"} {
		if got := profiles[0].Transports[protocol].ServerName; got != want {
			t.Fatalf("%s server_name = %q, want %q", protocol, got, want)
		}
		target := Target{Resolver: profiles[0], Protocol: protocol, Address: profiles[0].Addresses[0], Spec: profiles[0].Transports[protocol]}
		if metadata := target.EndpointMetadata(); metadata.TLSServerName != want || metadata.TLSIdentitySource != TLSIdentityConfigured {
			t.Fatalf("%s metadata = %#v, want configured %q", protocol, metadata, want)
		}
	}
}

// TestEndpointMetadataClassifiesZonedLiteralsAsTargetAddresses covers #244. A
// zoned link-local literal is dialed directly, but net.ParseIP rejects the
// zone, so the report claimed a system-resolver lookup that never happens.
func TestEndpointMetadataClassifiesZonedLiteralsAsTargetAddresses(t *testing.T) {
	for _, target := range []Target{
		{Protocol: DoT, Address: "fe80::1%eth0", Spec: TransportSpec{ServerName: "dns.example"}},
		{Protocol: DoQ, Address: "[fe80::1%eth0]", Spec: TransportSpec{ServerName: "dns.example"}},
		{Protocol: DoH, Spec: TransportSpec{URL: "https://[fe80::1%25eth0]/dns-query"}},
	} {
		if mode := target.EndpointMetadata().BootstrapMode; mode != BootstrapTarget {
			t.Fatalf("%s %q bootstrap mode = %q, want %q", target.Protocol, target.Address+target.Spec.URL, mode, BootstrapTarget)
		}
	}
}

// TestDoHURLWithUserinfoIsRejectedWithoutEchoingIt covers #243. A DoH URL with
// userinfo was accepted, sent as Basic authentication and written verbatim to
// endpoint_url in JSON, CSV and --details. It is rejected from a resolver file
// and from --resolver alike, and no error - including the generic malformed
// URL errors that quote the URL - prints the credentials.
func TestDoHURLWithUserinfoIsRejectedWithoutEchoingIt(t *testing.T) {
	secrets := []string{"alice", "s3cret", "bob", "hunter2", "TOKEN123"}
	assertNoSecret := func(t *testing.T, err error) {
		t.Helper()
		for _, secret := range secrets {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error leaks %q: %v", secret, err)
			}
		}
	}

	for _, raw := range []string{
		"https://alice:s3cret@doh.example/dns-query",
		"https://TOKEN123@doh.example/dns-query",
		"https://@doh.example/dns-query",
	} {
		input := "version: 1\nresolvers:\n  - id: creds\n    name: Creds\n    addresses: [192.0.2.53]\n    transports:\n      doh: {url: \"" + raw + "\"}\n"
		_, err := LoadYAML(strings.NewReader(input))
		if err == nil || !strings.Contains(err.Error(), `resolver "creds" DoH URL must not include user credentials`) {
			t.Fatalf("LoadYAML with %q = %v", raw, err)
		}
		assertNoSecret(t, err)

		profile, err := ParseResolverFlag("p=" + raw)
		if err == nil || !strings.Contains(err.Error(), "resolver URI must not include user credentials") || !reflect.DeepEqual(profile, ResolverProfile{}) {
			t.Fatalf("ParseResolverFlag(%q) = %#v/%v", raw, profile, err)
		}
		assertNoSecret(t, err)
	}
	// Userinfo means nothing to the other schemes either; it used to be
	// dropped without a word.
	for _, raw := range []string{"udp://alice:s3cret@192.0.2.53", "tls://TOKEN123@dns.example", "quic://bob:hunter2@dns.example"} {
		if _, err := ParseResolverFlag("p=" + raw); err == nil || !strings.Contains(err.Error(), "must not include user credentials") {
			t.Fatalf("ParseResolverFlag(%q) = %v", raw, err)
		} else {
			assertNoSecret(t, err)
		}
	}

	// A malformed value carrying credentials is withheld from the generic
	// errors that otherwise quote it.
	for _, value := range []string{"=https://alice:s3cret@doh.example/dns-query", "p=https://alice:s3cret@doh.example:bad/dns-query"} {
		_, err := ParseResolverFlag(value)
		if err == nil || !strings.Contains(err.Error(), `withheld because it contains "@"`) {
			t.Fatalf("ParseResolverFlag(%q) = %v, want the value withheld", value, err)
		}
		assertNoSecret(t, err)
	}
	malformed := minimalProfile("malformed")
	malformed.Transports = map[Protocol]TransportSpec{DoH: {URL: "https://bob:hunter2@doh.example:bad/dns-query"}}
	err := Validate([]ResolverProfile{malformed})
	if err == nil || !strings.Contains(err.Error(), `resolver "malformed" has invalid DoH URL (withheld`) {
		t.Fatalf("Validate of a malformed credentialed URL = %v", err)
	}
	assertNoSecret(t, err)
	// A malformed URL without credentials is still quoted, so the operator
	// sees what was wrong.
	malformed.Transports = map[Protocol]TransportSpec{DoH: {URL: "https://doh.example"}}
	if err := Validate([]ResolverProfile{malformed}); err == nil || !strings.Contains(err.Error(), `invalid DoH URL "https://doh.example"`) {
		t.Fatalf("Validate of a malformed URL = %v", err)
	}
}

// TestParseResolverFlagRejectsExplicitPortZero covers #244. ":0" used to mean
// the protocol default, so DoH dialed 443 while its URL and Host header kept
// port 0 - a URL a resolver file rejects. Only an absent port means the
// default now.
func TestParseResolverFlagRejectsExplicitPortZero(t *testing.T) {
	for _, value := range []string{
		"x=https://dns.example:0/dns-query",
		"x=udp://192.0.2.53:0",
		"x=tcp://192.0.2.53:0",
		"x=tls://dns.example:00",
		"x=quic://dns.example:0",
	} {
		profile, err := ParseResolverFlag(value)
		if err == nil || !strings.Contains(err.Error(), "must be 1-65535") || !reflect.DeepEqual(profile, ResolverProfile{}) {
			t.Fatalf("ParseResolverFlag(%q) = %#v/%v, want a port error", value, profile, err)
		}
	}
	for value, want := range map[string]int{
		"x=udp://192.0.2.53":                   53,
		"x=udp://192.0.2.53:":                  53,
		"x=https://dns.example/dns-query":      443,
		"x=https://dns.example:8443/dns-query": 8443,
	} {
		profile, err := ParseResolverFlag(value)
		if err != nil {
			t.Fatalf("ParseResolverFlag(%q) = %v", value, err)
		}
		for _, spec := range profile.Transports {
			if spec.Port != want {
				t.Fatalf("ParseResolverFlag(%q) port = %d, want %d", value, spec.Port, want)
			}
		}
	}
	profile, err := ParseResolverFlag("x=https://dns.example:8443/dns-query")
	if err != nil || profile.Transports[DoH].URL != "https://dns.example:8443/dns-query" {
		t.Fatalf("explicit DoH port URL = %#v/%v", profile, err)
	}
}

// TestBootstrapAddressesDeduplicateCanonically covers #234: duplicates were
// compared as raw strings, so case variants and IPv4-mapped spellings of one
// candidate were each tried, spending another timeout on an address that had
// already failed. The first spelling is kept, in order.
func TestBootstrapAddressesDeduplicateCanonically(t *testing.T) {
	input := `version: 1
resolvers:
  - id: dedupe
    name: Dedupe
    addresses: [192.0.2.53]
    transports:
      doq:
        server_name: dns.example
        bootstrap_addresses: ["2001:DB8::1", 192.0.2.1, "2001:db8::1", "::ffff:192.0.2.1", "[2001:db8:0::1]"]
`
	profiles, err := LoadYAML(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if got := profiles[0].Transports[DoQ].BootstrapAddresses; !reflect.DeepEqual(got, []string{"2001:DB8::1", "192.0.2.1"}) {
		t.Fatalf("canonical bootstrap de-duplication = %#v", got)
	}
}
