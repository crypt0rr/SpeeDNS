package catalog

import (
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// fuzzSchemeProtocols restates the accepted resolver URI schemes and their
// default ports independently of ParseResolverFlag. A scheme maps to exactly
// one transport: a custom UDP resolver must never gain a TCP entry, and an
// encrypted scheme must never lose its server name, because there is no
// fallback between transports.
var fuzzSchemeProtocols = map[string]struct {
	protocol    Protocol
	defaultPort int
}{
	"udp":   {UDP, 53},
	"tcp":   {TCP, 53},
	"https": {DoH, 443},
	"tls":   {DoT, 853},
	"quic":  {DoQ, 853},
}

func FuzzParseResolverFlagInvariants(f *testing.F) {
	for _, seed := range []string{
		"resolver=udp://192.0.2.53:53",
		"resolver=https://dns.example/dns-query",
		"resolver=tls://dns.example:853",
		"resolver=quic://dns.example:853",
		"malformed",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		profile, err := ParseResolverFlag(input)
		if err != nil {
			if !reflect.DeepEqual(profile, ResolverProfile{}) {
				t.Fatalf("rejected %q but returned profile %#v", input, profile)
			}
			return
		}

		name, rawURI, ok := strings.Cut(input, "=")
		name = strings.TrimSpace(name)
		rawURI = strings.TrimSpace(rawURI)
		if !ok || name == "" || rawURI == "" {
			t.Fatalf("accepted %q which is not NAME=URI", input)
		}
		u, parseErr := url.Parse(rawURI)
		if parseErr != nil || u.Scheme == "" || u.Host == "" {
			t.Fatalf("accepted unparsable resolver URI %q: %v", rawURI, parseErr)
		}
		scheme, known := fuzzSchemeProtocols[strings.ToLower(u.Scheme)]
		if !known {
			t.Fatalf("accepted unsupported scheme %q", u.Scheme)
		}

		if profile.ID != "custom-"+strings.ToLower(name) {
			t.Fatalf("profile ID = %q for name %q", profile.ID, name)
		}
		if profile.Name != name || profile.Owner != "custom" || profile.Policy != "user supplied" {
			t.Fatalf("profile provenance = %#v", profile)
		}
		host := u.Hostname()
		if len(profile.Addresses) != 1 || profile.Addresses[0] != host {
			t.Fatalf("profile addresses = %#v, want [%q]", profile.Addresses, host)
		}
		if len(profile.Transports) != 1 {
			t.Fatalf("profile declares %d transports, want exactly the requested one: %#v", len(profile.Transports), profile.Transports)
		}
		spec, present := profile.Transports[scheme.protocol]
		if !present {
			t.Fatalf("profile transports = %#v, want protocol %q", profile.Transports, scheme.protocol)
		}

		wantPort := scheme.defaultPort
		if rawPort := u.Port(); rawPort != "" {
			number, convErr := strconv.Atoi(rawPort)
			if convErr != nil || number < 0 || number > 65535 {
				t.Fatalf("accepted out-of-range port %q", rawPort)
			}
			if number != 0 {
				wantPort = number
			}
		}
		if spec.Port != wantPort {
			t.Fatalf("transport port = %d, want %d for %q", spec.Port, wantPort, rawURI)
		}
		if len(spec.BootstrapAddresses) != 0 {
			t.Fatalf("flag resolvers must not declare bootstrap addresses: %#v", spec.BootstrapAddresses)
		}

		switch scheme.protocol {
		case DoH:
			if spec.URL != rawURI || spec.ServerName != host {
				t.Fatalf("DoH spec = %#v, want URL %q and server name %q", spec, rawURI, host)
			}
		case DoT, DoQ:
			if spec.URL != "" || spec.ServerName != host {
				t.Fatalf("%s spec = %#v, want server name %q and no URL", scheme.protocol, spec, host)
			}
		default:
			if spec.URL != "" || spec.ServerName != "" {
				t.Fatalf("plaintext %s spec must carry no TLS or HTTP settings: %#v", scheme.protocol, spec)
			}
		}
	})
}

func FuzzLoadYAMLInvariants(f *testing.F) {
	for _, seed := range []string{
		"version: 1\nresolvers: []\n",
		"version: 1\nresolvers:\n  - id: example\n    name: Example\n    owner: Example\n    policy: unfiltered\n    addresses: [192.0.2.53]\n    transports:\n      udp: {port: 53}\n",
		"version: bad\nresolvers: [",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		profiles, err := LoadYAML(strings.NewReader(input))
		if err != nil {
			if profiles != nil {
				t.Fatalf("rejected input but returned %#v", profiles)
			}
			return
		}
		if len(profiles) == 0 {
			t.Fatal("accepted a resolver file with no profiles")
		}
		// Every accepted file must survive validation again: LoadYAML both
		// validates and normalizes, so re-validating the returned profiles is
		// a fixed point rather than a second, weaker check.
		if err := Validate(profiles); err != nil {
			t.Fatalf("accepted profiles fail revalidation: %v", err)
		}
		seen := make(map[string]struct{}, len(profiles))
		for _, profile := range profiles {
			if profile.ID == "" || profile.Name == "" {
				t.Fatalf("accepted profile without id or name: %#v", profile)
			}
			if strings.TrimSpace(profile.ID) != profile.ID {
				t.Fatalf("accepted untrimmed profile id %q", profile.ID)
			}
			if _, duplicate := seen[profile.ID]; duplicate {
				t.Fatalf("accepted duplicate resolver id %q", profile.ID)
			}
			seen[profile.ID] = struct{}{}
			if len(profile.Addresses) == 0 {
				t.Fatalf("accepted resolver %q without addresses", profile.ID)
			}
			for _, address := range profile.Addresses {
				if strings.TrimSpace(address) == "" {
					t.Fatalf("accepted resolver %q with an empty address", profile.ID)
				}
			}
			for protocol, spec := range profile.Transports {
				if !isKnownProtocol(protocol) {
					t.Fatalf("accepted resolver %q with unsupported protocol %q", profile.ID, protocol)
				}
				if spec.Port < 1 || spec.Port > 65535 {
					t.Fatalf("accepted resolver %q protocol %q port %d", profile.ID, protocol, spec.Port)
				}
				switch protocol {
				case DoH:
					u, parseErr := url.Parse(spec.URL)
					if parseErr != nil || u.Scheme != "https" || u.Host == "" || u.Path == "" {
						t.Fatalf("accepted resolver %q with DoH URL %q", profile.ID, spec.URL)
					}
				case DoT, DoQ:
					if strings.TrimSpace(spec.ServerName) == "" {
						t.Fatalf("accepted resolver %q protocol %q without a server name", profile.ID, protocol)
					}
				default:
					if len(spec.BootstrapAddresses) != 0 {
						t.Fatalf("accepted resolver %q protocol %q with bootstrap addresses", profile.ID, protocol)
					}
				}
			}
		}
	})
}
