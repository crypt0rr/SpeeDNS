package catalog

import (
	"strings"
	"testing"
)

func FuzzParseResolverFlagNeverPanics(f *testing.F) {
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
		_, _ = ParseResolverFlag(input)
	})
}

func FuzzLoadYAMLNeverPanics(f *testing.F) {
	for _, seed := range []string{
		"version: 1\nresolvers: []\n",
		"version: 1\nresolvers:\n  - id: example\n    name: Example\n    owner: Example\n    policy: unfiltered\n    addresses: [192.0.2.53]\n    transports:\n      udp: {port: 53}\n",
		"version: bad\nresolvers: [",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = LoadYAML(strings.NewReader(input))
	})
}
