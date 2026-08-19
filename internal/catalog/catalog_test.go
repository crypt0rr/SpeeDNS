package catalog

import (
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
	doqCount := 0
	for _, resolver := range resolvers {
		for _, address := range resolver.Addresses {
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
	if doqCount != 2 {
		t.Fatalf("DoQ profile count = %d, want Quad9's two profiles", doqCount)
	}
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
