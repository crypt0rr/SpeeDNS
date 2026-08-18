package catalog

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Protocol identifies a DNS wire transport.
type Protocol string

const (
	UDP Protocol = "udp"
	TCP Protocol = "tcp"
	DoH Protocol = "doh"
	DoT Protocol = "dot"
	DoQ Protocol = "doq"
)

var AllProtocols = []Protocol{UDP, TCP, DoH, DoT, DoQ}

func (p Protocol) String() string { return string(p) }

// ParseProtocol parses a user-facing protocol name.
func ParseProtocol(value string) (Protocol, error) {
	p := Protocol(strings.ToLower(strings.TrimSpace(value)))
	for _, supported := range AllProtocols {
		if p == supported {
			return p, nil
		}
	}
	return "", fmt.Errorf("unsupported protocol %q (choose udp, tcp, doh, dot, or doq)", value)
}

// TransportSpec contains the endpoint details needed for one protocol. For
// encrypted transports ServerName is used for TLS authentication while the
// profile address is used as the dial target when it is an IP address.
type TransportSpec struct {
	Port               int      `yaml:"port,omitempty"`
	ServerName         string   `yaml:"server_name,omitempty"`
	URL                string   `yaml:"url,omitempty"`
	BootstrapAddresses []string `yaml:"bootstrap_addresses,omitempty"`
}

// ResolverProfile is the stable configuration unit shown to users. A profile
// may expose more than one address, but each address is benchmarked as its own
// target.
type ResolverProfile struct {
	ID         string                     `yaml:"id"`
	Name       string                     `yaml:"name"`
	Owner      string                     `yaml:"owner"`
	Policy     string                     `yaml:"policy"`
	Addresses  []string                   `yaml:"addresses"`
	Transports map[Protocol]TransportSpec `yaml:"transports"`
}

type catalogFile struct {
	Version   int               `yaml:"version"`
	Resolvers []ResolverProfile `yaml:"resolvers"`
}

// Target is one independently benchmarked address/protocol combination.
type Target struct {
	Resolver ResolverProfile
	Protocol Protocol
	Address  string
	Spec     TransportSpec
}

func (t Target) ID() string {
	return fmt.Sprintf("%s@%s/%s", t.Resolver.ID, t.Address, t.Protocol)
}

func (t Target) DisplayName() string {
	if t.Resolver.Name == "" {
		return t.Resolver.ID
	}
	return t.Resolver.Name
}

// DefaultResolvers returns the focused initial public resolver catalog.
func DefaultResolvers() []ResolverProfile {
	return []ResolverProfile{
		{
			ID:        "google-8888",
			Name:      "Google Public DNS",
			Owner:     "Google",
			Policy:    "unfiltered",
			Addresses: []string{"8.8.8.8"},
			Transports: encryptedTransports(
				"dns.google", "https://dns.google/dns-query", false,
			),
		},
		{
			ID:        "google-8844",
			Name:      "Google Public DNS",
			Owner:     "Google",
			Policy:    "unfiltered",
			Addresses: []string{"8.8.4.4"},
			Transports: encryptedTransports(
				"dns.google", "https://dns.google/dns-query", false,
			),
		},
		{
			ID:        "quad9-9999",
			Name:      "Quad9",
			Owner:     "Quad9",
			Policy:    "threat blocking + DNSSEC",
			Addresses: []string{"9.9.9.9"},
			Transports: encryptedTransports(
				"dns.quad9.net", "https://dns.quad9.net/dns-query", true,
			),
		},
		{
			ID:        "quad9-99910",
			Name:      "Quad9",
			Owner:     "Quad9",
			Policy:    "unfiltered",
			Addresses: []string{"9.9.9.10"},
			Transports: encryptedTransports(
				"dns10.quad9.net", "https://dns10.quad9.net/dns-query", true,
			),
		},
		{
			ID:        "cloudflare-1111",
			Name:      "Cloudflare 1.1.1.1",
			Owner:     "Cloudflare",
			Policy:    "unfiltered",
			Addresses: []string{"1.1.1.1"},
			Transports: encryptedTransports(
				"one.one.one.one", "https://cloudflare-dns.com/dns-query", false,
			),
		},
		{
			ID:        "cloudflare-1112",
			Name:      "Cloudflare 1.1.1.2",
			Owner:     "Cloudflare",
			Policy:    "malware filtering",
			Addresses: []string{"1.1.1.2"},
			Transports: encryptedTransports(
				"security.cloudflare-dns.com", "https://security.cloudflare-dns.com/dns-query", false,
			),
		},
		{
			ID:        "dns4eu-111",
			Name:      "DNS4EU",
			Owner:     "DNS4EU / JOINDNS4.eu",
			Policy:    "protective",
			Addresses: []string{"86.54.11.1"},
			Transports: encryptedTransports(
				"protective.joindns4.eu", "https://protective.joindns4.eu/dns-query", false,
			),
		},
		{
			ID:        "dns4eu-1112",
			Name:      "DNS4EU",
			Owner:     "DNS4EU / JOINDNS4.eu",
			Policy:    "protective + child protection",
			Addresses: []string{"86.54.11.12"},
			Transports: encryptedTransports(
				"child.joindns4.eu", "https://child.joindns4.eu/dns-query", false,
			),
		},
		{
			ID:        "dns4eu-1113",
			Name:      "DNS4EU",
			Owner:     "DNS4EU / JOINDNS4.eu",
			Policy:    "protective + ad blocking",
			Addresses: []string{"86.54.11.13"},
			Transports: encryptedTransports(
				"noads.joindns4.eu", "https://noads.joindns4.eu/dns-query", false,
			),
		},
		{
			ID:        "dns4eu-11100",
			Name:      "DNS4EU",
			Owner:     "DNS4EU / JOINDNS4.eu",
			Policy:    "unfiltered",
			Addresses: []string{"86.54.11.100"},
			Transports: encryptedTransports(
				"unfiltered.joindns4.eu", "https://unfiltered.joindns4.eu/dns-query", false,
			),
		},
	}
}

func encryptedTransports(serverName, dohURL string, doq bool) map[Protocol]TransportSpec {
	transports := map[Protocol]TransportSpec{
		UDP: {Port: 53},
		TCP: {Port: 53},
		DoH: {Port: 443, ServerName: serverName, URL: dohURL},
		DoT: {Port: 853, ServerName: serverName},
	}
	if doq {
		transports[DoQ] = TransportSpec{Port: 853, ServerName: serverName}
	}
	return transports
}

// LoadYAML loads a strict versioned resolver profile file.
func LoadYAML(r io.Reader) ([]ResolverProfile, error) {
	decoder := yaml.NewDecoder(r)
	decoder.KnownFields(true)
	var file catalogFile
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("decode resolver file: %w", err)
	}
	if file.Version != 1 {
		return nil, fmt.Errorf("unsupported resolver file version %d", file.Version)
	}
	if err := Validate(file.Resolvers); err != nil {
		return nil, err
	}
	return file.Resolvers, nil
}

// Validate checks profiles before any network work begins.
func Validate(profiles []ResolverProfile) error {
	if len(profiles) == 0 {
		return errors.New("resolver catalog is empty")
	}
	ids := make(map[string]struct{}, len(profiles))
	for i := range profiles {
		profile := &profiles[i]
		profile.ID = strings.TrimSpace(profile.ID)
		profile.Name = strings.TrimSpace(profile.Name)
		profile.Owner = strings.TrimSpace(profile.Owner)
		profile.Policy = strings.TrimSpace(profile.Policy)
		if profile.ID == "" || profile.Name == "" {
			return fmt.Errorf("resolver %d must have id and name", i+1)
		}
		if _, exists := ids[profile.ID]; exists {
			return fmt.Errorf("duplicate resolver id %q", profile.ID)
		}
		ids[profile.ID] = struct{}{}
		if len(profile.Addresses) == 0 {
			return fmt.Errorf("resolver %q has no addresses", profile.ID)
		}
		for addressIndex, address := range profile.Addresses {
			address = strings.TrimSpace(address)
			if address == "" {
				return fmt.Errorf("resolver %q address %d is empty", profile.ID, addressIndex+1)
			}
			profile.Addresses[addressIndex] = address
		}
		for protocol, spec := range profile.Transports {
			if !isKnownProtocol(protocol) {
				return fmt.Errorf("resolver %q has unsupported protocol %q", profile.ID, protocol)
			}
			if spec.Port == 0 {
				spec.Port = defaultPort(protocol)
				profile.Transports[protocol] = spec
			}
			if spec.Port < 1 || spec.Port > 65535 {
				return fmt.Errorf("resolver %q protocol %q has invalid port %d", profile.ID, protocol, spec.Port)
			}
			if protocol == DoH {
				u, err := url.Parse(spec.URL)
				if err != nil || u.Scheme != "https" || u.Host == "" || u.Path == "" {
					return fmt.Errorf("resolver %q has invalid DoH URL %q", profile.ID, spec.URL)
				}
			}
			if protocol == DoT || protocol == DoQ {
				if strings.TrimSpace(spec.ServerName) == "" {
					return fmt.Errorf("resolver %q protocol %q requires server_name", profile.ID, protocol)
				}
			}
		}
	}
	return nil
}

func defaultPort(protocol Protocol) int {
	switch protocol {
	case UDP, TCP:
		return 53
	case DoH:
		return 443
	case DoT, DoQ:
		return 853
	default:
		return 0
	}
}

func isKnownProtocol(protocol Protocol) bool {
	for _, supported := range AllProtocols {
		if protocol == supported {
			return true
		}
	}
	return false
}

// Expand creates one target for each address and selected supported protocol.
func Expand(profiles []ResolverProfile, selected []Protocol) []Target {
	if len(selected) == 0 {
		selected = AllProtocols
	}
	var targets []Target
	for _, profile := range profiles {
		for _, protocol := range selected {
			spec, supported := profile.Transports[protocol]
			if !supported {
				continue
			}
			for _, address := range profile.Addresses {
				targets = append(targets, Target{Resolver: profile, Protocol: protocol, Address: address, Spec: spec})
			}
		}
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Protocol != targets[j].Protocol {
			return targets[i].Protocol < targets[j].Protocol
		}
		return targets[i].ID() < targets[j].ID()
	})
	return targets
}

// ParseResolverFlag converts NAME=URI into a single-profile resolver.
func ParseResolverFlag(value string) (ResolverProfile, error) {
	name, rawURI, ok := strings.Cut(value, "=")
	name = strings.TrimSpace(name)
	rawURI = strings.TrimSpace(rawURI)
	if !ok || name == "" || rawURI == "" {
		return ResolverProfile{}, fmt.Errorf("resolver must use NAME=URI, got %q", value)
	}
	u, err := url.Parse(rawURI)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ResolverProfile{}, fmt.Errorf("invalid resolver URI %q", rawURI)
	}
	var protocol Protocol
	switch strings.ToLower(u.Scheme) {
	case "udp":
		protocol = UDP
	case "tcp":
		protocol = TCP
	case "https":
		protocol = DoH
	case "tls":
		protocol = DoT
	case "quic":
		protocol = DoQ
	default:
		return ResolverProfile{}, fmt.Errorf("unsupported resolver URI scheme %q", u.Scheme)
	}
	port := 0
	if u.Port() != "" {
		port, err = net.LookupPort("tcp", u.Port())
		if err != nil {
			return ResolverProfile{}, fmt.Errorf("invalid resolver URI port: %w", err)
		}
	}
	if port == 0 {
		port = map[Protocol]int{UDP: 53, TCP: 53, DoH: 443, DoT: 853, DoQ: 853}[protocol]
	}
	host := u.Hostname()
	spec := TransportSpec{Port: port}
	if protocol == DoH {
		spec.URL = rawURI
		spec.ServerName = host
	} else if protocol == DoT || protocol == DoQ {
		spec.ServerName = host
	}
	return ResolverProfile{
		ID:         "custom-" + strings.ToLower(name),
		Name:       name,
		Owner:      "custom",
		Policy:     "user supplied",
		Addresses:  []string{host},
		Transports: map[Protocol]TransportSpec{protocol: spec},
	}, nil
}
