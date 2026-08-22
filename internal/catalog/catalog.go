package catalog

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/crypt0rr/SpeeDNS/data"
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
// profile address or BootstrapAddresses provide the dial candidates.
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
	Scope      string                     `yaml:"scope,omitempty"`
	Interface  string                     `yaml:"interface,omitempty"`
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

// EndpointMetadata describes the connection and TLS choices made for one
// target. It is intentionally derived from the target rather than copied
// into benchmark results so reports cannot drift from transport behavior.
//
// For encrypted transports, server_name is the explicit opt-in for a TLS
// identity. bootstrap_addresses is the explicit opt-in for alternate IP
// connection candidates; it never changes the TLS identity. When neither is
// configured, the target address is used directly if it is an IP literal or
// resolved by the operating system otherwise.
type EndpointMetadata struct {
	EndpointURL        string
	TLSServerName      string
	TLSIdentitySource  string
	BootstrapMode      string
	BootstrapAddresses []string
}

const (
	TLSIdentityNotApplicable = "none"
	TLSIdentityConfigured    = "configured"
	TLSIdentityURLHost       = "url_host"
	TLSIdentityTarget        = "target_address"

	BootstrapNotApplicable = "none"
	BootstrapExplicit      = "explicit"
	BootstrapTarget        = "target_address"
	BootstrapSystem        = "system_resolver"
)

// EndpointMetadata returns the effective endpoint identity and bootstrap
// mode. It does not perform DNS resolution or network I/O.
func (t Target) EndpointMetadata() EndpointMetadata {
	metadata := EndpointMetadata{
		TLSIdentitySource: TLSIdentityNotApplicable,
		BootstrapMode:     BootstrapNotApplicable,
	}
	if t.Protocol != DoH && t.Protocol != DoT && t.Protocol != DoQ {
		return metadata
	}

	metadata.BootstrapMode = BootstrapSystem
	if len(t.Spec.BootstrapAddresses) > 0 {
		metadata.BootstrapMode = BootstrapExplicit
		metadata.BootstrapAddresses = append([]string(nil), t.Spec.BootstrapAddresses...)
	} else {
		address := strings.TrimSpace(t.Address)
		if address == "" && t.Protocol == DoH {
			if endpoint, err := url.Parse(t.Spec.URL); err == nil {
				address = endpoint.Hostname()
			}
		}
		address = strings.Trim(strings.TrimSpace(address), "[]")
		if net.ParseIP(address) != nil {
			metadata.BootstrapMode = BootstrapTarget
		}
	}

	switch t.Protocol {
	case DoH:
		metadata.EndpointURL = t.Spec.URL
		endpoint, err := url.Parse(t.Spec.URL)
		if t.Spec.ServerName != "" {
			metadata.TLSServerName = strings.TrimSpace(t.Spec.ServerName)
			metadata.TLSIdentitySource = TLSIdentityConfigured
		} else if err == nil {
			metadata.TLSServerName = endpoint.Hostname()
			metadata.TLSIdentitySource = TLSIdentityURLHost
		}
	case DoT, DoQ:
		if t.Spec.ServerName != "" {
			metadata.TLSServerName = strings.TrimSpace(t.Spec.ServerName)
			metadata.TLSIdentitySource = TLSIdentityConfigured
		} else {
			metadata.TLSServerName = strings.TrimSpace(t.Address)
			metadata.TLSIdentitySource = TLSIdentityTarget
		}
	}
	return metadata
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

var defaultResolverCatalog = data.ResolverCatalog

// DefaultResolvers returns the focused initial public resolver catalog loaded
// from the embedded, versioned YAML asset.
func DefaultResolvers() []ResolverProfile {
	profiles, err := LoadYAML(strings.NewReader(defaultResolverCatalog()))
	if err != nil {
		panic(fmt.Sprintf("embedded resolver catalog is invalid: %v", err))
	}
	return profiles
}

// LoadYAML loads a strict versioned resolver profile file.
func LoadYAML(r io.Reader) ([]ResolverProfile, error) {
	decoder := yaml.NewDecoder(r)
	decoder.KnownFields(true)
	var file catalogFile
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("decode resolver file: %w", err)
	}
	var extraDocument any
	if err := decoder.Decode(&extraDocument); err == nil {
		return nil, errors.New("resolver file contains multiple YAML documents; use one document")
	} else if !errors.Is(err, io.EOF) {
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
		profile.Scope = strings.TrimSpace(profile.Scope)
		profile.Interface = strings.TrimSpace(profile.Interface)
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
		seenAddresses := make(map[string]int, len(profile.Addresses))
		for addressIndex, address := range profile.Addresses {
			address = strings.TrimSpace(address)
			if address == "" {
				return fmt.Errorf("resolver %q address %d is empty", profile.ID, addressIndex+1)
			}
			addressKey := canonicalAddressKey(address)
			if previousIndex, exists := seenAddresses[addressKey]; exists {
				return fmt.Errorf("resolver %q address %d %q duplicates address %d", profile.ID, addressIndex+1, address, previousIndex)
			}
			seenAddresses[addressKey] = addressIndex + 1
			profile.Addresses[addressIndex] = address
		}
		for protocol, spec := range profile.Transports {
			if !isKnownProtocol(protocol) {
				return fmt.Errorf("resolver %q has unsupported protocol %q", profile.ID, protocol)
			}
			if protocol == DoH {
				u, err := url.Parse(spec.URL)
				if err != nil || u.Scheme != "https" || u.Host == "" || u.Path == "" {
					return fmt.Errorf("resolver %q has invalid DoH URL %q", profile.ID, spec.URL)
				}
				if spec.Port == 0 {
					spec.Port = defaultPort(protocol)
					if rawPort := u.Port(); rawPort != "" {
						port, portErr := net.LookupPort("tcp", rawPort)
						if portErr != nil {
							return fmt.Errorf("resolver %q has invalid DoH URL port %q: %w", profile.ID, rawPort, portErr)
						}
						if port < 1 || port > 65535 {
							return fmt.Errorf("resolver %q has invalid DoH URL port %q", profile.ID, rawPort)
						}
						spec.Port = port
					}
				}
			}
			if spec.Port == 0 {
				spec.Port = defaultPort(protocol)
				profile.Transports[protocol] = spec
			}
			if spec.Port < 1 || spec.Port > 65535 {
				return fmt.Errorf("resolver %q protocol %q has invalid port %d", profile.ID, protocol, spec.Port)
			}
			if len(spec.BootstrapAddresses) > 0 {
				if protocol == UDP || protocol == TCP {
					return fmt.Errorf("resolver %q protocol %q cannot use bootstrap_addresses", profile.ID, protocol)
				}
				normalized, err := normalizeBootstrapAddresses(spec.BootstrapAddresses)
				if err != nil {
					return fmt.Errorf("resolver %q protocol %q has invalid bootstrap_addresses: %w", profile.ID, protocol, err)
				}
				spec.BootstrapAddresses = normalized
			}
			if protocol == DoT || protocol == DoQ {
				if strings.TrimSpace(spec.ServerName) == "" {
					return fmt.Errorf("resolver %q protocol %q requires server_name", profile.ID, protocol)
				}
			}
			profile.Transports[protocol] = spec
		}
	}
	return nil
}

func normalizeBootstrapAddresses(addresses []string) ([]string, error) {
	normalized := make([]string, 0, len(addresses))
	seen := make(map[string]struct{}, len(addresses))
	for index, address := range addresses {
		address = strings.TrimSpace(address)
		if strings.HasPrefix(address, "[") && strings.HasSuffix(address, "]") {
			address = strings.TrimPrefix(strings.TrimSuffix(address, "]"), "[")
		}
		if net.ParseIP(address) == nil {
			return nil, fmt.Errorf("entry %d %q is not an IPv4 or IPv6 literal", index+1, address)
		}
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		normalized = append(normalized, address)
	}
	return normalized, nil
}

func canonicalAddressKey(address string) string {
	address = strings.TrimSpace(address)
	if strings.HasPrefix(address, "[") && strings.HasSuffix(address, "]") {
		address = strings.TrimPrefix(strings.TrimSuffix(address, "]"), "[")
	}
	if ip := net.ParseIP(address); ip != nil {
		return "ip:" + ip.String()
	}
	return "host:" + strings.ToLower(strings.TrimSuffix(address, "."))
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
		port = defaultPort(protocol)
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
