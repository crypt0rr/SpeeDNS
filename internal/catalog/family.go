package catalog

import (
	"fmt"
	"net/netip"
	"strings"
)

// AddressFamily controls which literal resolver addresses are expanded into
// benchmark targets.
type AddressFamily string

const (
	FamilyAuto AddressFamily = "auto"
	Family4    AddressFamily = "4"
	Family6    AddressFamily = "6"
	FamilyBoth AddressFamily = "both"
)

// ParseAddressFamily parses the user-facing --family value.
func ParseAddressFamily(value string) (AddressFamily, error) {
	family := AddressFamily(strings.ToLower(strings.TrimSpace(value)))
	if family == "" {
		family = FamilyAuto
	}
	switch family {
	case FamilyAuto, Family4, Family6, FamilyBoth:
		return family, nil
	default:
		return "", fmt.Errorf("unsupported address family %q (choose 4, 6, both, or auto)", value)
	}
}

// AddressFamilyForAddress classifies an IP literal. Hostnames are returned as
// unspecified because selecting their eventual A/AAAA result would require a
// separate network lookup before benchmarking.
func AddressFamilyForAddress(address string) (AddressFamily, bool) {
	addr, ok := parseAddressLiteral(address)
	if !ok {
		return "", false
	}
	if addr.Unmap().Is4() {
		return Family4, true
	}
	return Family6, true
}

// parseAddressLiteral parses an optionally bracketed IP literal. netip is
// used instead of net.ParseIP because a zoned link-local literal such as
// "fe80::1%en0" is a dialable system nameserver that net.ParseIP rejects;
// treating it as a hostname would misclassify its family.
func parseAddressLiteral(address string) (netip.Addr, bool) {
	address = strings.TrimSpace(address)
	if strings.HasPrefix(address, "[") && strings.HasSuffix(address, "]") {
		address = strings.TrimPrefix(strings.TrimSuffix(address, "]"), "[")
	}
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

// isLoopbackLiteral reports whether address is a loopback IP literal. A
// loopback stub resolver is answered by the host's own stack, so it stays
// reachable no matter which families have external routes.
func isLoopbackLiteral(address string) bool {
	addr, ok := parseAddressLiteral(address)
	return ok && addr.IsLoopback()
}

// FilterProfilesByFamily keeps only addresses compatible with family. The
// available map is used by FamilyAuto and should contain the families visible
// on the host's usable interfaces. If auto-detection finds none, both literal
// families are retained as a conservative no-probe fallback. Hostnames are
// retained for auto and both because their family is resolved by the endpoint
// connection path; explicit 4/6 selection rejects them rather than silently
// making an untruthful family claim. Loopback literals are exempt from the
// auto filter: a local stub resolver is reachable through the loopback
// interface even when auto-detection sees external routes for one family
// only, so filtering it out would drop a resolver that answers.
//
// The same rule applies to the bootstrap_addresses of every encrypted
// transport, because a transport that has them dials those candidates and
// never the target address. Filtering the addresses alone let a row labelled
// with an IPv6 address measure an IPv4 candidate under --family 6. A
// transport left with no candidate is dropped rather than falling back to
// the target address, which the operator replaced deliberately, and a
// profile left with no transport is dropped like one left with no address.
// The input profiles, their address slices and their transport maps are
// never modified.
func FilterProfilesByFamily(profiles []ResolverProfile, family AddressFamily, available map[AddressFamily]bool) ([]ResolverProfile, error) {
	allowed, err := allowedFamilies(family, available)
	if err != nil {
		return nil, err
	}
	filteredProfiles := make([]ResolverProfile, 0, len(profiles))
	for _, profile := range profiles {
		addresses := make([]string, 0, len(profile.Addresses))
		for _, address := range profile.Addresses {
			address = strings.TrimSpace(address)
			addressFamily, isLiteral := AddressFamilyForAddress(address)
			if !isLiteral {
				if family == Family4 || family == Family6 {
					return nil, fmt.Errorf("resolver %q address %q is not an IP literal; --family %s requires literal addresses", profile.ID, address, family)
				}
				addresses = append(addresses, address)
				continue
			}
			if familyAllowed(address, addressFamily, family, allowed) {
				addresses = append(addresses, address)
			}
		}
		if len(addresses) == 0 {
			continue
		}
		transports := filterBootstrapByFamily(profile.Transports, family, allowed)
		if len(transports) == 0 {
			continue
		}
		profile.Addresses = addresses
		profile.Transports = transports
		filteredProfiles = append(filteredProfiles, profile)
	}
	return filteredProfiles, nil
}

// familyAllowed reports whether a literal of addressFamily survives the
// filter: its family is allowed, or it is a loopback literal under auto.
func familyAllowed(address string, addressFamily, family AddressFamily, allowed map[AddressFamily]bool) bool {
	return allowed[addressFamily] || (family == FamilyAuto && isLoopbackLiteral(address))
}

// filterBootstrapByFamily returns a new transport map whose bootstrap
// candidates all pass the family filter. Validate admits only IP literals as
// candidates, so a candidate with no family is never allowed. Candidate
// order is kept, because it is the order the transport tries them in.
func filterBootstrapByFamily(transports map[Protocol]TransportSpec, family AddressFamily, allowed map[AddressFamily]bool) map[Protocol]TransportSpec {
	filtered := make(map[Protocol]TransportSpec, len(transports))
	for protocol, spec := range transports {
		if len(spec.BootstrapAddresses) == 0 {
			filtered[protocol] = spec
			continue
		}
		candidates := make([]string, 0, len(spec.BootstrapAddresses))
		for _, candidate := range spec.BootstrapAddresses {
			candidateFamily, _ := AddressFamilyForAddress(candidate)
			if familyAllowed(candidate, candidateFamily, family, allowed) {
				candidates = append(candidates, candidate)
			}
		}
		if len(candidates) == 0 {
			continue
		}
		spec.BootstrapAddresses = candidates
		filtered[protocol] = spec
	}
	return filtered
}

func allowedFamilies(family AddressFamily, available map[AddressFamily]bool) (map[AddressFamily]bool, error) {
	allowed := make(map[AddressFamily]bool, 2)
	switch family {
	case Family4:
		allowed[Family4] = true
	case Family6:
		allowed[Family6] = true
	case FamilyBoth:
		allowed[Family4] = true
		allowed[Family6] = true
	case FamilyAuto:
		allowed[Family4] = available[Family4]
		allowed[Family6] = available[Family6]
		if !allowed[Family4] && !allowed[Family6] {
			allowed[Family4] = true
			allowed[Family6] = true
		}
	default:
		return nil, fmt.Errorf("unsupported address family %q (choose 4, 6, both, or auto)", family)
	}
	return allowed, nil
}
