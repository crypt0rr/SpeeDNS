package catalog

import (
	"fmt"
	"net"
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
	address = strings.TrimSpace(address)
	if strings.HasPrefix(address, "[") && strings.HasSuffix(address, "]") {
		address = strings.TrimPrefix(strings.TrimSuffix(address, "]"), "[")
	}
	ip := net.ParseIP(address)
	if ip == nil {
		return "", false
	}
	if ip.To4() != nil {
		return Family4, true
	}
	return Family6, true
}

// FilterProfilesByFamily keeps only addresses compatible with family. The
// available map is used by FamilyAuto and should contain the families visible
// on the host's usable interfaces. If auto-detection finds none, both literal
// families are retained as a conservative no-probe fallback. Hostnames are
// retained for auto and both because their family is resolved by the endpoint
// connection path; explicit 4/6 selection rejects them rather than silently
// making an untruthful family claim.
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
			if allowed[addressFamily] {
				addresses = append(addresses, address)
			}
		}
		if len(addresses) == 0 {
			continue
		}
		profile.Addresses = addresses
		filteredProfiles = append(filteredProfiles, profile)
	}
	return filteredProfiles, nil
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
