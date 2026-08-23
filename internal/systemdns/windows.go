package systemdns

import (
	"strconv"
	"strings"
)

// windowsAdapter is one network adapter's DNS configuration as reported by the
// operating system, reduced to the fields this package needs. Keeping the
// Windows API call behind this shape lets every decision below — which
// adapters count, which addresses are real, how they are labeled — be tested
// on any host, the way the macOS path is tested through scutil output.
type windowsAdapter struct {
	// Index is the operating system's interface index, used as the address
	// zone when the adapter advertises a link-local IPv6 resolver.
	Index int
	// Name is the adapter's friendly name ("Wi-Fi", "Ethernet", a VPN's
	// tunnel name), which is what an operator recognizes in a report.
	Name string
	// Nameservers holds the configured resolver addresses in the order the
	// operating system returns them, which is the order it queries them.
	Nameservers []string
}

// discoverWindowsAdapters reads the live adapter table. It is a variable so
// tests can supply an adapter set instead of calling into iphlpapi, and it is
// the only part of the Windows path that is platform-specific.
var discoverWindowsAdapters = platformWindowsAdapters

// windowsPlaceholderResolvers lists the site-local addresses Windows presents
// as IPv6 nameservers on adapters that have no IPv6 DNS configured at all.
// They are a legacy default, not resolvers: benchmarking them measures a
// guaranteed timeout and would rank a phantom target against real ones.
var windowsPlaceholderResolvers = map[string]struct{}{
	"fec0:0:0:ffff::1": {},
	"fec0:0:0:ffff::2": {},
	"fec0:0:0:ffff::3": {},
}

func discoverWindowsSources() ([]resolverSource, error) {
	adapters, err := discoverWindowsAdapters()
	if err != nil {
		return nil, err
	}
	return windowsSources(adapters), nil
}

// windowsSources turns adapters into resolver sources. Each adapter that
// configures at least one usable nameserver becomes its own numbered block,
// mirroring how macOS scutil blocks are kept separate: a laptop on Wi-Fi with
// a VPN up has two independent resolver sets, and collapsing them would hide
// the comparison the operator most wants. Blocks are numbered over the
// adapters that contribute, not over the raw table, so an unconfigured adapter
// does not leave a gap in the report.
func windowsSources(adapters []windowsAdapter) []resolverSource {
	sources := make([]resolverSource, 0, len(adapters))
	block := 0
	for _, adapter := range adapters {
		addresses := usableWindowsResolvers(adapter.Nameservers)
		if len(addresses) == 0 {
			continue
		}
		block++
		label := windowsInterfaceLabel(adapter)
		for _, address := range addresses {
			sources = append(sources, resolverSource{
				Address:   address,
				Block:     block,
				Interface: label,
			})
		}
	}
	return sources
}

// usableWindowsResolvers keeps the configured addresses that can actually be
// queried, in the order Windows would try them, without repeats. An adapter
// commonly lists the same resolver for IPv4 and IPv6 discovery.
func usableWindowsResolvers(nameservers []string) []string {
	addresses := make([]string, 0, len(nameservers))
	seen := make(map[string]struct{}, len(nameservers))
	for _, nameserver := range nameservers {
		address, ok := normalizeAddress(nameserver)
		if !ok {
			continue
		}
		if _, placeholder := windowsPlaceholderResolvers[address]; placeholder {
			continue
		}
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
	}
	return addresses
}

// windowsInterfaceLabel names the adapter for the report. A friendly name is
// what the operator sees in Windows itself; the interface index is the fallback
// when the adapter has none, matching how an unnamed macOS block is labeled.
func windowsInterfaceLabel(adapter windowsAdapter) string {
	if name := collapseSpaces(adapter.Name); name != "" {
		return name
	}
	if adapter.Index > 0 {
		return "if-index-" + strconv.Itoa(adapter.Index)
	}
	return ""
}

// collapseSpaces reduces an adapter name to a single line of single-spaced
// words. Adapter names are user-editable, and a name carrying a newline would
// otherwise break the aligned table this string ends up in.
func collapseSpaces(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
