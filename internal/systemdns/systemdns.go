package systemdns

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/crypt0rr/SpeeDNS/internal/safetext"
)

var macOSResolverHeader = regexp.MustCompile(`^\s*resolver\s+#\s*([0-9]+)\s*$`)
var macOSNameServer = regexp.MustCompile(`^\s*nameserver\[[0-9]+\]\s*:\s*(\S+)\s*$`)

// macOSScope matches only the `domain :` line of a resolver block, which makes
// the block a supplemental resolver for that domain. A `search domain[n]` line
// is the suffix search list, which expands short names but does not limit
// which queries the resolver answers; DHCP puts one on the default resolver of
// most networks, so treating it as a scope labelled the default resolver as a
// split-DNS one.
var macOSScope = regexp.MustCompile(`^\s*domain\s*:\s*(\S+)\s*$`)
var macOSInterface = regexp.MustCompile(`^\s*if_index\s*:\s*([0-9]+)(?:\s+\(([^)]+)\))?\s*$`)

var currentOS = runtime.GOOS

// resolvConfPath is the resolver configuration file read on every platform
// that is not macOS. It is a variable so tests can exercise the real reader
// against a fixture file instead of the host configuration.
var resolvConfPath = "/etc/resolv.conf"

// resolvConfPlatforms lists the operating systems that publish the active
// resolver set through /etc/resolv.conf. macOS and Windows are handled
// separately; anything outside all three has no discovery implementation here,
// and opening a Unix path there would report a missing file rather than the
// real limitation.
var resolvConfPlatforms = map[string]bool{
	"aix":       true,
	"android":   true,
	"darwin":    true,
	"dragonfly": true,
	"freebsd":   true,
	"illumos":   true,
	"ios":       true,
	"linux":     true,
	"netbsd":    true,
	"openbsd":   true,
	"solaris":   true,
}

// ErrUnsupportedPlatform reports that system resolver discovery has no
// implementation for the running operating system. Callers that selected
// other resolvers can treat it as a warning instead of a fatal error.
var ErrUnsupportedPlatform = errors.New("system resolver discovery is not supported on this platform")

// UnsupportedPlatformError names the platform that cannot be inspected. Linux
// and the BSDs are read through /etc/resolv.conf, macOS through scutil, and
// Windows through GetAdaptersAddresses; a platform outside those exposes its
// resolver set some other way that this build does not know about.
type UnsupportedPlatformError struct {
	OS string
}

func (e *UnsupportedPlatformError) Error() string {
	return fmt.Sprintf("system resolver discovery is not supported on %s; pass --resolver to benchmark a specific address", e.OS)
}

func (e *UnsupportedPlatformError) Unwrap() error { return ErrUnsupportedPlatform }

var openResolvConf = func() (io.ReadCloser, error) {
	return os.Open(resolvConfPath)
}

// resolvedUplinkPath is where systemd-resolved publishes, in resolv.conf
// format, the DNS servers it forwards to. When /etc/resolv.conf names only
// its loopback stub, this file is the one read-only place that says which
// upstream the host's lookups actually reach. It is a variable, with an
// opener seam beside it, so tests read a fixture instead of the host file.
var resolvedUplinkPath = "/run/systemd/resolve/resolv.conf"

var openResolvedUplink = func() (io.ReadCloser, error) {
	return os.Open(resolvedUplinkPath)
}

// resolvedUplinkPolicy says what a profile read from resolvedUplinkPath
// cannot show. The file is a flattened view of resolved's configuration: it
// holds only the servers of default-route links, so a split-DNS or VPN link
// that answers only its routing domains is absent, and resolv.conf syntax has
// no way to carry a DNS-over-TLS setting or a non-standard port. It is a table
// column, so it stays short; the documentation spells the limits out.
const resolvedUplinkPolicy = "unknown; split DNS, DoT and ports not shown"

// scutilCommand builds the read-only macOS resolver query. It is separated
// from runScutil so tests can assert the command name and arguments without
// executing anything.
var scutilCommand = func(ctx context.Context) *exec.Cmd {
	return exec.CommandContext(ctx, "scutil", "--dns")
}

var runScutil = func(ctx context.Context) ([]byte, error) {
	return scutilCommand(ctx).Output()
}

const defaultScutilTimeout = 2 * time.Second

var scutilTimeout = defaultScutilTimeout

type resolverSource struct {
	Address   string
	Block     int
	Scope     string
	Interface string
	// Uplink marks a server read from systemd-resolved's uplink file rather
	// than from the resolver configuration the host's lookups use directly.
	Uplink bool
}

type macOSResolverBlock struct {
	Number      int
	Scopes      []string
	Interface   string
	Nameservers []string
}

// Discover reads the current system resolver configuration without changing
// it. macOS exposes scoped resolver blocks through scutil; Windows exposes
// per-adapter resolver sets through GetAdaptersAddresses; Linux generally
// exposes the active set through resolv.conf (including a systemd-resolved
// stub). Each macOS block and each Windows adapter remains a separate system
// profile, even when two of them contain the same nameserver address. On
// Linux, a resolv.conf that names only loopback stubs is followed by the
// servers systemd-resolved forwards to, as extra profiles after the stub.
func Discover(ctx context.Context) ([]catalog.ResolverProfile, error) {
	var sources []resolverSource
	var err error
	switch {
	case currentOS == "darwin":
		sources, err = discoverMacOSSources(ctx)
	case currentOS == "windows":
		sources, err = discoverWindowsSources()
	case resolvConfPlatforms[currentOS]:
		var addresses []string
		addresses, err = discoverResolvConf()
		sources = plainSources(addresses)
		if currentOS == "linux" {
			sources = append(sources, resolvedUplinkSources(sources)...)
		}
	default:
		return nil, &UnsupportedPlatformError{OS: currentOS}
	}
	if err != nil {
		return nil, err
	}
	profiles := profilesFromSources(sources)
	if len(profiles) == 0 {
		return nil, fmt.Errorf("no system nameservers found")
	}
	return profiles, nil
}

func discoverMacOSSources(ctx context.Context) ([]resolverSource, error) {
	scutilContext, cancel := context.WithTimeout(ctx, scutilTimeout)
	defer cancel()
	output, err := runScutil(scutilContext)
	if err == nil {
		sources := parseMacOSSources(output)
		if len(sources) > 0 {
			return sources, nil
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	addresses, fallbackErr := discoverResolvConf()
	if fallbackErr != nil {
		return nil, fallbackErr
	}
	return plainSources(addresses), nil
}

func parseMacOSSources(output []byte) []resolverSource {
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	var sources []resolverSource
	var block *macOSResolverBlock
	flush := func() {
		if block == nil {
			return
		}
		scope := strings.Join(uniqueStrings(block.Scopes), ",")
		if scope == "" {
			scope = "global"
		}
		seen := make(map[string]struct{}, len(block.Nameservers))
		for _, rawAddress := range block.Nameservers {
			address, ok := normalizeAddress(rawAddress)
			if !ok {
				continue
			}
			if _, exists := seen[address]; exists {
				continue
			}
			seen[address] = struct{}{}
			sources = append(sources, resolverSource{
				Address: address, Block: block.Number, Scope: scope,
				Interface: block.Interface,
			})
		}
	}
	for scanner.Scan() {
		line := scanner.Text()
		if match := macOSResolverHeader.FindStringSubmatch(line); len(match) == 2 {
			flush()
			number, _ := strconv.Atoi(match[1])
			block = &macOSResolverBlock{Number: number}
			continue
		}
		if block == nil {
			continue
		}
		if match := macOSNameServer.FindStringSubmatch(line); len(match) == 2 {
			block.Nameservers = append(block.Nameservers, match[1])
			continue
		}
		if match := macOSScope.FindStringSubmatch(line); len(match) == 2 {
			block.Scopes = append(block.Scopes, match[1])
			continue
		}
		if match := macOSInterface.FindStringSubmatch(line); len(match) >= 2 {
			if len(match) == 3 && strings.TrimSpace(match[2]) != "" {
				block.Interface = strings.TrimSpace(match[2])
			} else {
				block.Interface = "if-index-" + match[1]
			}
		}
	}
	flush()
	return sources
}

func plainSources(addresses []string) []resolverSource {
	sources := make([]resolverSource, 0, len(addresses))
	for _, address := range addresses {
		if normalized, ok := normalizeAddress(address); ok {
			sources = append(sources, resolverSource{Address: normalized})
		}
	}
	return sources
}

// normalizeAddress canonicalizes a configured nameserver literal. netip
// parsing is required because a link-local IPv6 nameserver carries a zone
// ("fe80::1%en0") that net.ParseIP rejects; dropping it would hide the only
// resolver on a host whose router advertises a link-local address.
//
// netip accepts any text as a zone, while catalog.Validate rejects an address
// with a control or invisible character, because the address is part of the
// target ID. Such a nameserver is skipped here, like any other entry that is
// not an address, so one odd line of OS configuration cannot fail the whole
// --include-system run.
func normalizeAddress(address string) (string, bool) {
	address = strings.TrimSpace(address)
	parsed, err := netip.ParseAddr(address)
	if err != nil {
		return "", false
	}
	if zone := parsed.Zone(); safetext.Escape(zone) != zone {
		return "", false
	}
	return parsed.Unmap().String(), true
}

func profilesFromSources(sources []resolverSource) []catalog.ResolverProfile {
	profiles := make([]catalog.ResolverProfile, 0, len(sources))
	seen := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		address, ok := normalizeAddress(source.Address)
		if !ok {
			continue
		}
		dedupeKey := address
		if source.Block > 0 {
			dedupeKey = fmt.Sprintf("%d/%s", source.Block, address)
		}
		if source.Uplink {
			dedupeKey = "uplink/" + address
		}
		if _, exists := seen[dedupeKey]; exists {
			continue
		}
		seen[dedupeKey] = struct{}{}

		name := "System DNS"
		owner := "configured locally"
		policy := "unknown"
		id := "system-" + sanitizeAddress(address)
		local := isLocalStub(address)
		if local {
			name = "System DNS stub"
			owner = "local stub/forwarder"
			policy = "local forwarding (upstream unknown)"
			id = "system-stub-" + sanitizeAddress(address)
		}
		if source.Uplink {
			// The system- prefix keeps the profile under --redact-system, and
			// the label says where the address came from: the stub stays the
			// row the host's lookups use, and this one is what it forwards to.
			name = "System DNS (systemd-resolved default route)"
			owner = "configured locally (systemd-resolved default route)"
			policy = resolvedUplinkPolicy
			id = "system-resolved-" + sanitizeAddress(address)
		}
		if source.Block > 0 {
			// The scope and interface come from the operating system - a
			// DHCP-supplied domain, a user-renamed adapter - and
			// catalog.Validate rejects a name or owner that would not print
			// as written. Escaping the label keeps such a host's resolvers in
			// the run, shown the way every report renders them anyway.
			label := safetext.Escape(sourceLabel(source))
			name += " (" + label + ")"
			owner += " (" + label + ")"
			id = fmt.Sprintf("system-resolver-%d-%s", source.Block, sanitizeAddress(address))
		}
		profiles = append(profiles, catalog.ResolverProfile{
			ID: id, Name: name, Owner: owner, Policy: policy,
			Scope: source.Scope, Interface: source.Interface, Local: local,
			Addresses: []string{address},
			Transports: map[catalog.Protocol]catalog.TransportSpec{
				catalog.UDP: {Port: 53},
				catalog.TCP: {Port: 53},
			},
		})
	}
	return profiles
}

func isLocalStub(address string) bool {
	parsed, err := netip.ParseAddr(address)
	return err == nil && parsed.IsLoopback()
}

func sourceLabel(source resolverSource) string {
	parts := make([]string, 0, 2)
	if source.Scope != "" {
		parts = append(parts, "scope: "+source.Scope)
	}
	if source.Interface != "" {
		parts = append(parts, "interface: "+source.Interface)
	}
	if len(parts) == 0 {
		return "resolver block"
	}
	return strings.Join(parts, "; ")
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func sanitizeAddress(address string) string {
	return strings.NewReplacer(":", "-", ".", "-", "%", "-").Replace(address)
}

func discoverResolvConf() ([]string, error) {
	file, err := openResolvConf()
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", resolvConfPath, err)
	}
	defer file.Close()
	addresses, err := scanNameservers(file)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", resolvConfPath, err)
	}
	return addresses, nil
}

// scanNameservers returns the nameserver entries of a resolv.conf-format file
// in the order listed.
func scanNameservers(reader io.Reader) ([]string, error) {
	var addresses []string
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			addresses = append(addresses, fields[1])
		}
	}
	return addresses, scanner.Err()
}

// resolvedUplinkSources returns the servers systemd-resolved forwards to when
// every nameserver in sources is a loopback stub, and nothing otherwise. A
// stub-only resolv.conf leaves --include-system with one row that is never
// ranked, so the host's real upstream - its router or ISP resolver - was
// never compared. Each non-loopback uplink becomes its own network profile
// next to the unchanged stub. The file is optional: a missing or unreadable
// one means the host is not running resolved, or not in a form this reader
// understands, and discovery then returns exactly what resolv.conf gives.
func resolvedUplinkSources(sources []resolverSource) []resolverSource {
	if len(sources) == 0 {
		return nil
	}
	for _, source := range sources {
		if !isLocalStub(source.Address) {
			return nil
		}
	}
	file, err := openResolvedUplink()
	if err != nil {
		return nil
	}
	defer file.Close()
	addresses, err := scanNameservers(file)
	if err != nil {
		return nil
	}
	var uplinks []resolverSource
	for _, source := range plainSources(addresses) {
		if isLocalStub(source.Address) {
			continue
		}
		source.Uplink = true
		uplinks = append(uplinks, source)
	}
	return uplinks
}
