package systemdns

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/catalog"
)

var macOSResolverHeader = regexp.MustCompile(`^\s*resolver\s+#\s*([0-9]+)\s*$`)
var macOSNameServer = regexp.MustCompile(`^\s*nameserver\[[0-9]+\]\s*:\s*(\S+)\s*$`)
var macOSScope = regexp.MustCompile(`^\s*(?:domain|search\s+domain\[[0-9]+\])\s*:\s*(\S+)\s*$`)
var macOSInterface = regexp.MustCompile(`^\s*if_index\s*:\s*([0-9]+)(?:\s+\(([^)]+)\))?\s*$`)

var currentOS = runtime.GOOS

var openResolvConf = func() (io.ReadCloser, error) {
	return os.Open("/etc/resolv.conf")
}

var runScutil = func(ctx context.Context) ([]byte, error) {
	return exec.CommandContext(ctx, "scutil", "--dns").Output()
}

const defaultScutilTimeout = 2 * time.Second

var scutilTimeout = defaultScutilTimeout

type resolverSource struct {
	Address   string
	Block     int
	Scope     string
	Interface string
}

type macOSResolverBlock struct {
	Number      int
	Scopes      []string
	Interface   string
	Nameservers []string
}

// Discover reads the current system resolver configuration without changing
// it. macOS exposes scoped resolver blocks through scutil; Linux generally
// exposes the active set through resolv.conf (including a systemd-resolved
// stub). Each macOS block remains a separate system profile, even when two
// blocks contain the same nameserver address.
func Discover(ctx context.Context) ([]catalog.ResolverProfile, error) {
	var sources []resolverSource
	var err error
	if currentOS == "darwin" {
		sources, err = discoverMacOSSources(ctx)
	} else {
		var addresses []string
		addresses, err = discoverResolvConf()
		sources = plainSources(addresses)
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

func normalizeAddress(address string) (string, bool) {
	address = strings.TrimSpace(address)
	ip := net.ParseIP(address)
	if ip == nil {
		return "", false
	}
	return ip.String(), true
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
		if source.Block > 0 {
			label := sourceLabel(source)
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
	ip := net.ParseIP(address)
	return ip != nil && ip.IsLoopback()
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
	return strings.NewReplacer(":", "-", ".", "-").Replace(address)
}

func discoverResolvConf() ([]string, error) {
	file, err := openResolvConf()
	if err != nil {
		return nil, fmt.Errorf("open /etc/resolv.conf: %w", err)
	}
	defer file.Close()
	var addresses []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			addresses = append(addresses, fields[1])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read /etc/resolv.conf: %w", err)
	}
	return addresses, nil
}
