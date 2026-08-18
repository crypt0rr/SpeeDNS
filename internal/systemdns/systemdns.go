package systemdns

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"github.com/crypt0rr/dns-speedtest/internal/catalog"
)

var macOSNameServer = regexp.MustCompile(`nameserver\[[0-9]+\]\s*:\s*(\S+)`)

var currentOS = runtime.GOOS

var openResolvConf = func() (io.ReadCloser, error) {
	return os.Open("/etc/resolv.conf")
}

var runScutil = func(ctx context.Context) ([]byte, error) {
	return exec.CommandContext(ctx, "scutil", "--dns").Output()
}

// Discover reads the current system resolver configuration without changing
// it. macOS exposes scoped resolvers through scutil; Linux generally exposes
// the active set through resolv.conf (including a systemd-resolved stub).
func Discover(ctx context.Context) ([]catalog.ResolverProfile, error) {
	var addresses []string
	var err error
	if currentOS == "darwin" {
		addresses, err = discoverMacOS(ctx)
	} else {
		addresses, err = discoverResolvConf()
	}
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no system nameservers found")
	}
	profiles := make([]catalog.ResolverProfile, 0, len(addresses))
	seen := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		address = strings.TrimSpace(address)
		if address == "" {
			continue
		}
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		profiles = append(profiles, catalog.ResolverProfile{
			ID:        "system-" + strings.NewReplacer(":", "-", ".", "-").Replace(address),
			Name:      "System DNS",
			Owner:     "configured locally",
			Policy:    "unknown",
			Addresses: []string{address},
			Transports: map[catalog.Protocol]catalog.TransportSpec{
				catalog.UDP: {Port: 53},
				catalog.TCP: {Port: 53},
			},
		})
	}
	return profiles, nil
}

func discoverMacOS(ctx context.Context) ([]string, error) {
	output, err := runScutil(ctx)
	if err == nil {
		matches := macOSNameServer.FindAllStringSubmatch(string(output), -1)
		addresses := make([]string, 0, len(matches))
		for _, match := range matches {
			if len(match) == 2 {
				addresses = append(addresses, match[1])
			}
		}
		if len(addresses) > 0 {
			return addresses, nil
		}
	}
	return discoverResolvConf()
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
