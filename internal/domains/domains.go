package domains

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/crypt0rr/dns-speedtest/data"
	"github.com/miekg/dns"
)

// Load returns either the embedded corpus or a user-provided newline-delimited
// list. Empty lines, comments, duplicates, and a trailing root dot are handled
// consistently in both modes.
func Load(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return validate(data.Domains())
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open domain list: %w", err)
	}
	defer file.Close()
	return loadReader(file)
}

func loadReader(reader io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024), 64*1024)
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read domain list: %w", err)
	}
	return validate(lines)
}

func validate(lines []string) ([]string, error) {
	seen := make(map[string]struct{}, len(lines))
	domains := make([]string, 0, len(lines))
	for _, line := range lines {
		name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(line)), ".")
		if name == "" || strings.HasPrefix(name, "#") {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		if _, ok := dns.IsDomainName(name); !ok {
			return nil, fmt.Errorf("invalid domain name %q", name)
		}
		seen[name] = struct{}{}
		domains = append(domains, name)
	}
	if len(domains) == 0 {
		return nil, errors.New("domain list is empty")
	}
	return domains, nil
}
