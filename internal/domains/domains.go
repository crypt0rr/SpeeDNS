package domains

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/crypt0rr/dns-speedtest/data"
	"golang.org/x/net/idna"
)

const maxDomainLineSize = 64 * 1024

var lookupProfile = idna.New(idna.MapForLookup(), idna.VerifyDNSLength(true), idna.BidiRule())

type domainInput struct {
	value string
	line  int
}

// Load returns either the embedded corpus or a user-provided newline-delimited
// list. Empty lines, comments, duplicates, and a trailing root dot are handled
// consistently in both modes.
func Load(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return Normalize(data.Domains())
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
	scanner.Buffer(make([]byte, 1024), maxDomainLineSize)
	var lines []domainInput
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, domainInput{value: line, line: lineNumber})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read domain list: %w", err)
	}
	return validateInputs(lines)
}

func validate(lines []string) ([]string, error) {
	return Normalize(lines)
}

// Normalize validates and canonicalizes a list of domain names. It is shared
// by embedded data, custom files, and benchmark callers that provide names
// directly instead of going through Load.
func Normalize(lines []string) ([]string, error) {
	inputs := make([]domainInput, 0, len(lines))
	for _, line := range lines {
		inputs = append(inputs, domainInput{value: line})
	}
	return validateInputs(inputs)
}

func validateInputs(inputs []domainInput) ([]string, error) {
	seen := make(map[string]struct{}, len(inputs))
	domains := make([]string, 0, len(inputs))
	for _, input := range inputs {
		name, err := normalize(input.value)
		if err != nil {
			if input.line > 0 {
				return nil, fmt.Errorf("invalid domain name on line %d %q: %w", input.line, input.value, err)
			}
			return nil, fmt.Errorf("invalid domain name %q: %w", input.value, err)
		}
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		domains = append(domains, name)
	}
	if len(domains) == 0 {
		return nil, errors.New("domain list is empty")
	}
	return domains, nil
}

func normalize(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) {
		return "", errors.New("input is not valid UTF-8")
	}
	if value == "" || strings.HasPrefix(value, "#") {
		return "", nil
	}
	if value == "." {
		return "", nil
	}
	for _, character := range value {
		if unicode.IsSpace(character) {
			return "", errors.New("whitespace is not allowed")
		}
		if unicode.IsControl(character) {
			return "", errors.New("control characters are not allowed")
		}
	}
	if strings.Contains(value, "*") {
		return "", errors.New("wildcards are not allowed")
	}
	if strings.Contains(value, "..") {
		return "", errors.New("empty labels are not allowed")
	}

	name, err := lookupProfile.ToASCII(value)
	if err != nil {
		return "", err
	}
	name = strings.TrimSuffix(name, ".")
	return strings.ToLower(name), nil
}
