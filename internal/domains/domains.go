package domains

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/crypt0rr/SpeeDNS/data"
	"golang.org/x/net/idna"
)

const maxDomainLineSize = 64 * 1024

// CacheMissZone is the IANA-reserved example zone used only by the explicit
// cache-miss mode. SpeeDNS never sends these names unless the user opts in.
const CacheMissZone = "example.com"

const (
	CacheMissDefaultSample  = 10
	CacheMissMaxSample      = 20
	CacheMissMaxConcurrency = 2
)

var lookupProfile = idna.New(idna.MapForLookup(), idna.VerifyDNSLength(true), idna.BidiRule())

var verifyEmbeddedCorpus = data.VerifyCorpus
var randomRead = rand.Read

type domainInput struct {
	value string
	line  int
}

// Load returns either the embedded corpus or a user-provided newline-delimited
// list. Empty lines, comments, duplicates, and a trailing root dot are handled
// consistently in both modes.
func Load(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		if _, err := verifyEmbeddedCorpus(); err != nil {
			return nil, fmt.Errorf("verify embedded domain corpus: %w", err)
		}
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

// NewCacheMissNonce returns a local random nonce used to make cache-miss names
// unique between runs. It does not contact the network or persist state.
func NewCacheMissNonce() (string, error) {
	var value [8]byte
	if _, err := randomRead(value[:]); err != nil {
		return "", fmt.Errorf("generate cache-miss nonce: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

// CacheMissNames creates a bounded set of unique names below the reserved
// example zone. The nonce must be hexadecimal so generated labels remain
// syntactically valid and auditable in reports.
func CacheMissNames(nonce string, count int) ([]string, error) {
	nonce = strings.ToLower(strings.TrimSpace(nonce))
	if nonce == "" {
		return nil, errors.New("cache-miss nonce is empty")
	}
	if count <= 0 || count > CacheMissMaxSample {
		return nil, fmt.Errorf("cache-miss sample must be between 1 and %d", CacheMissMaxSample)
	}
	for _, character := range nonce {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return nil, errors.New("cache-miss nonce must be hexadecimal")
		}
	}
	raw := make([]string, 0, count)
	for index := 1; index <= count; index++ {
		raw = append(raw, fmt.Sprintf("speedns-%s-%04d.%s", nonce, index, CacheMissZone))
	}
	return Normalize(raw)
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
