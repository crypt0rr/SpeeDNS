package domains

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
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

// maxReportedInvalidNames bounds the error text for a badly wrong list, so a
// thousand-line file cannot produce a thousand-line error.
const maxReportedInvalidNames = 10

// rootLabelSeparators lists every code point UTS-46 maps onto the DNS label
// separator: FULL STOP, IDEOGRAPHIC FULL STOP, FULLWIDTH FULL STOP, and
// HALFWIDTH IDEOGRAPHIC FULL STOP.
const rootLabelSeparators = ".\u3002\uff0e\uff61"

// CacheMissZone is the IANA-reserved example zone used only by the explicit
// cache-miss mode. SpeeDNS never sends these names unless the user opts in.
const CacheMissZone = "example.com"

const (
	CacheMissDefaultSample  = 10
	CacheMissMaxSample      = 20
	CacheMissMaxConcurrency = 2
)

// lookupProfile keeps the full UTS #46 lookup mapping, the RFC 5891 label
// validation, the DNS length limits, and the Bidi rule. STD3 ASCII rules are
// disabled because they reject the underscore that RFC 8552 service labels
// require; checkLabelSyntax below restores the letter-digit-hyphen restriction
// STD3 provided, with a single leading underscore as the only exception.
var lookupProfile = idna.New(
	idna.MapForLookup(),
	idna.StrictDomainName(false),
	idna.VerifyDNSLength(true),
	idna.BidiRule(),
)

var verifyEmbeddedCorpus = data.VerifyCorpus
var randomRead = rand.Read

type domainInput struct {
	value string
	line  int
}

// Load returns either the embedded corpus or a user-provided newline-delimited
// list. Empty lines, comments, duplicates, and a trailing root dot are handled
// consistently in both modes. Any entry that is not a usable domain name fails
// the whole list.
func Load(path string) ([]string, error) {
	result, err := LoadTolerant(path, false)
	return result.Names, err
}

// LoadResult carries a loaded corpus and, when invalid entries were skipped
// rather than rejected, a bounded description of what was dropped.
type LoadResult struct {
	Names   []string
	Skipped []string
}

// LoadTolerant loads a corpus, optionally skipping entries that are not usable
// domain names instead of failing the list.
//
// Skipping is never the default. A run measures a corpus whose size and digest
// are recorded in the report, so quietly benchmarking a subset of what the
// caller supplied would make that provenance describe a file rather than a
// measurement. A caller that opts in is expected to disclose the difference.
//
// A list with no usable entry still fails: there is nothing to measure, and
// reporting an empty corpus would be worse than an error.
func LoadTolerant(path string, skipInvalid bool) (LoadResult, error) {
	if strings.TrimSpace(path) == "" {
		if _, err := verifyEmbeddedCorpus(); err != nil {
			return LoadResult{}, fmt.Errorf("verify embedded domain corpus: %w", err)
		}
		// The embedded corpus is pinned and checksum-verified, so it is never
		// loaded tolerantly: an invalid entry there is a build problem.
		names, err := Normalize(data.Domains())
		return LoadResult{Names: names}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return LoadResult{}, fmt.Errorf("open domain list: %w", err)
	}
	defer file.Close()
	if skipInvalid {
		return loadReaderSkipping(file)
	}
	names, err := loadReader(file)
	return LoadResult{Names: names}, err
}

func loadReader(reader io.Reader) ([]string, error) {
	lines, err := scanDomainLines(reader)
	if err != nil {
		return nil, err
	}
	return validateInputs(lines)
}

// scanDomainLines reads a newline-delimited list, dropping blank lines and
// comments and remembering each remaining entry's line number.
func scanDomainLines(reader io.Reader) ([]domainInput, error) {
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
	return lines, nil
}

// loadReaderSkipping reads a list and drops entries that are not usable names.
func loadReaderSkipping(reader io.Reader) (LoadResult, error) {
	lines, err := scanDomainLines(reader)
	if err != nil {
		return LoadResult{}, err
	}
	return validateInputsSkipping(lines)
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

// CorpusDigest returns the SHA-256 digest of the exact normalized domain
// sequence used by a benchmark. The canonical representation is one name per
// line with a final LF, matching the embedded corpus metadata convention.
func CorpusDigest(names []string) string {
	canonical := strings.Join(names, "\n")
	if len(names) > 0 {
		canonical += "\n"
	}
	digest := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(digest[:])
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
	// Every invalid entry is collected before failing. Returning on the first
	// one made fixing a large list an edit-and-retry loop, one line per run.
	var invalid []string
	for _, input := range inputs {
		name, err := normalize(input.value)
		if err != nil {
			if len(invalid) < maxReportedInvalidNames {
				if input.line > 0 {
					invalid = append(invalid, fmt.Sprintf("line %d %q: %v", input.line, input.value, err))
				} else {
					invalid = append(invalid, fmt.Sprintf("%q: %v", input.value, err))
				}
			}
			continue
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
	if len(invalid) > 0 {
		suffix := ""
		if len(invalid) == maxReportedInvalidNames {
			suffix = ", and possibly more"
		}
		return nil, fmt.Errorf("invalid domain names: %s%s", strings.Join(invalid, "; "), suffix)
	}
	if len(domains) == 0 {
		return nil, errors.New("domain list is empty")
	}
	return domains, nil
}

// validateInputsSkipping normalizes what it can and describes what it dropped.
// The description is bounded like the rejection error, so a wholly invalid file
// cannot produce an unbounded warning.
func validateInputsSkipping(inputs []domainInput) (LoadResult, error) {
	seen := make(map[string]struct{}, len(inputs))
	names := make([]string, 0, len(inputs))
	skipped := make([]string, 0)
	dropped := 0
	for _, input := range inputs {
		name, err := normalize(input.value)
		if err != nil {
			dropped++
			// Only a file read reaches here, so every entry has a line number.
			if len(skipped) < maxReportedInvalidNames {
				skipped = append(skipped, fmt.Sprintf("line %d %q: %v", input.line, input.value, err))
			}
			continue
		}
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	if len(names) == 0 {
		return LoadResult{}, errors.New("domain list has no usable names")
	}
	if dropped > len(skipped) {
		skipped = append(skipped, fmt.Sprintf("and %d more", dropped-len(skipped)))
	}
	return LoadResult{Names: names, Skipped: skipped}, nil
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

	// The root label must be removed before IDNA processing. UTS-46 ToASCII
	// with VerifyDNSLength rejects a trailing empty label, so trimming
	// afterwards makes acceptance depend on the Unicode tables the building
	// Go toolchain selects (x/net/idna ships tables15 for < go1.27 and
	// tables17 for go1.27+). UTS-46 also maps the ideographic and fullwidth
	// stops onto the ASCII separator, so every form has to be trimmed here.
	value = strings.TrimRight(value, rootLabelSeparators)
	if value == "" {
		return "", nil
	}
	name, err := lookupProfile.ToASCII(value)
	if err != nil {
		return "", err
	}
	// main now trims the root label before ToASCII, so no trailing dot can
	// survive to here; only case folding remains.
	name = strings.ToLower(name)
	if err := checkLabelSyntax(name); err != nil {
		return "", err
	}
	return name, nil
}

// checkLabelSyntax re-applies the RFC 1034 letter-digit-hyphen rule that the
// IDNA profile no longer enforces. One leading underscore per label is allowed
// so the underscored service names of RFC 8552 round-trip unchanged: SRV
// (RFC 2782), TLSA (RFC 6698), DMARC (RFC 7489) and DKIM all address an
// attribute leaf such as "_dmarc" or "_sip._tcp". Those specifications only
// ever place the underscore first, so an underscore elsewhere in a label stays
// rejected along with every other non-LDH ASCII character.
func checkLabelSyntax(name string) error {
	for _, label := range strings.Split(name, ".") {
		body := strings.TrimPrefix(label, "_")
		if body == "" {
			return fmt.Errorf("label %q must name a host or service", label)
		}
		for _, character := range body {
			allowed := (character >= 'a' && character <= 'z') ||
				(character >= '0' && character <= '9') ||
				character == '-'
			if !allowed {
				return fmt.Errorf("label %q may only contain letters, digits, hyphens, and a leading underscore", label)
			}
		}
	}
	return nil
}
