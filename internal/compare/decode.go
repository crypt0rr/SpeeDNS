// Package compare answers one question about two saved SpeeDNS reports: did any
// resolver behave differently between them?
//
// It deliberately never answers "was it faster". The confound is not sampling
// noise but an unobserved variable -- the network path, which anycast site
// answered, the time of day -- and a report contains no field that bounds it,
// so no threshold computed from two reports can bound it either. Measured on
// one host, six byte-identical back-to-back runs moved p95 by up to 248% and
// the composite score by up to 50%, while every categorical count stayed
// identical across all six. That gap is the whole design: what a resolver DID
// is stable enough to compare across runs, how fast it did it is not.
package compare

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// ErrRunsNotComparable reports that the two runs did not measure the same
// thing, so no comparison was produced. It is distinct from
// benchmark.ErrNoComparableResults, which means a single run produced nothing
// rankable.
var ErrRunsNotComparable = errors.New("runs not comparable")

// ErrNothingCompared reports that two comparable runs had no endpoint the diff
// could pair -- every target was incomplete, local, redacted, or present in
// only one run -- so a --require condition that passed did so without reading
// a single count. Like a refusal, it means the gate could not evaluate.
var ErrNothingCompared = errors.New("nothing compared")

// Report is the subset of a published report this package reads.
//
// The gated provenance fields are pointers on purpose. A report written before
// those fields existed omits them, and decoding an absent bool into a plain
// bool yields false -- which would silently compare a DNSSEC run against a
// plain one and attribute the difference to the resolver. Absent must be
// distinguishable from zero, so this type is kept separate from
// report.JSONProvenance rather than reusing it.
type Report struct {
	Path          string
	SchemaVersion *int     `json:"schema_version"`
	Run           *Run     `json:"run"`
	Results       []Result `json:"results"`
	Warnings      []string `json:"warnings"`
}

type Run struct {
	StartedAt        time.Time   `json:"started_at"`
	FinishedAt       time.Time   `json:"finished_at"`
	Seed             *int64      `json:"seed"`
	SampleSize       *int        `json:"sample_size"`
	QueriesPerTarget *int        `json:"queries_per_target"`
	QueryTypes       []int       `json:"query_types"`
	CorpusMode       string      `json:"corpus_mode"`
	CorpusZone       string      `json:"corpus_zone"`
	CorpusNonce      string      `json:"corpus_nonce"`
	Provenance       *Provenance `json:"provenance"`
}

type Provenance struct {
	Version       string   `json:"speedns_version"`
	Commit        string   `json:"commit"`
	OS            string   `json:"os"`
	Architecture  string   `json:"architecture"`
	Interfaces    []string `json:"interfaces"`
	CorpusEntries *int     `json:"corpus_entries"`
	CorpusSHA256  *string  `json:"corpus_sha256"`
	TimeoutMS     *int64   `json:"timeout_ms"`
	Concurrency   *int     `json:"concurrency"`
	Family        *string  `json:"family"`
	DNSSEC        *bool    `json:"dnssec"`
}

type Result struct {
	Target     Target  `json:"target"`
	Stats      Stats   `json:"stats"`
	Status     string  `json:"status"`
	OpenError  string  `json:"open_error"`
	Incomplete bool    `json:"incomplete"`
	DNSSEC     *DNSSEC `json:"dnssec"`
}

type Target struct {
	ID       string `json:"id"`
	Address  string `json:"address"`
	Protocol string `json:"protocol"`
	Local    bool   `json:"local"`
}

type Stats struct {
	Total           int            `json:"total"`
	Successes       int            `json:"successes"`
	UsableResponses int            `json:"usable_responses"`
	Answers         int            `json:"answers"`
	Truncated       int            `json:"truncated"`
	Scored          int            `json:"scored"`
	Divergent       int            `json:"divergent"`
	RCodeCounts     map[string]int `json:"rcode_counts"`
}

type DNSSEC struct {
	Verdict string `json:"verdict"`
}

// maxReportBytes caps how much of one diff input is read. A default report
// stays far below it; only --raw samples over a large custom --domains corpus
// can approach it, because their size grows with the corpus. The cap exists so
// an endless stream such as /dev/zero ends in a usage error instead of
// exhausting memory. It is a variable only so tests can exercise the cap
// without a stream of this size.
var maxReportBytes int64 = 256 << 20

// reportReadChunk is how much of an input is read into one buffer.
const reportReadChunk = 1 << 20

// Load reads a published report. It decodes only the fields this package uses,
// so a report carrying keys it does not know about is read without complaint.
// The path need not be a regular file: a pipe, /dev/stdin and a shell's
// process substitution are read the same way, up to maxReportBytes.
func Load(path string) (Report, error) {
	content, err := readReportInput(path)
	if err != nil {
		return Report{}, err
	}
	var loaded Report
	if err := json.Unmarshal(content, &loaded); err != nil {
		return Report{}, fmt.Errorf("parse %s: %w", path, err)
	}
	loaded.Path = path
	if loaded.SchemaVersion == nil {
		return Report{}, fmt.Errorf("%s has no schema_version; it is not a SpeeDNS report", path)
	}
	if *loaded.SchemaVersion != 1 {
		return Report{}, fmt.Errorf("%s uses schema_version %d; this build reads version 1", path, *loaded.SchemaVersion)
	}
	if loaded.Run == nil {
		return Report{}, fmt.Errorf("%s has no run section", path)
	}
	if loaded.Run.Provenance == nil {
		return Report{}, fmt.Errorf("%s has no run.provenance; it cannot be checked for comparability", path)
	}
	return loaded, nil
}

// readReportInput returns the whole input at path, refusing one larger than
// maxReportBytes. A regular file states its size, so one past the cap is
// refused before any of it is read, and one within it is read into a single
// buffer of that size, as os.ReadFile would. Anything else is read in fixed
// chunks that are joined only once the input has ended within the cap.
// Regrowing a single buffer instead would keep every outgrown copy alive until
// the next garbage collection, so an endless stream would cost several times
// the cap before it was refused; chunks cost the cap and no more.
func readReportInput(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer file.Close()
	limit := fmt.Sprintf("the %d MiB limit for a report", maxReportBytes>>20)
	chunkSize := int64(reportReadChunk)
	if info, err := file.Stat(); err == nil && info.Mode().IsRegular() {
		if info.Size() > maxReportBytes {
			return nil, fmt.Errorf("%s is %d bytes, larger than %s", path, info.Size(), limit)
		}
		// One byte more than the file holds lets the first read reach its
		// end, so a file that did not grow after Stat fills one buffer and is
		// never copied to be joined. The floor keeps a file that reports no
		// size, as procfs files do, from being read a byte at a time.
		chunkSize = max(chunkSize, info.Size()+1)
	}
	// One byte past the cap tells an input of exactly the cap from a larger
	// one without reading the rest of an endless stream.
	input := io.LimitReader(file, maxReportBytes+1)
	var chunks [][]byte
	var total int64
	for {
		chunk := make([]byte, chunkSize)
		n, err := io.ReadFull(input, chunk)
		chunks = append(chunks, chunk[:n])
		total += int64(n)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
	}
	if total > maxReportBytes {
		return nil, fmt.Errorf("%s is larger than %s", path, limit)
	}
	if len(chunks) == 1 {
		return chunks[0], nil
	}
	return bytes.Join(chunks, nil), nil
}

// resultByID indexes a report's results by target ID.
func (r Report) resultByID() map[string]Result {
	index := make(map[string]Result, len(r.Results))
	for _, result := range r.Results {
		index[result.Target.ID] = result
	}
	return index
}
