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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// ErrRunsNotComparable reports that the two runs did not measure the same
// thing, so no comparison was produced. It is distinct from
// benchmark.ErrNoComparableResults, which means a single run produced nothing
// rankable.
var ErrRunsNotComparable = errors.New("runs not comparable")

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

// Load reads a published report. It decodes only the fields this package uses,
// so a report carrying keys it does not know about is read without complaint.
func Load(path string) (Report, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Report{}, fmt.Errorf("read %s: %w", path, err)
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

// resultByID indexes a report's results by target ID.
func (r Report) resultByID() map[string]Result {
	index := make(map[string]Result, len(r.Results))
	for _, result := range r.Results {
		index[result.Target.ID] = result
	}
	return index
}
