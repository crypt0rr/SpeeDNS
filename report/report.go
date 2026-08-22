// Package report is the public Go view of a SpeeDNS JSON report.
//
// The types in this package are the ones the SpeeDNS encoder marshals, so a
// consumer decodes exactly what the tool emits. Nothing about the benchmark
// engine itself is exported: this package is a report contract, not an API for
// running benchmarks.
//
// schema_version 1 is the compatibility unit. Decode accepts documents whose
// schema_version equals SchemaVersion and rejects every other value with
// ErrUnsupportedSchemaVersion. Within version 1 the contract only grows:
// fields may be added, so decoding ignores keys this package does not know and
// a consumer must not assume the absence of a key is permanent. The
// machine-readable form of the same contract is published by
// github.com/crypt0rr/SpeeDNS/schema (schema.ReportV1).
//
// Typical use, failing a build when a transport is too slow:
//
//	document, err := report.Decode(os.Stdin)
//	if err != nil {
//		return err
//	}
//	for _, result := range document.Results {
//		if result.Target.Protocol == report.DoT && result.Stats.MedianMS > 40 {
//			return fmt.Errorf("%s: DoT median %.1f ms", result.Target.ID, result.Stats.MedianMS)
//		}
//	}
package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// SchemaVersion is the report schema version this package decodes. It is the
// compatibility unit: a document carrying a different value has a different
// contract and is rejected rather than partially decoded.
const SchemaVersion = 1

// ErrUnsupportedSchemaVersion reports a document whose schema_version is not
// SchemaVersion.
var ErrUnsupportedSchemaVersion = errors.New("unsupported SpeeDNS report schema version")

// Protocol identifies a DNS wire transport.
type Protocol string

const (
	UDP Protocol = "udp"
	TCP Protocol = "tcp"
	DoH Protocol = "doh"
	DoT Protocol = "dot"
	DoQ Protocol = "doq"
)

func (p Protocol) String() string { return string(p) }

// Report is a decoded SpeeDNS JSON report.
type Report struct {
	SchemaVersion      int                 `json:"schema_version"`
	Run                Run                 `json:"run"`
	Results            []Result            `json:"results"`
	Rankings           []Ranking           `json:"rankings"`
	PairedEffects      []PairedEffect      `json:"paired_effects,omitempty"`
	ProfileComparisons []ProfileComparison `json:"profile_comparisons,omitempty"`
	Divergence         []DivergenceDetail  `json:"divergence,omitempty"`
	Warnings           []string            `json:"warnings,omitempty"`
}

// Run describes the benchmark run that produced the report.
type Run struct {
	StartedAt   string      `json:"started_at"`
	FinishedAt  string      `json:"finished_at"`
	Seed        int64       `json:"seed"`
	Provenance  *Provenance `json:"provenance,omitempty"`
	CorpusMode  string      `json:"corpus_mode,omitempty"`
	CorpusZone  string      `json:"corpus_zone,omitempty"`
	CorpusNonce string      `json:"corpus_nonce,omitempty"`
	SampleSize  int         `json:"sample_size"`
	Queries     int         `json:"queries_per_target"`
	QueryTypes  []uint16    `json:"query_types"`
}

// Provenance records the build, platform, corpus, and effective settings a run
// used, so two reports can be compared knowingly.
type Provenance struct {
	SpeeDNSVersion string     `json:"speedns_version"`
	Commit         string     `json:"commit"`
	BuildDate      string     `json:"build_date"`
	OS             string     `json:"os"`
	Architecture   string     `json:"architecture"`
	Interfaces     []string   `json:"interfaces,omitempty"`
	Protocols      []Protocol `json:"protocols"`
	CorpusEntries  int        `json:"corpus_entries"`
	CorpusSHA256   string     `json:"corpus_sha256"`
	TimeoutMS      int64      `json:"timeout_ms"`
	Concurrency    int        `json:"concurrency"`
	DurationMS     float64    `json:"duration_ms"`
}

// ProfileComparison groups the transports of one resolver profile, as emitted
// by the profile view.
type ProfileComparison struct {
	ID         string             `json:"id"`
	Name       string             `json:"name"`
	Owner      string             `json:"owner"`
	Address    string             `json:"address"`
	Transports []ProfileTransport `json:"transports"`
}

// ProfileTransport is one transport of a compared resolver profile. Status is
// a human-facing label and is not a closed set; treat an unknown value as
// informational.
type ProfileTransport struct {
	Protocol Protocol   `json:"protocol"`
	TargetID string     `json:"target_id"`
	Stats    Statistics `json:"stats"`
	Status   string     `json:"status"`
}

// Result is the measurement of one benchmark target. Observations and Cold are
// only present in raw reports.
type Result struct {
	Target       Target            `json:"target"`
	Stats        Statistics        `json:"stats"`
	OpenError    string            `json:"open_error,omitempty"`
	Incomplete   bool              `json:"incomplete,omitempty"`
	Observations []Observation     `json:"samples,omitempty"`
	Cold         []ColdObservation `json:"cold,omitempty"`
}

// Target identifies the resolver endpoint a result was measured against.
type Target struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Owner              string   `json:"owner"`
	Policy             string   `json:"policy"`
	Address            string   `json:"address"`
	Protocol           Protocol `json:"protocol"`
	EndpointURL        string   `json:"endpoint_url,omitempty"`
	TLSServerName      string   `json:"tls_server_name,omitempty"`
	TLSIdentitySource  string   `json:"tls_identity_source,omitempty"`
	BootstrapMode      string   `json:"bootstrap_mode"`
	BootstrapAddresses []string `json:"bootstrap_addresses,omitempty"`
	DialAddress        string   `json:"dial_address,omitempty"`
}

// Statistics summarizes the measured samples for one target.
type Statistics struct {
	Total               int            `json:"total"`
	Successes           int            `json:"successes"`
	Failures            int            `json:"failures"`
	UsableResponses     int            `json:"usable_responses"`
	ResolverFailures    int            `json:"resolver_failures"`
	Scored              int            `json:"scored"`
	Divergent           int            `json:"divergent"`
	Truncated           int            `json:"truncated"`
	Reconnects          int            `json:"reconnects"`
	SuccessRate         float64        `json:"success_rate"`
	FailureRate         float64        `json:"failure_rate"`
	UsableRate          float64        `json:"usable_rate"`
	ResolverFailureRate float64        `json:"resolver_failure_rate"`
	ScoringFailureRate  float64        `json:"scoring_failure_rate"`
	RCodeCounts         map[string]int `json:"rcode_counts,omitempty"`
	MedianMS            float64        `json:"median_ms"`
	P95MS               float64        `json:"p95_ms"`
	MinMS               float64        `json:"min_ms"`
	MaxMS               float64        `json:"max_ms"`
	MADMS               float64        `json:"mad_ms"`
	ColdMedianMS        float64        `json:"cold_median_ms,omitempty"`
	ScoreMS             float64        `json:"score_ms"`
	CILowMS             float64        `json:"ci_low_ms,omitempty"`
	CIHighMS            float64        `json:"ci_high_ms,omitempty"`
	Recommended         bool           `json:"recommended"`
	Tie                 bool           `json:"tie,omitempty"`
}

// Observation is a single measured DNS query.
type Observation struct {
	Name               string  `json:"name"`
	QType              uint16  `json:"qtype"`
	LatencyMS          float64 `json:"latency_ms,omitempty"`
	Success            bool    `json:"success"`
	Usable             bool    `json:"usable"`
	RCode              int     `json:"rcode,omitempty"`
	Truncated          bool    `json:"truncated,omitempty"`
	ResponseClass      string  `json:"response_class,omitempty"`
	Divergent          bool    `json:"divergent,omitempty"`
	DivergenceBaseline string  `json:"divergence_baseline,omitempty"`
	Reconnected        bool    `json:"reconnected,omitempty"`
	Error              string  `json:"error,omitempty"`
}

// ColdObservation is a single cold-start query, measured on a fresh session.
type ColdObservation struct {
	Name      string  `json:"name"`
	QType     uint16  `json:"qtype"`
	LatencyMS float64 `json:"latency_ms,omitempty"`
	Success   bool    `json:"success"`
	Error     string  `json:"error,omitempty"`
}

// Ranking places one target within its protocol.
type Ranking struct {
	Protocol Protocol `json:"protocol"`
	TargetID string   `json:"target_id"`
	Rank     int      `json:"rank"`
	Tie      bool     `json:"tie"`
}

// PairedEffect describes the latency difference between a target and the
// deterministic reference for its protocol and declared policy group. A
// positive delta means that the target was slower than the reference.
//
// Only observations that are usable, non-divergent, non-reconnect samples are
// paired. The composite score remains the ranking authority; these values
// explain whether a ranked difference is distinguishable from noise.
type PairedEffect struct {
	Protocol          Protocol `json:"protocol"`
	Policy            string   `json:"policy"`
	TargetID          string   `json:"target_id"`
	ReferenceTargetID string   `json:"reference_target_id"`
	Samples           int      `json:"samples"`
	MedianDeltaMS     float64  `json:"median_delta_ms"`
	CILowMS           float64  `json:"ci_low_ms"`
	CIHighMS          float64  `json:"ci_high_ms"`
	Indistinguishable bool     `json:"indistinguishable"`
	Reference         bool     `json:"reference,omitempty"`
	Reason            string   `json:"reason,omitempty"`
}

// DivergenceExclusion identifies a successful response that differed from the
// selected response-class baseline. Usable outliers are removed from the
// latency sample; unusable outliers remain failure-penalized.
type DivergenceExclusion struct {
	TargetID      string `json:"target_id"`
	ResponseClass string `json:"response_class"`
	Treatment     string `json:"treatment"`
}

// DivergenceDetail records the deterministic baseline decision for one query
// and policy group. A tied plurality has no safe baseline, so Ambiguous is
// true and all successful observations in the group are excluded from
// comparative latency scoring.
type DivergenceDetail struct {
	Name      string                `json:"name"`
	QType     uint16                `json:"qtype"`
	Policy    string                `json:"policy"`
	Compared  int                   `json:"compared"`
	Baseline  string                `json:"baseline,omitempty"`
	Ambiguous bool                  `json:"ambiguous,omitempty"`
	Classes   map[string]int        `json:"classes"`
	Excluded  []DivergenceExclusion `json:"excluded,omitempty"`
}

// Decode reads one JSON report and returns it as typed values. Unknown keys
// are ignored so that an older consumer keeps working against a newer,
// additively extended schema_version 1 report.
func Decode(reader io.Reader) (Report, error) {
	var document Report
	if err := json.NewDecoder(reader).Decode(&document); err != nil {
		return Report{}, fmt.Errorf("decode SpeeDNS report: %w", err)
	}
	if document.SchemaVersion != SchemaVersion {
		return Report{}, fmt.Errorf("%w: %d", ErrUnsupportedSchemaVersion, document.SchemaVersion)
	}
	return document, nil
}

// Parse decodes one JSON report from a byte slice.
func Parse(data []byte) (Report, error) { return Decode(bytes.NewReader(data)) }
