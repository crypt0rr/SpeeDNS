// Package schema contains machine-readable contracts for SpeeDNS output.
package schema

import _ "embed"

//go:embed report-v1.json
var reportV1 []byte

//go:embed live-results-v1.json
var liveResultsV1 []byte

//go:embed compare-v1.json
var compareV1 []byte

// ReportV1 returns a copy of the published schema for schema_version 1 JSON
// reports.
func ReportV1() []byte {
	return append([]byte(nil), reportV1...)
}

// LiveResultsV1 returns a copy of the published schema for the aggregated live
// results site. scripts/publish-live-results.py enforces the same contract, so
// embedding it here lets Go tests check encoder output against it directly.
func LiveResultsV1() []byte {
	return append([]byte(nil), liveResultsV1...)
}

// CompareV1 returns a copy of the published schema for `speedns diff` output.
// A comparison is a different document from a report -- two run identities, no
// results, no rankings -- so it carries its own schema rather than a version of
// report-v1.
func CompareV1() []byte {
	return append([]byte(nil), compareV1...)
}
