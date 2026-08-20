// Package schema contains machine-readable contracts for SpeeDNS output.
package schema

import _ "embed"

//go:embed report-v1.json
var reportV1 []byte

// ReportV1 returns a copy of the published schema for schema_version 1 JSON
// reports.
func ReportV1() []byte {
	return append([]byte(nil), reportV1...)
}
