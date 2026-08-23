package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/crypt0rr/SpeeDNS/internal/safetext"
	"github.com/crypt0rr/SpeeDNS/internal/textwidth"
)

type JSONReport struct {
	SchemaVersion      int                          `json:"schema_version"`
	Run                JSONRun                      `json:"run"`
	Results            []JSONResult                 `json:"results"`
	Rankings           []benchmark.Ranking          `json:"rankings"`
	PairedEffects      []benchmark.PairedEffect     `json:"paired_effects,omitempty"`
	ProfileComparisons []JSONProfileComparison      `json:"profile_comparisons,omitempty"`
	Divergence         []benchmark.DivergenceDetail `json:"divergence,omitempty"`
	Warnings           []string                     `json:"warnings,omitempty"`
}

type JSONRun struct {
	StartedAt   string          `json:"started_at"`
	FinishedAt  string          `json:"finished_at"`
	Seed        int64           `json:"seed"`
	Provenance  *JSONProvenance `json:"provenance,omitempty"`
	CorpusMode  string          `json:"corpus_mode,omitempty"`
	CorpusZone  string          `json:"corpus_zone,omitempty"`
	CorpusNonce string          `json:"corpus_nonce,omitempty"`
	SampleSize  int             `json:"sample_size"`
	Queries     int             `json:"queries_per_target"`
	QueryTypes  []uint16        `json:"query_types"`
}

type JSONProvenance struct {
	SpeeDNSVersion string             `json:"speedns_version"`
	Commit         string             `json:"commit"`
	BuildDate      string             `json:"build_date"`
	OS             string             `json:"os"`
	Architecture   string             `json:"architecture"`
	Interfaces     []string           `json:"interfaces,omitempty"`
	Protocols      []catalog.Protocol `json:"protocols"`
	CorpusEntries  int                `json:"corpus_entries"`
	CorpusSHA256   string             `json:"corpus_sha256"`
	TimeoutMS      int64              `json:"timeout_ms"`
	Concurrency    int                `json:"concurrency"`
	DurationMS     float64            `json:"duration_ms"`
}

type JSONProfileComparison struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Owner      string                 `json:"owner"`
	Address    string                 `json:"address"`
	Transports []JSONProfileTransport `json:"transports"`
}

type JSONProfileTransport struct {
	Protocol catalog.Protocol     `json:"protocol"`
	TargetID string               `json:"target_id"`
	Stats    benchmark.Statistics `json:"stats"`
	Status   string               `json:"status"`
}

type JSONResult struct {
	Target       JSONTarget                  `json:"target"`
	Stats        benchmark.Statistics        `json:"stats"`
	OpenError    string                      `json:"open_error,omitempty"`
	Incomplete   bool                        `json:"incomplete,omitempty"`
	Observations []benchmark.Observation     `json:"samples,omitempty"`
	Cold         []benchmark.ColdObservation `json:"cold,omitempty"`
}

type JSONTarget struct {
	ID                 string           `json:"id"`
	Name               string           `json:"name"`
	Owner              string           `json:"owner"`
	Policy             string           `json:"policy"`
	Address            string           `json:"address"`
	Protocol           catalog.Protocol `json:"protocol"`
	Local              bool             `json:"local,omitempty"`
	EndpointURL        string           `json:"endpoint_url,omitempty"`
	TLSServerName      string           `json:"tls_server_name,omitempty"`
	TLSIdentitySource  string           `json:"tls_identity_source,omitempty"`
	BootstrapMode      string           `json:"bootstrap_mode"`
	BootstrapAddresses []string         `json:"bootstrap_addresses,omitempty"`
	DialAddress        string           `json:"dial_address,omitempty"`
}

type JSONOptions struct {
	RedactSystem bool
	ProfileView  bool
}

type CSVOptions struct {
	RedactSystem bool
}

type csvWriter interface {
	Write([]string) error
	Flush()
	Error() error
}

var newCSVWriter = func(writer io.Writer) csvWriter {
	return csv.NewWriter(writer)
}

func toJSONWithOptions(report benchmark.Report, raw bool, options JSONOptions) JSONReport {
	results := make([]JSONResult, 0, len(report.Targets))
	redactedIDs := redactedTargetIDs(report, options.RedactSystem)
	for _, result := range report.Targets {
		metadata := result.Target.EndpointMetadata()
		view := targetViewFor(result.Target, options.RedactSystem, redactedIDs[result.Target.ID()])
		dialAddress := result.DialAddress
		if options.RedactSystem && isSystemTarget(result.Target) && dialAddress != "" {
			dialAddress = redactedValue
		}
		jsonResult := JSONResult{
			Target: JSONTarget{
				ID: view.ID, Name: view.Name, Owner: view.Owner, Policy: view.Policy,
				Address: view.Address, Protocol: result.Target.Protocol, Local: result.Target.Resolver.Local,
				EndpointURL: metadata.EndpointURL, TLSServerName: metadata.TLSServerName,
				TLSIdentitySource: metadata.TLSIdentitySource, BootstrapMode: metadata.BootstrapMode,
				BootstrapAddresses: metadata.BootstrapAddresses, DialAddress: dialAddress,
			},
			Stats: result.Stats, OpenError: redactResultText(result, result.OpenError, options.RedactSystem, redactedIDs[result.Target.ID()]), Incomplete: result.Incomplete,
		}
		if raw {
			jsonResult.Observations = redactObservations(result, options.RedactSystem, redactedIDs[result.Target.ID()])
			jsonResult.Cold = redactColdObservations(result, options.RedactSystem, redactedIDs[result.Target.ID()])
		}
		results = append(results, jsonResult)
	}
	rankings := append(make([]benchmark.Ranking, 0, len(report.Rankings)), report.Rankings...)
	for index := range rankings {
		if redactedID, ok := redactedIDs[rankings[index].TargetID]; ok {
			rankings[index].TargetID = redactedID
		}
	}
	warnings := renderWarnings(report, options.RedactSystem, redactedIDs)
	var profileComparisons []JSONProfileComparison
	if options.ProfileView {
		profileComparisons = profileComparisonsForJSON(report, redactedIDs)
	}
	var provenance *JSONProvenance
	if report.Provenance != nil {
		interfaces := append([]string(nil), report.Provenance.Interfaces...)
		if options.RedactSystem && len(interfaces) > 0 {
			interfaces = []string{redactedValue}
		}
		provenance = &JSONProvenance{
			SpeeDNSVersion: report.Provenance.Version,
			Commit:         report.Provenance.Commit,
			BuildDate:      report.Provenance.BuildDate,
			OS:             report.Provenance.OS,
			Architecture:   report.Provenance.Architecture,
			Interfaces:     interfaces,
			Protocols:      append([]catalog.Protocol(nil), report.Provenance.Protocols...),
			CorpusEntries:  report.Provenance.CorpusEntries,
			CorpusSHA256:   report.Provenance.CorpusSHA256,
			TimeoutMS:      report.Provenance.Timeout.Milliseconds(),
			Concurrency:    report.Provenance.Concurrency,
			DurationMS:     durationMilliseconds(report.StartedAt, report.FinishedAt),
		}
	}
	return JSONReport{
		SchemaVersion: 1,
		Run: JSONRun{
			StartedAt: report.StartedAt.UTC().Format("2006-01-02T15:04:05.000Z"), FinishedAt: report.FinishedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
			Seed: report.Seed, CorpusMode: report.CorpusMode, CorpusZone: report.CorpusZone, CorpusNonce: report.CorpusNonce,
			SampleSize: report.SampleSize, Queries: report.Queries, QueryTypes: report.QueryTypes, Provenance: provenance,
		},
		Results: results, Rankings: rankings, PairedEffects: pairedEffectsForJSON(report, redactedIDs), ProfileComparisons: profileComparisons,
		Divergence: divergenceForJSON(report, redactedIDs), Warnings: warnings,
	}
}

func durationMilliseconds(started, finished time.Time) float64 {
	if started.IsZero() || finished.Before(started) {
		return 0
	}
	return float64(finished.Sub(started)) / float64(time.Millisecond)
}

func WriteJSON(writer io.Writer, report benchmark.Report, raw bool) error {
	return WriteJSONWithOptions(writer, report, raw, JSONOptions{})
}

func WriteJSONWithOptions(writer io.Writer, report benchmark.Report, raw bool, options JSONOptions) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(toJSONWithOptions(report, raw, options))
}

func WriteCSV(writer io.Writer, report benchmark.Report) error {
	return WriteCSVWithOptions(writer, report, CSVOptions{})
}

func WriteCSVWithOptions(writer io.Writer, report benchmark.Report, options CSVOptions) error {
	writerCSV := newCSVWriter(writer)
	if err := writerCSV.Write([]string{
		"target_id", "name", "owner", "policy", "address", "protocol", "rank", "recommended", "tie",
		"total", "successes", "failures", "usable_responses", "resolver_failures", "scored", "divergent", "truncated", "success_rate", "usable_rate", "resolver_failure_rate", "scoring_failure_rate", "rcode_counts", "median_ms", "p95_ms",
		"min_ms", "max_ms", "mad_ms", "cold_median_ms", "score_ms", "ci_low_ms", "ci_high_ms", "open_error", "reconnects", "incomplete",
		"endpoint_url", "tls_server_name", "tls_identity_source", "bootstrap_mode", "bootstrap_addresses", "dial_address",
		"corpus_mode", "corpus_zone", "corpus_nonce", "local",
	}); err != nil {
		return err
	}
	redactedIDs := redactedTargetIDs(report, options.RedactSystem)
	for _, result := range report.Targets {
		rank := rankFor(report, result.Target.ID())
		stats := result.Stats
		metadata := result.Target.EndpointMetadata()
		view := targetViewFor(result.Target, options.RedactSystem, redactedIDs[result.Target.ID()])
		dialAddress := result.DialAddress
		if options.RedactSystem && isSystemTarget(result.Target) && dialAddress != "" {
			dialAddress = redactedValue
		}
		row := []string{
			csvCell(view.ID), csvCell(view.Name), csvCell(view.Owner), csvCell(view.Policy),
			csvCell(view.Address), csvCell(result.Target.Protocol.String()), strconv.Itoa(rank), strconv.FormatBool(stats.Recommended),
			strconv.FormatBool(stats.Tie), strconv.Itoa(stats.Total), strconv.Itoa(stats.Successes), strconv.Itoa(stats.Failures),
			strconv.Itoa(stats.UsableResponses), strconv.Itoa(stats.ResolverFailures), strconv.Itoa(stats.Scored), strconv.Itoa(stats.Divergent), strconv.Itoa(stats.Truncated),
			formatFloat(stats.SuccessRate), formatFloat(stats.UsableRate), formatFloat(stats.ResolverFailureRate), formatFloat(stats.ScoringFailureRate), rcodeCountsCSV(stats.RCodeCounts), formatFloat(stats.MedianMS),
			formatFloat(stats.P95MS), formatFloat(stats.MinMS), formatFloat(stats.MaxMS), formatFloat(stats.MADMS),
			formatFloat(stats.ColdMedianMS), formatFloat(stats.ScoreMS), formatFloat(stats.CILowMS), formatFloat(stats.CIHighMS), csvCell(redactResultText(result, result.OpenError, options.RedactSystem, redactedIDs[result.Target.ID()])), strconv.Itoa(stats.Reconnects), strconv.FormatBool(result.Incomplete),
			csvCell(metadata.EndpointURL), csvCell(metadata.TLSServerName), csvCell(metadata.TLSIdentitySource), csvCell(metadata.BootstrapMode), csvCell(bootstrapAddressesCSV(metadata.BootstrapAddresses)), csvCell(dialAddress),
			csvCell(report.CorpusMode), csvCell(report.CorpusZone), csvCell(report.CorpusNonce), strconv.FormatBool(result.Target.Resolver.Local),
		}
		if err := writerCSV.Write(row); err != nil {
			return err
		}
	}
	writerCSV.Flush()
	return writerCSV.Error()
}

func rankFor(report benchmark.Report, targetID string) int {
	for _, ranking := range report.Rankings {
		if ranking.TargetID == targetID {
			return ranking.Rank
		}
	}
	return 0
}

func formatFloat(value float64) string { return strconv.FormatFloat(value, 'f', 3, 64) }

func placeholderText(value string) string {
	if value == "" {
		return "—"
	}
	return safetext.Escape(value)
}

// csvCell escapes control characters and then prefixes values that spreadsheet
// applications may interpret as a formula. The leading apostrophe is part of
// the exported cell value and is understood by spreadsheet programs as text
// protection.
//
// The order matters, and the guard is re-evaluated on the escaped value. A
// value such as "\x1b=cmd|'/C calc'!A1" passes a plain first-character test,
// because its first character is ESC rather than '='; escaping it afterwards
// would then hand a spreadsheet a cell whose visible content starts with a
// formula. An escape sequence therefore joins the leading characters that ask
// for the apostrophe, which also keeps the guard stable for values that were
// already escaped upstream. Escaping never removes bytes, so it cannot shift
// a formula character into the leading position after the guard looked at it
// either.
func csvCell(value string) string {
	value = safetext.Escape(value)
	if value == "" {
		return value
	}
	if strings.HasPrefix(value, safetext.EscapePrefix) {
		return "'" + value
	}
	switch value[0] {
	case '=', '+', '-', '@':
		return "'" + value
	default:
		return value
	}
}

func rcodeCountsText(counts map[string]int) string {
	if len(counts) == 0 {
		return "—"
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s:%d", key, counts[key]))
	}
	return strings.Join(parts, ",")
}

func rcodeCountsCSV(counts map[string]int) string {
	if len(counts) == 0 {
		return ""
	}
	return rcodeCountsText(counts)
}

func bootstrapAddressesCSV(addresses []string) string {
	return strings.Join(addresses, ";")
}

const (
	redactedValue       = "redacted"
	redactedSystemName  = "System DNS (redacted)"
	redactedSystemOwner = "configured locally (redacted)"
)

type targetView struct {
	ID      string
	Name    string
	Owner   string
	Policy  string
	Address string
}

func isSystemTarget(target catalog.Target) bool {
	return strings.HasPrefix(target.Resolver.ID, "system-")
}

func redactedTargetIDs(report benchmark.Report, redact bool) map[string]string {
	if !redact {
		return nil
	}
	ids := make(map[string]string)
	ordinal := 0
	for _, result := range report.Targets {
		if !isSystemTarget(result.Target) {
			continue
		}
		ordinal++
		ids[result.Target.ID()] = fmt.Sprintf("system-redacted-%d@redacted/%s", ordinal, result.Target.Protocol)
	}
	return ids
}

// targetViewFor builds the presentation values for one target. Every field is
// escaped here because catalog.Validate only trims the surrounding whitespace
// of resolver names, owners, policies, scopes and interfaces, so --resolver,
// --resolver-file and the system resolver configuration can all place control
// characters in them. Escaping at the view keeps every consumer - table, CSV
// and JSON - on the same rendered value.
func targetViewFor(target catalog.Target, redact bool, redactedID string) targetView {
	view := targetView{
		ID: safetext.Escape(target.ID()), Name: safetext.Escape(target.DisplayName()), Owner: safetext.Escape(target.Resolver.Owner),
		Policy: safetext.Escape(target.Resolver.Policy), Address: safetext.Escape(target.Address),
	}
	if redact && isSystemTarget(target) {
		view.ID = redactedID
		view.Name = redactedSystemName
		view.Owner = redactedSystemOwner
		view.Address = redactedValue
	}
	return view
}

func redactResultText(result benchmark.TargetResult, value string, redact bool, redactedID string) string {
	if !redact || !isSystemTarget(result.Target) || value == "" {
		return value
	}
	sources := []string{
		result.Target.ID(), redactedID,
		result.Target.DisplayName(), redactedSystemName,
		result.Target.Resolver.Owner, redactedSystemOwner,
		result.DialAddress, redactedValue,
		result.Target.Address, redactedValue,
	}
	replacements := make([]string, 0, len(sources)*2)
	for index := 0; index+1 < len(sources); index += 2 {
		if sources[index] == "" {
			continue
		}
		replacements = append(replacements, sources[index], sources[index+1])
		// Warnings are escaped where they are built, so a local value that
		// contains control characters appears in them in its escaped form.
		// Both spellings must be redacted, since this helper is also called
		// with values that are still unescaped.
		if escaped := safetext.Escape(sources[index]); escaped != sources[index] {
			replacements = append(replacements, escaped, sources[index+1])
		}
	}
	return strings.NewReplacer(replacements...).Replace(value)
}

// redactObservations also escapes the per-query error text. Those strings come
// from the measured endpoint - a DoH status line, a TLS diagnostic quoting
// certificate fields - so they get the same treatment as the target metadata
// rather than being the one report value that reaches a consumer unescaped.
func redactObservations(result benchmark.TargetResult, redact bool, redactedID string) []benchmark.Observation {
	redacting := redact && isSystemTarget(result.Target)
	if len(result.Observations) == 0 {
		return result.Observations
	}
	observations := append([]benchmark.Observation(nil), result.Observations...)
	for index := range observations {
		if redacting {
			observations[index].Error = redactResultText(result, observations[index].Error, true, redactedID)
		}
		observations[index].Error = safetext.Escape(observations[index].Error)
		observations[index].ResponseClass = safetext.Escape(observations[index].ResponseClass)
		observations[index].DivergenceBaseline = safetext.Escape(observations[index].DivergenceBaseline)
	}
	return observations
}

func redactColdObservations(result benchmark.TargetResult, redact bool, redactedID string) []benchmark.ColdObservation {
	redacting := redact && isSystemTarget(result.Target)
	if len(result.Cold) == 0 {
		return result.Cold
	}
	observations := append([]benchmark.ColdObservation(nil), result.Cold...)
	for index := range observations {
		if redacting {
			observations[index].Error = redactResultText(result, observations[index].Error, true, redactedID)
		}
		observations[index].Error = safetext.Escape(observations[index].Error)
	}
	return observations
}

// redactRunWarningText scrubs system resolver identities from a run-level
// warning. A run-level warning carries no endpoint, so scanning its text is the
// only way to catch an identity that a producer embedded in the message.
func redactRunWarningText(report benchmark.Report, message string, redactedIDs map[string]string) string {
	for _, result := range report.Targets {
		if isSystemTarget(result.Target) {
			message = redactResultText(result, message, true, redactedIDs[result.Target.ID()])
		}
	}
	return message
}

// warningTargetResult returns the measured result for the endpoint a warning is
// attributed to, so redaction can also scrub the dial address. The zero result
// keeps rendering correct when the warning outlives its target result.
func warningTargetResult(report benchmark.Report, target catalog.Target) benchmark.TargetResult {
	for _, result := range report.Targets {
		if result.Target.ID() == target.ID() {
			return result
		}
	}
	return benchmark.TargetResult{Target: target}
}

// renderWarning renders one structured warning. Attribution comes from the
// warning itself, never from the rendered text, so the label format can change
// on either side without a view losing warnings.
func renderWarning(report benchmark.Report, warning benchmark.Warning, redactSystem bool, redactedIDs map[string]string) string {
	if !warning.Targeted() {
		if redactSystem {
			return redactRunWarningText(report, warning.Message, redactedIDs)
		}
		return warning.Message
	}
	if !redactSystem || !isSystemTarget(*warning.Target) {
		return warning.String()
	}
	redactedID := redactedIDs[warning.Target.ID()]
	redacted := warning
	redacted.Message = redactResultText(warningTargetResult(report, *warning.Target), warning.Message, true, redactedID)
	view := targetViewFor(*warning.Target, true, redactedID)
	return redacted.RenderWith(view.Name, view.Address)
}

func renderWarnings(report benchmark.Report, redactSystem bool, redactedIDs map[string]string) []string {
	warnings := make([]string, 0, len(report.Warnings))
	for _, warning := range report.Warnings {
		warnings = append(warnings, safetext.Escape(renderWarning(report, warning, redactSystem, redactedIDs)))
	}
	return warnings
}

func divergenceForJSON(report benchmark.Report, redactedIDs map[string]string) []benchmark.DivergenceDetail {
	if len(report.Divergence) == 0 {
		return nil
	}
	details := make([]benchmark.DivergenceDetail, len(report.Divergence))
	copy(details, report.Divergence)
	for index := range details {
		details[index].Classes = cloneIntMap(details[index].Classes)
		details[index].Excluded = append([]benchmark.DivergenceExclusion(nil), details[index].Excluded...)
		for exclusionIndex := range details[index].Excluded {
			if replacement, ok := redactedIDs[details[index].Excluded[exclusionIndex].TargetID]; ok {
				details[index].Excluded[exclusionIndex].TargetID = replacement
			}
		}
	}
	return details
}

func pairedEffectsForJSON(report benchmark.Report, redactedIDs map[string]string) []benchmark.PairedEffect {
	if len(report.PairedEffects) == 0 {
		return nil
	}
	effects := append([]benchmark.PairedEffect(nil), report.PairedEffects...)
	for index := range effects {
		if replacement, ok := redactedIDs[effects[index].TargetID]; ok {
			effects[index].TargetID = replacement
		}
		if replacement, ok := redactedIDs[effects[index].ReferenceTargetID]; ok {
			effects[index].ReferenceTargetID = replacement
		}
	}
	return effects
}

type profileGroup struct {
	Target  catalog.Target
	Results map[catalog.Protocol]benchmark.TargetResult
}

func profileGroupKey(target catalog.Target) string {
	return target.Resolver.ID + "\x00" + target.Address
}

func profileGroups(report benchmark.Report) map[string]profileGroup {
	groups := make(map[string]profileGroup)
	for _, result := range report.Targets {
		key := profileGroupKey(result.Target)
		group, ok := groups[key]
		if !ok {
			group = profileGroup{Target: result.Target, Results: make(map[catalog.Protocol]benchmark.TargetResult)}
		}
		group.Results[result.Target.Protocol] = result
		groups[key] = group
	}
	return groups
}

func sortedProfileGroupKeys(groups map[string]profileGroup) []string {
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left, right := groups[keys[i]].Target, groups[keys[j]].Target
		if left.Resolver.ID != right.Resolver.ID {
			return left.Resolver.ID < right.Resolver.ID
		}
		return left.Address < right.Address
	})
	return keys
}

func profileComparisonsForJSON(report benchmark.Report, redactedIDs map[string]string) []JSONProfileComparison {
	groups := profileGroups(report)
	comparisons := make([]JSONProfileComparison, 0, len(groups))
	for _, key := range sortedProfileGroupKeys(groups) {
		group := groups[key]
		view := targetViewFor(group.Target, len(redactedIDs) > 0, redactedIDs[group.Target.ID()])
		profileID := group.Target.Resolver.ID
		if len(redactedIDs) > 0 && isSystemTarget(group.Target) {
			profileID = "system-redacted"
		}
		comparison := JSONProfileComparison{ID: profileID, Name: view.Name, Owner: view.Owner, Address: view.Address}
		for _, protocol := range catalog.AllProtocols {
			result, ok := group.Results[protocol]
			if !ok {
				continue
			}
			targetID := result.Target.ID()
			if replacement, exists := redactedIDs[targetID]; exists {
				targetID = replacement
			}
			comparison.Transports = append(comparison.Transports, JSONProfileTransport{
				Protocol: protocol, TargetID: targetID, Stats: result.Stats, Status: resultStatus(result),
			})
		}
		comparisons = append(comparisons, comparison)
	}
	return comparisons
}

func cloneIntMap(values map[string]int) map[string]int {
	if len(values) == 0 {
		return nil
	}
	clone := make(map[string]int, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

type TableOptions struct {
	Details      bool
	Color        bool
	ProfileView  bool
	RedactSystem bool
	Profiles     []catalog.ResolverProfile
	Protocols    []catalog.Protocol
}

const (
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
	ansiReset  = "\x1b[0m"
)

func rankedResult(report benchmark.Report, protocol catalog.Protocol, rank int) (benchmark.TargetResult, bool) {
	for _, ranking := range report.Rankings {
		if ranking.Protocol != protocol || ranking.Rank != rank {
			continue
		}
		if result, ok := report.ResultFor(ranking.TargetID); ok {
			if !result.Incomplete {
				return result, true
			}
		}
	}
	return benchmark.TargetResult{}, false
}

func recommendedResult(report benchmark.Report, protocol catalog.Protocol) (benchmark.TargetResult, bool) {
	for _, ranking := range report.Rankings {
		if ranking.Protocol != protocol {
			continue
		}
		result, ok := report.ResultFor(ranking.TargetID)
		if ok && !result.Incomplete && result.Stats.Recommended {
			return result, true
		}
	}
	return benchmark.TargetResult{}, false
}

func reportProtocols(report benchmark.Report) []catalog.Protocol {
	seen := make(map[catalog.Protocol]bool)
	for _, result := range report.Targets {
		seen[result.Target.Protocol] = true
	}
	for _, ranking := range report.Rankings {
		seen[ranking.Protocol] = true
	}
	protocols := make([]catalog.Protocol, 0, len(seen))
	for _, protocol := range catalog.AllProtocols {
		if seen[protocol] {
			protocols = append(protocols, protocol)
			delete(seen, protocol)
		}
	}
	remaining := make([]catalog.Protocol, 0, len(seen))
	for protocol := range seen {
		remaining = append(remaining, protocol)
	}
	sort.Slice(remaining, func(i, j int) bool { return remaining[i] < remaining[j] })
	return append(protocols, remaining...)
}

func tableProtocols(report benchmark.Report, options TableOptions) []catalog.Protocol {
	if len(options.Protocols) == 0 {
		return reportProtocols(report)
	}
	seen := make(map[catalog.Protocol]bool, len(options.Protocols))
	for _, protocol := range options.Protocols {
		seen[protocol] = true
	}
	protocols := make([]catalog.Protocol, 0, len(seen))
	for _, protocol := range catalog.AllProtocols {
		if seen[protocol] {
			protocols = append(protocols, protocol)
			delete(seen, protocol)
		}
	}
	remaining := make([]catalog.Protocol, 0, len(seen))
	for protocol := range seen {
		remaining = append(remaining, protocol)
	}
	sort.Slice(remaining, func(i, j int) bool { return remaining[i] < remaining[j] })
	return append(protocols, remaining...)
}

func resultStatus(result benchmark.TargetResult) string {
	if result.Incomplete {
		return "INCOMPLETE"
	}
	if result.Stats.Successes == 0 {
		return "FAILED"
	}
	if result.Target.Resolver.Local {
		return "NOT COMPARABLE"
	}
	if result.Stats.Recommended {
		return "QUALIFIED"
	}
	return "INELIGIBLE"
}

func styledStatus(status string, color bool) string {
	if !color {
		return status
	}
	colorCode := ""
	switch status {
	case "RECOMMENDED", "QUALIFIED", "REFERENCE":
		colorCode = ansiGreen
	case "PROVISIONAL", "INELIGIBLE", "INCOMPLETE", "NOT COMPARABLE", "NO CLEAR DIFFERENCE", "NOT MEASURED", "TIED":
		colorCode = ansiYellow
	case "FAILED":
		colorCode = ansiRed
	default:
		return status
	}
	return colorCode + status + ansiReset
}

func latencyText(value float64) string {
	if value == 0 {
		return "—"
	}
	return fmt.Sprintf("%.2f ms", value)
}

func percentText(value float64) string { return fmt.Sprintf("%.2f%%", value*100) }

func scoreText(result benchmark.TargetResult) string {
	if result.Stats.Scored == 0 {
		return "—"
	}
	return latencyText(result.Stats.ScoreMS)
}

func rankText(report benchmark.Report, targetID string) string {
	rank := rankFor(report, targetID)
	if rank == 0 {
		return "—"
	}
	return strconv.Itoa(rank)
}

const tieNote = "\n  TIED: the 95% score confidence interval overlaps another ranked target, so that ordering is not statistically distinguishable.\n"

func tieText(stats benchmark.Statistics, color bool) string {
	if !stats.Tie {
		return "—"
	}
	return styledStatus("TIED", color)
}

func summaryRowWithOptions(protocol catalog.Protocol, result benchmark.TargetResult, status string, color bool, redactSystem bool) []string {
	view := targetViewFor(result.Target, redactSystem, redactedValue)
	return []string{
		string(protocol), view.Owner, view.Address, view.Policy,
		latencyText(result.Stats.MedianMS), latencyText(result.Stats.P95MS), percentText(result.Stats.SuccessRate), percentText(result.Stats.UsableRate),
		scoreText(result), tieText(result.Stats, color), styledStatus(status, color),
	}
}

func comparisonRowWithOptions(report benchmark.Report, result benchmark.TargetResult, details bool, color bool, redactSystem bool) []string {
	view := targetViewFor(result.Target, redactSystem, redactedValue)
	row := []string{
		rankText(report, result.Target.ID()), view.Owner, view.Address, view.Policy,
		latencyText(result.Stats.MedianMS), latencyText(result.Stats.P95MS), percentText(result.Stats.SuccessRate), percentText(result.Stats.UsableRate),
		scoreText(result),
	}
	if details {
		metadata := result.Target.EndpointMetadata()
		row = append(row,
			latencyText(result.Stats.ColdMedianMS), latencyText(result.Stats.MADMS),
			strconv.Itoa(result.Stats.Scored), strconv.Itoa(result.Stats.Failures),
			strconv.Itoa(result.Stats.ResolverFailures), strconv.Itoa(result.Stats.Divergent), strconv.Itoa(result.Stats.Truncated), strconv.Itoa(result.Stats.Reconnects),
			rcodeCountsText(result.Stats.RCodeCounts), endpointURLText(metadata.EndpointURL), tlsServerNameText(metadata.TLSServerName),
			tlsIdentitySourceText(metadata.TLSIdentitySource), bootstrapModeText(metadata.BootstrapMode), bootstrapAddressesText(metadata.BootstrapAddresses), dialAddressTextWithOptions(result, redactSystem),
		)
	}
	return append(row, tieText(result.Stats, color), styledStatus(resultStatus(result), color))
}

func dialAddressTextWithOptions(result benchmark.TargetResult, redactSystem bool) string {
	if result.DialAddress == "" {
		return "—"
	}
	if redactSystem && isSystemTarget(result.Target) {
		return redactedValue
	}
	return safetext.Escape(result.DialAddress)
}

func endpointURLText(value string) string {
	if value == "" {
		return "—"
	}
	return safetext.Escape(value)
}

func tlsServerNameText(value string) string {
	if value == "" {
		return "—"
	}
	return safetext.Escape(value)
}

func tlsIdentitySourceText(value string) string {
	if value == "" || value == catalog.TLSIdentityNotApplicable {
		return "—"
	}
	return safetext.Escape(value)
}

func bootstrapModeText(value string) string {
	if value == "" || value == catalog.BootstrapNotApplicable {
		return "—"
	}
	return safetext.Escape(value)
}

func bootstrapAddressesText(addresses []string) string {
	if len(addresses) == 0 {
		return "—"
	}
	return safetext.Escape(strings.Join(addresses, ";"))
}

func sortComparisonResults(report benchmark.Report, results []benchmark.TargetResult) {
	sort.SliceStable(results, func(i, j int) bool {
		leftRank := rankFor(report, results[i].Target.ID())
		rightRank := rankFor(report, results[j].Target.ID())
		if leftRank == 0 && rightRank != 0 {
			return false
		}
		if leftRank != 0 && rightRank == 0 {
			return true
		}
		if leftRank != 0 && rightRank != 0 && leftRank != rightRank {
			return leftRank < rightRank
		}
		if results[i].Target.Resolver.Owner != results[j].Target.Resolver.Owner {
			return results[i].Target.Resolver.Owner < results[j].Target.Resolver.Owner
		}
		return results[i].Target.Address < results[j].Target.Address
	})
}

func comparisonRows(report benchmark.Report, protocol catalog.Protocol, details bool, color bool) [][]string {
	return comparisonRowsWithOptions(report, protocol, details, color, false)
}

func comparisonRowsWithOptions(report benchmark.Report, protocol catalog.Protocol, details bool, color bool, redactSystem bool) [][]string {
	results := make([]benchmark.TargetResult, 0)
	for _, result := range report.Targets {
		if result.Target.Protocol == protocol {
			results = append(results, result)
		}
	}
	sortComparisonResults(report, results)
	rows := make([][]string, 0, len(results))
	for _, result := range results {
		rows = append(rows, comparisonRowWithOptions(report, result, details, color, redactSystem))
	}
	return rows
}

func unsupportedComparisonRowWithOptions(target catalog.Target, details bool, redactSystem bool) []string {
	view := targetViewFor(target, redactSystem, redactedValue)
	row := []string{"—", view.Owner, view.Address, view.Policy, "—", "—", "—", "—", "—"}
	if details {
		for range len(comparisonHeaders(true)) - len(comparisonHeaders(false)) {
			row = append(row, "—")
		}
	}
	return append(row, "—", "—")
}

// collapsedIPv6Targets returns the endpoints that the collapsed IPv6 warning
// already summarizes. Partial IPv6 failures never reach this set, because
// ipv6UnavailableWarning collapses only when every selected IPv6 endpoint
// failed at the transport layer.
func collapsedIPv6Targets(report benchmark.Report) map[string]bool {
	warning, results := ipv6UnavailableWarning(report)
	if warning == "" {
		return nil
	}
	collapsed := make(map[string]bool, len(results))
	for _, result := range results {
		collapsed[result.Target.ID()] = true
	}
	return collapsed
}

// comparisonRowsForTable returns the comparison rows for one protocol and the
// number of endpoints that were hidden because the collapsed IPv6 warning
// already accounts for them. The detailed view keeps every row.
func comparisonRowsForTable(report benchmark.Report, protocol catalog.Protocol, options TableOptions) ([][]string, int) {
	present := make(map[string]bool, len(report.Targets))
	for _, result := range report.Targets {
		present[result.Target.ID()] = true
	}
	hidden := 0
	if !options.Details {
		collapsed := collapsedIPv6Targets(report)
		if len(collapsed) > 0 {
			visible := make([]benchmark.TargetResult, 0, len(report.Targets))
			for _, result := range report.Targets {
				if !collapsed[result.Target.ID()] {
					visible = append(visible, result)
					continue
				}
				if result.Target.Protocol == protocol {
					hidden++
				}
			}
			report.Targets = visible
		}
	}
	rows := comparisonRowsWithOptions(report, protocol, options.Details, options.Color, options.RedactSystem)
	for _, profile := range options.Profiles {
		if _, supported := profile.Transports[protocol]; supported {
			continue
		}
		for _, address := range profile.Addresses {
			target := catalog.Target{Resolver: profile, Protocol: protocol, Address: address}
			if present[target.ID()] {
				continue
			}
			rows = append(rows, unsupportedComparisonRowWithOptions(target, options.Details, options.RedactSystem))
		}
	}
	return rows, hidden
}

func pairedEffectTargetText(report benchmark.Report, targetID string, redactSystem bool) string {
	result, ok := report.ResultFor(targetID)
	if !ok {
		return "—"
	}
	view := targetViewFor(result.Target, redactSystem, redactedValue)
	return strings.TrimSpace(view.Owner + " " + view.Address)
}

// pairedComparable reports whether an effect carries a usable delta and
// interval. Any effect that benchmark left unmeasured records a Reason, which
// includes samples below the paired minimum, so no reason means measured.
func pairedComparable(effect benchmark.PairedEffect) bool {
	return effect.Samples > 0 && effect.Reason == ""
}

func pairedDeltaText(effect benchmark.PairedEffect) string {
	if !pairedComparable(effect) {
		return "—"
	}
	return fmt.Sprintf("%+.2f ms", effect.MedianDeltaMS)
}

func pairedCIText(effect benchmark.PairedEffect) string {
	if !pairedComparable(effect) {
		return "—"
	}
	return fmt.Sprintf("[%+.2f, %+.2f] ms", effect.CILowMS, effect.CIHighMS)
}

func pairedInterpretation(effect benchmark.PairedEffect, color bool) string {
	if effect.Reference {
		return styledStatus("REFERENCE", color)
	}
	if !pairedComparable(effect) {
		return styledStatus("NOT COMPARABLE", color)
	}
	if effect.Indistinguishable || effect.MedianDeltaMS == 0 {
		return styledStatus("NO CLEAR DIFFERENCE", color)
	}
	if effect.MedianDeltaMS < 0 {
		return "FASTER"
	}
	return "SLOWER"
}

type pairedPolicyGroup struct {
	protocol catalog.Protocol
	policy   string
}

// pairedGroupSizes counts the effects in each protocol/policy group. A group
// with a single member has no policy-comparable peer, so its only row is a
// reference self-comparison that carries no information.
func pairedGroupSizes(effects []benchmark.PairedEffect) map[pairedPolicyGroup]int {
	sizes := make(map[pairedPolicyGroup]int, len(effects))
	for _, effect := range effects {
		sizes[pairedPolicyGroup{protocol: effect.Protocol, policy: effect.Policy}]++
	}
	return sizes
}

// pairedEffectRows returns the rendered paired-effect rows and the number of
// targets that were omitted because they had no policy-comparable peer. The
// detailed view keeps every row; the JSON section always keeps every entry.
func pairedEffectRows(report benchmark.Report, options TableOptions) ([][]string, int) {
	effects := append([]benchmark.PairedEffect(nil), report.PairedEffects...)
	sort.SliceStable(effects, func(i, j int) bool {
		if effects[i].Protocol != effects[j].Protocol {
			return effects[i].Protocol < effects[j].Protocol
		}
		if effects[i].Policy != effects[j].Policy {
			return effects[i].Policy < effects[j].Policy
		}
		return effects[i].TargetID < effects[j].TargetID
	})
	sizes := pairedGroupSizes(effects)
	rows := make([][]string, 0, len(effects))
	omitted := 0
	for _, effect := range effects {
		if !options.Details && sizes[pairedPolicyGroup{protocol: effect.Protocol, policy: effect.Policy}] == 1 {
			omitted++
			continue
		}
		rows = append(rows, []string{
			string(effect.Protocol), safetext.Escape(effect.Policy),
			pairedEffectTargetText(report, effect.TargetID, options.RedactSystem),
			pairedEffectTargetText(report, effect.ReferenceTargetID, options.RedactSystem),
			strconv.Itoa(effect.Samples), pairedDeltaText(effect), pairedCIText(effect),
			pairedInterpretation(effect, options.Color),
		})
	}
	return rows, omitted
}

func writePairedEffects(writer io.Writer, report benchmark.Report, options TableOptions) error {
	if len(report.PairedEffects) == 0 {
		return nil
	}
	rows, omitted := pairedEffectRows(report, options)
	if _, err := io.WriteString(writer, "\nPaired latency effects (target - reference; policy-local reference)\n"); err != nil {
		return err
	}
	if len(rows) > 0 {
		if err := writeAlignedTable(writer, []string{"Protocol", "Policy", "Target", "Reference", "Samples", "Median Δ", "95% CI", "Interpretation"}, rows); err != nil {
			return err
		}
	}
	if omitted > 0 {
		if _, err := fmt.Fprintf(writer, "  omitted %s without a policy-comparable peer (--details lists them)\n", targetCountText(omitted)); err != nil {
			return err
		}
	}
	return nil
}

func profileGroupsForTable(report benchmark.Report, options TableOptions) map[string]profileGroup {
	groups := profileGroups(report)
	for _, profile := range options.Profiles {
		for _, address := range profile.Addresses {
			target := catalog.Target{Resolver: profile, Address: address}
			key := profileGroupKey(target)
			if _, exists := groups[key]; !exists {
				groups[key] = profileGroup{Target: target, Results: make(map[catalog.Protocol]benchmark.TargetResult)}
			}
		}
	}
	return groups
}

func profileViewProtocols(report benchmark.Report, options TableOptions) []catalog.Protocol {
	if len(options.Protocols) > 0 {
		return tableProtocols(report, options)
	}
	return reportProtocols(report)
}

func profileScoreCIText(stats benchmark.Statistics) string {
	if stats.Scored == 0 {
		return "—"
	}
	return fmt.Sprintf("[%.2f, %.2f] ms", stats.CILowMS, stats.CIHighMS)
}

func profileViewRow(group profileGroup, protocol catalog.Protocol, options TableOptions) []string {
	view := targetViewFor(group.Target, options.RedactSystem, redactedValue)
	result, ok := group.Results[protocol]
	if !ok {
		status := "—"
		if _, supported := group.Target.Resolver.Transports[protocol]; supported {
			status = styledStatus("NOT MEASURED", options.Color)
		}
		return []string{view.Name, view.Owner, view.Address, string(protocol), "—", "—", "—", "—", "—", "—", status}
	}
	return []string{
		view.Name, view.Owner, view.Address, string(protocol), latencyText(result.Stats.MedianMS),
		latencyText(result.Stats.P95MS), latencyText(result.Stats.ColdMedianMS), scoreText(result),
		profileScoreCIText(result.Stats), percentText(result.Stats.SuccessRate), styledStatus(resultStatus(result), options.Color),
	}
}

func profileViewRows(report benchmark.Report, options TableOptions) [][]string {
	groups := profileGroupsForTable(report, options)
	protocols := profileViewProtocols(report, options)
	rows := make([][]string, 0, len(groups)*len(protocols))
	for _, key := range sortedProfileGroupKeys(groups) {
		for _, protocol := range protocols {
			rows = append(rows, profileViewRow(groups[key], protocol, options))
		}
	}
	return rows
}

func writeProfileView(writer io.Writer, report benchmark.Report, options TableOptions) error {
	if _, err := io.WriteString(writer, "\nProfile-level transport view (same resolver/address; score 95% CI)\n"); err != nil {
		return err
	}
	rows := profileViewRows(report, options)
	if len(rows) == 0 {
		_, err := io.WriteString(writer, "  no profile results\n")
		return err
	}
	return writeAlignedTable(writer, []string{"Profile", "Owner", "Address", "Protocol", "Median", "P95", "Cold", "Score", "Score 95% CI", "Success", "Status"}, rows)
}

// tableColumnPadding is the number of spaces kept between two columns.
const tableColumnPadding = 2

// writeAlignedTable renders a table whose columns line up by display width.
// Counting runes, as text/tabwriter does, shears every column to the right of
// an East Asian owner name and drifts the other way for combining marks, so
// cells are measured in terminal cells instead. Zero-width ANSI colour codes
// from styledStatus are discounted the same way. The trailing column is never
// padded, so no line carries trailing whitespace.
// targetCountText and ipv6EndpointCountText keep the collapsed summary lines
// grammatical for a single hidden row.
func targetCountText(count int) string {
	if count == 1 {
		return "1 target"
	}
	return fmt.Sprintf("%d targets", count)
}

func ipv6EndpointCountText(count int) string {
	if count == 1 {
		return "1 IPv6 endpoint"
	}
	return fmt.Sprintf("%d IPv6 endpoints", count)
}

func writeAlignedTable(writer io.Writer, headers []string, rows [][]string) error {
	lines := make([][]string, 0, len(rows)+1)
	lines = append(lines, indentedCells(headers))
	for _, row := range rows {
		lines = append(lines, indentedCells(row))
	}
	widths := tableColumnWidths(lines)
	for _, line := range lines {
		if _, err := io.WriteString(writer, alignedTableLine(line, widths)); err != nil {
			return err
		}
	}
	return nil
}

// indentedCells copies values and indents the first cell by the table margin.
func indentedCells(values []string) []string {
	cells := append([]string(nil), values...)
	cells[0] = "  " + cells[0]
	return cells
}

// tableColumnWidths returns the padded width of every column except the last,
// which is trailing and therefore never padded.
func tableColumnWidths(lines [][]string) []int {
	var widths []int
	for _, line := range lines {
		for column := 0; column < len(line)-1; column++ {
			for len(widths) <= column {
				widths = append(widths, 0)
			}
			if cells := textwidth.Display(line[column]) + tableColumnPadding; cells > widths[column] {
				widths[column] = cells
			}
		}
	}
	return widths
}

// alignedTableLine pads every non-trailing cell out to its column width.
func alignedTableLine(line []string, widths []int) string {
	builder := strings.Builder{}
	for column, cell := range line {
		builder.WriteString(cell)
		if column < len(widths) {
			builder.WriteString(strings.Repeat(" ", widths[column]-textwidth.Display(cell)))
		}
	}
	builder.WriteString("\n")
	return builder.String()
}

func summaryHeaders() []string {
	return []string{"Protocol", "Owner", "Address", "Policy", "Median", "P95", "Success", "Usable", "Score", "Tie", "Status"}
}

func comparisonHeaders(details bool) []string {
	headers := []string{"Rank", "Owner", "Address", "Policy", "Median", "P95", "Success", "Usable", "Score"}
	if details {
		headers = append(headers, "Cold", "MAD", "Scored", "Failed", "ResolverFail", "Divergent", "Truncated", "Reconnects", "RCodes", "Endpoint", "TLSName", "TLSSource", "Bootstrap", "BootstrapAddrs", "Dial")
	}
	return append(headers, "Tie", "Status")
}

func targetWarningLabelWithOptions(result benchmark.TargetResult, redactSystem bool) string {
	view := targetViewFor(result.Target, redactSystem, redactedValue)
	return fmt.Sprintf("%s %s/%s", view.Name, view.Address, result.Target.Protocol)
}

func compactWarnings(report benchmark.Report) []string {
	return compactWarningsWithOptions(report, false)
}

func compactWarningsWithOptions(report benchmark.Report, redactSystem bool) []string {
	warnings := make([]string, 0)
	handled := make(map[string]bool)
	if ipv6Warning, targets := ipv6UnavailableWarning(report); ipv6Warning != "" {
		warnings = append(warnings, ipv6Warning)
		for _, result := range targets {
			handled[result.Target.ID()] = true
		}
	}
	for _, protocol := range reportProtocols(report) {
		targets := make([]benchmark.TargetResult, 0)
		for _, result := range report.Targets {
			if result.Target.Protocol == protocol && !handled[result.Target.ID()] {
				targets = append(targets, result)
			}
		}
		if len(targets) == 0 {
			continue
		}
		allUnavailable := true
		allTransportFailed := true
		allResponsesUnusable := true
		failedQueries := 0
		totalQueries := 0
		for _, result := range targets {
			totalQueries += result.Stats.Total
			failedQueries += result.Stats.Failures
			if result.Incomplete || result.Stats.Total == 0 || result.Stats.Scored != 0 {
				allUnavailable = false
			}
			if result.Stats.Total == 0 || result.Stats.Failures != result.Stats.Total {
				allTransportFailed = false
			}
			if result.Stats.Total == 0 || result.Stats.UsableResponses != 0 {
				allResponsesUnusable = false
			}
		}
		if allUnavailable {
			switch {
			case allTransportFailed:
				warnings = append(warnings, fmt.Sprintf("%s: %d/%d endpoints unavailable; %d/%d measured queries failed", protocol, len(targets), len(targets), failedQueries, totalQueries))
			case allResponsesUnusable:
				resolverFailures := 0
				for _, result := range targets {
					resolverFailures += result.Stats.ResolverFailures
				}
				warnings = append(warnings, fmt.Sprintf("%s: %d/%d endpoints returned no usable DNS responses; %d resolver errors", protocol, len(targets), len(targets), resolverFailures))
			default:
				warnings = append(warnings, fmt.Sprintf("%s: %d/%d endpoints unavailable; no endpoint produced a comparable result", protocol, len(targets), len(targets)))
			}
			for _, result := range targets {
				handled[result.Target.ID()] = true
			}
		}
	}
	for _, result := range report.Targets {
		if handled[result.Target.ID()] {
			continue
		}
		parts := make([]string, 0, 4)
		if result.Incomplete {
			parts = append(parts, "incomplete; excluded from ranking")
		}
		if result.OpenError != "" && !result.Incomplete && result.Stats.Scored == 0 {
			parts = append(parts, "unavailable")
		}
		if result.Stats.Failures > 0 {
			parts = append(parts, fmt.Sprintf("%d/%d queries failed", result.Stats.Failures, result.Stats.Total))
		}
		if result.Stats.ResolverFailures > 0 {
			resolverWarning := fmt.Sprintf("%d unusable DNS responses", result.Stats.ResolverFailures)
			if codes := rcodeCountsText(result.Stats.RCodeCounts); codes != "" {
				resolverWarning += " (" + codes + ")"
			}
			parts = append(parts, resolverWarning)
		}
		if result.Stats.Divergent > 0 {
			parts = append(parts, fmt.Sprintf("%d divergent responses", result.Stats.Divergent))
		}
		if result.Stats.Truncated > 0 {
			parts = append(parts, fmt.Sprintf("%d truncated responses", result.Stats.Truncated))
		}
		if result.Target.Resolver.Local {
			parts = append(parts, "local resolver; cache-hit latency excludes the upstream cost, so it is not ranked or recommended")
		}
		if len(parts) > 0 {
			warnings = append(warnings, fmt.Sprintf("%s: %s", targetWarningLabelWithOptions(result, redactSystem), strings.Join(parts, "; ")))
		}
	}
	redactedIDs := redactedTargetIDs(report, redactSystem)
	for _, warning := range report.Warnings {
		// Per-target warnings are rebuilt above as one compact line per
		// endpoint; only run-level warnings are carried through verbatim.
		if warning.Targeted() {
			continue
		}
		warnings = append(warnings, safetext.Escape(renderWarning(report, warning, redactSystem, redactedIDs)))
	}
	return warnings
}

// ipv6UnavailableWarning collapses the common case where every selected
// IPv6 endpoint fails at the transport layer because the local network has no
// usable IPv6 path. It deliberately leaves partial failures and DNS-level
// errors visible per endpoint, since those can identify a resolver-specific
// problem rather than a local address-family limitation.
func ipv6UnavailableWarning(report benchmark.Report) (string, []benchmark.TargetResult) {
	targets := make([]benchmark.TargetResult, 0)
	for _, result := range report.Targets {
		family, ok := catalog.AddressFamilyForAddress(result.Target.Address)
		if ok && family == catalog.Family6 {
			targets = append(targets, result)
		}
	}
	if len(targets) < 2 {
		return "", nil
	}
	for _, result := range targets {
		if !transportUnavailable(result) {
			return "", nil
		}
	}
	protocols := make(map[catalog.Protocol]bool, len(targets))
	for _, result := range targets {
		protocols[result.Target.Protocol] = true
	}
	orderedProtocols := make([]catalog.Protocol, 0, len(protocols))
	for _, protocol := range catalog.AllProtocols {
		if protocols[protocol] {
			orderedProtocols = append(orderedProtocols, protocol)
		}
	}
	protocolNames := make([]string, 0, len(orderedProtocols))
	for _, protocol := range orderedProtocols {
		protocolNames = append(protocolNames, protocol.String())
	}
	return fmt.Sprintf("IPv6: %d/%d endpoints unavailable across %s; no usable IPv6 path detected", len(targets), len(targets), strings.Join(protocolNames, ",")), targets
}

func transportUnavailable(result benchmark.TargetResult) bool {
	if result.Incomplete || result.Stats.Total == 0 {
		return result.OpenError != "" && !result.Incomplete
	}
	return result.Stats.Failures == result.Stats.Total &&
		result.Stats.Successes == 0 &&
		result.Stats.UsableResponses == 0 &&
		result.Stats.ResolverFailures == 0 &&
		result.Stats.Divergent == 0 &&
		result.Stats.Truncated == 0
}

func writeWarnings(writer io.Writer, report benchmark.Report, details bool) error {
	return writeWarningsWithOptions(writer, report, details, false)
}

// detailWarnings returns the full warning list rendered under --details.
//
// A message can quote strings the endpoint chose: a certificate SAN reaches a
// session error through "x509: certificate is valid for ...", and ESC survives
// the IA5String check x509 applies to those fields. The benchmark escapes the
// messages it builds, but the report does not depend on that - the rendered
// list is escaped here, where the report takes ownership of it, rather than in
// the writer, so every producer is covered. Escaping is idempotent, so an
// already-escaped warning is unchanged.
func detailWarnings(report benchmark.Report, redactSystem bool) []string {
	warnings := renderWarnings(report, redactSystem, redactedTargetIDs(report, redactSystem))
	escaped := make([]string, 0, len(warnings))
	for _, warning := range warnings {
		escaped = append(escaped, safetext.Escape(warning))
	}
	return escaped
}

func writeWarningsWithOptions(writer io.Writer, report benchmark.Report, details bool, redactSystem bool) error {
	warnings := compactWarningsWithOptions(report, redactSystem)
	if details {
		warnings = detailWarnings(report, redactSystem)
	}
	if len(warnings) == 0 {
		return nil
	}
	if _, err := io.WriteString(writer, "\nWarnings\n"); err != nil {
		return err
	}
	for _, warning := range warnings {
		if _, err := fmt.Fprintf(writer, "  - %s\n", warning); err != nil {
			return err
		}
	}
	return nil
}

func divergenceClassesText(classes map[string]int) string {
	if len(classes) == 0 {
		return "—"
	}
	keys := make([]string, 0, len(classes))
	for key := range classes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s:%d", key, classes[key]))
	}
	return strings.Join(parts, ",")
}

func divergenceExcludedText(detail benchmark.DivergenceDetail, redactedIDs map[string]string) string {
	if len(detail.Excluded) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(detail.Excluded))
	for _, exclusion := range detail.Excluded {
		targetID := exclusion.TargetID
		if replacement, ok := redactedIDs[targetID]; ok {
			targetID = replacement
		}
		part := safetext.Escape(targetID) + "=" + exclusion.ResponseClass
		if exclusion.Treatment != "" {
			part += "[" + exclusion.Treatment + "]"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ",")
}

func writeDivergenceDetails(writer io.Writer, report benchmark.Report, redactSystem bool) error {
	if len(report.Divergence) == 0 {
		return nil
	}
	if _, err := io.WriteString(writer, "\nDivergence details\n"); err != nil {
		return err
	}
	redactedIDs := redactedTargetIDs(report, redactSystem)
	for _, detail := range report.Divergence {
		baseline := detail.Baseline
		if detail.Ambiguous {
			baseline = "ambiguous (no baseline)"
		}
		if _, err := fmt.Fprintf(writer, "  - %s/%s policy=%s compared=%d baseline=%s; classes=%s; excluded=%s\n",
			safetext.Escape(detail.Name), benchmark.QueryTypeName(detail.QType), safetext.Escape(detail.Policy), detail.Compared, safetext.Escape(baseline),
			divergenceClassesText(detail.Classes), divergenceExcludedText(detail, redactedIDs)); err != nil {
			return err
		}
	}
	return nil
}

func WriteTable(writer io.Writer, report benchmark.Report, details bool) error {
	return WriteTableWithOptions(writer, report, TableOptions{Details: details})
}

func WriteTableWithOptions(writer io.Writer, report benchmark.Report, options TableOptions) error {
	if _, err := fmt.Fprintf(writer, "SpeeDNS benchmark\nSeed: %d | sample: %d domains | query types: %s\n\n", report.Seed, report.SampleSize, queryTypes(report.QueryTypes)); err != nil {
		return err
	}
	if report.CorpusMode != "" {
		if _, err := fmt.Fprintf(writer, "Corpus: %s | zone: %s | nonce: %s\n\n", report.CorpusMode, placeholderText(report.CorpusZone), placeholderText(report.CorpusNonce)); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(writer, "Recommendations\n"); err != nil {
		return err
	}
	protocols := tableProtocols(report, options)
	recommendations := make([][]string, 0, len(protocols))
	provisionals := make([][]string, 0, len(protocols))
	tiedWinner := false
	for _, protocol := range protocols {
		if winner, found := recommendedResult(report, protocol); found {
			recommendations = append(recommendations, summaryRowWithOptions(protocol, winner, "RECOMMENDED", options.Color, options.RedactSystem))
			tiedWinner = tiedWinner || winner.Stats.Tie
			continue
		}
		if winner, found := rankedResult(report, protocol, 1); found {
			provisionals = append(provisionals, summaryRowWithOptions(protocol, winner, "PROVISIONAL", options.Color, options.RedactSystem))
			tiedWinner = tiedWinner || winner.Stats.Tie
		}
	}
	if len(recommendations) == 0 {
		if _, err := fmt.Fprintf(writer, "  none qualified (minimum %d comparable samples and %.0f%% usable responses)\n", benchmark.MinimumRecommendedSamples, benchmark.MinimumRecommendedSuccessRate*100); err != nil {
			return err
		}
	} else if err := writeAlignedTable(writer, summaryHeaders(), recommendations); err != nil {
		return err
	}
	if len(provisionals) > 0 {
		if _, err := io.WriteString(writer, "\nProvisional winners\n"); err != nil {
			return err
		}
		if err := writeAlignedTable(writer, summaryHeaders(), provisionals); err != nil {
			return err
		}
	}
	if tiedWinner {
		if _, err := io.WriteString(writer, tieNote); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(writer, "\nComparisons\n"); err != nil {
		return err
	}
	for _, protocol := range protocols {
		if _, err := fmt.Fprintf(writer, "\nProtocol %s\n", strings.ToUpper(string(protocol))); err != nil {
			return err
		}
		rows, hiddenIPv6 := comparisonRowsForTable(report, protocol, options)
		if len(rows) == 0 && hiddenIPv6 == 0 {
			if _, err := io.WriteString(writer, "  no targets\n"); err != nil {
				return err
			}
			continue
		}
		if len(rows) > 0 {
			if err := writeAlignedTable(writer, comparisonHeaders(options.Details), rows); err != nil {
				return err
			}
		}
		if hiddenIPv6 > 0 {
			if _, err := fmt.Fprintf(writer, "  %s hidden: no usable IPv6 path detected (--details lists them)\n", ipv6EndpointCountText(hiddenIPv6)); err != nil {
				return err
			}
		}
	}
	if err := writePairedEffects(writer, report, options); err != nil {
		return err
	}
	if options.ProfileView {
		if err := writeProfileView(writer, report, options); err != nil {
			return err
		}
	}
	if options.Details {
		if err := writeDivergenceDetails(writer, report, options.RedactSystem); err != nil {
			return err
		}
	}
	if err := writeWarningsWithOptions(writer, report, options.Details, options.RedactSystem); err != nil {
		return err
	}
	return nil
}

func queryTypes(types []uint16) string {
	names := make([]string, 0, len(types))
	for _, qtype := range types {
		names = append(names, benchmark.QueryTypeName(qtype))
	}
	return strings.Join(names, ",")
}
