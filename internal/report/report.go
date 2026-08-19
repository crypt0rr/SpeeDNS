package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
)

type JSONReport struct {
	SchemaVersion int                          `json:"schema_version"`
	Run           JSONRun                      `json:"run"`
	Results       []JSONResult                 `json:"results"`
	Rankings      []benchmark.Ranking          `json:"rankings"`
	PairedEffects []benchmark.PairedEffect     `json:"paired_effects,omitempty"`
	Divergence    []benchmark.DivergenceDetail `json:"divergence,omitempty"`
	Warnings      []string                     `json:"warnings,omitempty"`
}

type JSONRun struct {
	StartedAt  string   `json:"started_at"`
	FinishedAt string   `json:"finished_at"`
	Seed       int64    `json:"seed"`
	SampleSize int      `json:"sample_size"`
	Queries    int      `json:"queries_per_target"`
	QueryTypes []uint16 `json:"query_types"`
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
	EndpointURL        string           `json:"endpoint_url,omitempty"`
	TLSServerName      string           `json:"tls_server_name,omitempty"`
	TLSIdentitySource  string           `json:"tls_identity_source,omitempty"`
	BootstrapMode      string           `json:"bootstrap_mode"`
	BootstrapAddresses []string         `json:"bootstrap_addresses,omitempty"`
	DialAddress        string           `json:"dial_address,omitempty"`
}

type JSONOptions struct {
	RedactSystem bool
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
				Address: view.Address, Protocol: result.Target.Protocol,
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
	rankings := append([]benchmark.Ranking(nil), report.Rankings...)
	for index := range rankings {
		if redactedID, ok := redactedIDs[rankings[index].TargetID]; ok {
			rankings[index].TargetID = redactedID
		}
	}
	warnings := append([]string(nil), report.Warnings...)
	if options.RedactSystem {
		warnings = redactWarnings(report, redactedIDs)
	}
	return JSONReport{
		SchemaVersion: 1,
		Run: JSONRun{
			StartedAt:  report.StartedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
			FinishedAt: report.FinishedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
			Seed:       report.Seed, SampleSize: report.SampleSize, Queries: report.Queries, QueryTypes: report.QueryTypes,
		},
		Results: results, Rankings: rankings, PairedEffects: pairedEffectsForJSON(report, redactedIDs), Divergence: divergenceForJSON(report, redactedIDs), Warnings: warnings,
	}
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
	}); err != nil {
		return err
	}
	for _, result := range report.Targets {
		rank := rankFor(report, result.Target.ID())
		stats := result.Stats
		metadata := result.Target.EndpointMetadata()
		redactedIDs := redactedTargetIDs(report, options.RedactSystem)
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

// csvCell prefixes values that spreadsheet applications may interpret as a
// formula. The leading apostrophe is part of the exported cell value and is
// understood by spreadsheet programs as text protection.
func csvCell(value string) string {
	if value == "" {
		return value
	}
	switch value[0] {
	case '=', '+', '-', '@', '\t', '\r':
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

func targetViewFor(target catalog.Target, redact bool, redactedID string) targetView {
	view := targetView{
		ID: target.ID(), Name: target.DisplayName(), Owner: target.Resolver.Owner,
		Policy: target.Resolver.Policy, Address: target.Address,
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
	replacements := []string{
		result.Target.ID(), redactedID,
		result.Target.DisplayName(), redactedSystemName,
		result.Target.Resolver.Owner, redactedSystemOwner,
		result.DialAddress, redactedValue,
		result.Target.Address, redactedValue,
	}
	filtered := replacements[:0]
	for index := 0; index+1 < len(replacements); index += 2 {
		if replacements[index] == "" {
			continue
		}
		filtered = append(filtered, replacements[index], replacements[index+1])
	}
	return strings.NewReplacer(filtered...).Replace(value)
}

func redactObservations(result benchmark.TargetResult, redact bool, redactedID string) []benchmark.Observation {
	if !redact || !isSystemTarget(result.Target) || len(result.Observations) == 0 {
		return result.Observations
	}
	observations := append([]benchmark.Observation(nil), result.Observations...)
	for index := range observations {
		observations[index].Error = redactResultText(result, observations[index].Error, true, redactedID)
	}
	return observations
}

func redactColdObservations(result benchmark.TargetResult, redact bool, redactedID string) []benchmark.ColdObservation {
	if !redact || !isSystemTarget(result.Target) || len(result.Cold) == 0 {
		return result.Cold
	}
	observations := append([]benchmark.ColdObservation(nil), result.Cold...)
	for index := range observations {
		observations[index].Error = redactResultText(result, observations[index].Error, true, redactedID)
	}
	return observations
}

func redactWarningValue(report benchmark.Report, warning string, redactedIDs map[string]string) string {
	for _, result := range report.Targets {
		if isSystemTarget(result.Target) {
			warning = redactResultText(result, warning, true, redactedIDs[result.Target.ID()])
		}
	}
	return warning
}

func redactWarnings(report benchmark.Report, redactedIDs map[string]string) []string {
	warnings := append([]string(nil), report.Warnings...)
	for index := range warnings {
		warnings[index] = redactWarningValue(report, warnings[index], redactedIDs)
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
	case "PROVISIONAL", "INELIGIBLE", "INCOMPLETE", "NOT COMPARABLE", "NO CLEAR DIFFERENCE":
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

func usableRate(stats benchmark.Statistics) float64 {
	// Reports may be constructed by older callers that populate only the
	// original success fields. Prefer the explicit semantic metric whenever
	// the benchmark supplied one, including a real zero rate with resolver
	// failures.
	if stats.UsableResponses == 0 && stats.ResolverFailures == 0 && stats.UsableRate == 0 && stats.Successes > 0 {
		return stats.SuccessRate
	}
	return stats.UsableRate
}

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

func summaryRowWithOptions(protocol catalog.Protocol, result benchmark.TargetResult, status string, color bool, redactSystem bool) []string {
	view := targetViewFor(result.Target, redactSystem, redactedValue)
	return []string{
		string(protocol), view.Owner, view.Address, view.Policy,
		latencyText(result.Stats.MedianMS), latencyText(result.Stats.P95MS), percentText(result.Stats.SuccessRate), percentText(usableRate(result.Stats)),
		scoreText(result), styledStatus(status, color),
	}
}

func comparisonRowWithOptions(report benchmark.Report, result benchmark.TargetResult, details bool, color bool, redactSystem bool) []string {
	view := targetViewFor(result.Target, redactSystem, redactedValue)
	row := []string{
		rankText(report, result.Target.ID()), view.Owner, view.Address, view.Policy,
		latencyText(result.Stats.MedianMS), latencyText(result.Stats.P95MS), percentText(result.Stats.SuccessRate), percentText(usableRate(result.Stats)),
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
	return append(row, styledStatus(resultStatus(result), color))
}

func dialAddressTextWithOptions(result benchmark.TargetResult, redactSystem bool) string {
	if result.DialAddress == "" {
		return "—"
	}
	if redactSystem && isSystemTarget(result.Target) {
		return redactedValue
	}
	return result.DialAddress
}

func endpointURLText(value string) string {
	if value == "" {
		return "—"
	}
	return value
}

func tlsServerNameText(value string) string {
	if value == "" {
		return "—"
	}
	return value
}

func tlsIdentitySourceText(value string) string {
	if value == "" || value == catalog.TLSIdentityNotApplicable {
		return "—"
	}
	return value
}

func bootstrapModeText(value string) string {
	if value == "" || value == catalog.BootstrapNotApplicable {
		return "—"
	}
	return value
}

func bootstrapAddressesText(addresses []string) string {
	if len(addresses) == 0 {
		return "—"
	}
	return strings.Join(addresses, ";")
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
		for range comparisonHeaders(true)[len(comparisonHeaders(false))-1 : len(comparisonHeaders(true))-1] {
			row = append(row, "—")
		}
	}
	return append(row, "—")
}

func comparisonRowsForTable(report benchmark.Report, protocol catalog.Protocol, options TableOptions) [][]string {
	rows := comparisonRowsWithOptions(report, protocol, options.Details, options.Color, options.RedactSystem)
	if len(options.Profiles) == 0 {
		return rows
	}
	present := make(map[string]bool, len(report.Targets))
	for _, result := range report.Targets {
		present[result.Target.ID()] = true
	}
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
	return rows
}

func pairedEffectTargetText(report benchmark.Report, targetID string, redactSystem bool) string {
	result, ok := report.ResultFor(targetID)
	if !ok {
		return "—"
	}
	view := targetViewFor(result.Target, redactSystem, redactedValue)
	return strings.TrimSpace(view.Owner + " " + view.Address)
}

func pairedDeltaText(effect benchmark.PairedEffect) string {
	if effect.Samples == 0 {
		return "—"
	}
	return fmt.Sprintf("%+.2f ms", effect.MedianDeltaMS)
}

func pairedCIText(effect benchmark.PairedEffect) string {
	if effect.Samples == 0 {
		return "—"
	}
	return fmt.Sprintf("[%+.2f, %+.2f] ms", effect.CILowMS, effect.CIHighMS)
}

func pairedInterpretation(effect benchmark.PairedEffect, color bool) string {
	if effect.Reference {
		return styledStatus("REFERENCE", color)
	}
	if effect.Samples == 0 {
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

func pairedEffectRows(report benchmark.Report, options TableOptions) [][]string {
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
	rows := make([][]string, 0, len(effects))
	for _, effect := range effects {
		rows = append(rows, []string{
			string(effect.Protocol), effect.Policy,
			pairedEffectTargetText(report, effect.TargetID, options.RedactSystem),
			pairedEffectTargetText(report, effect.ReferenceTargetID, options.RedactSystem),
			strconv.Itoa(effect.Samples), pairedDeltaText(effect), pairedCIText(effect),
			pairedInterpretation(effect, options.Color),
		})
	}
	return rows
}

func writePairedEffects(writer io.Writer, report benchmark.Report, options TableOptions) error {
	if len(report.PairedEffects) == 0 {
		return nil
	}
	if _, err := io.WriteString(writer, "\nPaired latency effects (target - reference; policy-local reference)\n"); err != nil {
		return err
	}
	return writeAlignedTable(writer, []string{"Protocol", "Policy", "Target", "Reference", "Samples", "Median Δ", "95% CI", "Interpretation"}, pairedEffectRows(report, options))
}

func writeAlignedTable(writer io.Writer, headers []string, rows [][]string) error {
	table := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0)
	indent := func(values []string) string {
		copyValues := append([]string(nil), values...)
		copyValues[0] = "  " + copyValues[0]
		return strings.Join(copyValues, "\t")
	}
	if _, err := fmt.Fprintln(table, indent(headers)); err != nil {
		return err
	}
	for _, row := range rows {
		if _, err := fmt.Fprintln(table, indent(row)); err != nil {
			return err
		}
	}
	return table.Flush()
}

func summaryHeaders() []string {
	return []string{"Protocol", "Owner", "Address", "Policy", "Median", "P95", "Success", "Usable", "Score", "Status"}
}

func comparisonHeaders(details bool) []string {
	headers := []string{"Rank", "Owner", "Address", "Policy", "Median", "P95", "Success", "Usable", "Score"}
	if details {
		headers = append(headers, "Cold", "MAD", "Scored", "Failed", "ResolverFail", "Divergent", "Truncated", "Reconnects", "RCodes", "Endpoint", "TLSName", "TLSSource", "Bootstrap", "BootstrapAddrs", "Dial")
	}
	return append(headers, "Status")
}

func targetWarningLabel(result benchmark.TargetResult) string {
	return targetWarningLabelWithOptions(result, false)
}

func targetWarningLabelWithOptions(result benchmark.TargetResult, redactSystem bool) string {
	view := targetViewFor(result.Target, redactSystem, redactedValue)
	return fmt.Sprintf("%s %s/%s", view.Name, view.Address, result.Target.Protocol)
}

func isTargetWarningWithOptions(warning string, results []benchmark.TargetResult, redactSystem bool) bool {
	for _, result := range results {
		if strings.HasPrefix(warning, targetWarningLabel(result)) || strings.HasPrefix(warning, targetWarningLabelWithOptions(result, redactSystem)) {
			return true
		}
	}
	return false
}

func compactWarnings(report benchmark.Report) []string {
	return compactWarningsWithOptions(report, false)
}

func compactWarningsWithOptions(report benchmark.Report, redactSystem bool) []string {
	warnings := make([]string, 0)
	handled := make(map[string]bool)
	for _, protocol := range reportProtocols(report) {
		targets := make([]benchmark.TargetResult, 0)
		for _, result := range report.Targets {
			if result.Target.Protocol == protocol {
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
		if len(parts) > 0 {
			warnings = append(warnings, fmt.Sprintf("%s: %s", targetWarningLabelWithOptions(result, redactSystem), strings.Join(parts, "; ")))
		}
	}
	for _, warning := range report.Warnings {
		if !isTargetWarningWithOptions(warning, report.Targets, redactSystem) {
			if redactSystem {
				warning = redactWarningValue(report, warning, redactedTargetIDs(report, true))
			}
			warnings = append(warnings, warning)
		}
	}
	return warnings
}

func writeWarnings(writer io.Writer, report benchmark.Report, details bool) error {
	return writeWarningsWithOptions(writer, report, details, false)
}

func writeWarningsWithOptions(writer io.Writer, report benchmark.Report, details bool, redactSystem bool) error {
	warnings := report.Warnings
	if !details {
		warnings = compactWarningsWithOptions(report, redactSystem)
	} else if redactSystem {
		warnings = redactWarnings(report, redactedTargetIDs(report, true))
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
		part := targetID + "=" + exclusion.ResponseClass
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
			detail.Name, benchmark.QueryTypeName(detail.QType), detail.Policy, detail.Compared, baseline,
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
	if _, err := io.WriteString(writer, "Recommendations\n"); err != nil {
		return err
	}
	protocols := tableProtocols(report, options)
	recommendations := make([][]string, 0, len(protocols))
	provisionals := make([][]string, 0, len(protocols))
	for _, protocol := range protocols {
		if winner, found := recommendedResult(report, protocol); found {
			recommendations = append(recommendations, summaryRowWithOptions(protocol, winner, "RECOMMENDED", options.Color, options.RedactSystem))
			continue
		}
		if winner, found := rankedResult(report, protocol, 1); found {
			provisionals = append(provisionals, summaryRowWithOptions(protocol, winner, "PROVISIONAL", options.Color, options.RedactSystem))
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
	if _, err := io.WriteString(writer, "\nComparisons\n"); err != nil {
		return err
	}
	for _, protocol := range protocols {
		if _, err := fmt.Fprintf(writer, "\nProtocol %s\n", strings.ToUpper(string(protocol))); err != nil {
			return err
		}
		rows := comparisonRowsForTable(report, protocol, options)
		if len(rows) == 0 {
			if _, err := io.WriteString(writer, "  no targets\n"); err != nil {
				return err
			}
			continue
		}
		if err := writeAlignedTable(writer, comparisonHeaders(options.Details), rows); err != nil {
			return err
		}
	}
	if err := writePairedEffects(writer, report, options); err != nil {
		return err
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
