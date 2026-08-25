package compare

import (
	"fmt"
	"sort"
	"strings"
)

// Blocker is one reason two runs may not be compared. It carries both values so
// the reader can see what differs without opening either file.
type Blocker struct {
	Field    string `json:"field"`
	Baseline string `json:"baseline"`
	Current  string `json:"current"`
	Reason   string `json:"reason"`
}

// Disclosure is something a reader must weigh but which does not block a
// comparison.
type Disclosure struct {
	Reason string `json:"reason"`
	Detail string `json:"detail"`
}

// gateField is one row of the comparability contract. Keeping the contract as
// data rather than an if-chain means one test loop covers every row, and a new
// row cannot be added without a value renderer and a reason.
type gateField struct {
	name   string
	value  func(Report) (string, bool)
	reason string
}

// runIdentity lists the fields that must match exactly. Each decides WHAT was
// measured rather than how it was reported, so a difference means the two runs
// asked different questions and any comparison between them describes the
// question rather than the resolver.
var runIdentity = []gateField{
	{"run.seed", func(r Report) (string, bool) { return optInt64(r.Run.Seed) },
		"a different seed selects different names and a different query order, so the two runs asked different questions"},
	{"run.sample_size", func(r Report) (string, bool) { return optInt(r.Run.SampleSize) },
		"the sample size is the denominator of every published count"},
	{"run.queries_per_target", func(r Report) (string, bool) { return optInt(r.Run.QueriesPerTarget) },
		"a different query matrix measures a different population"},
	{"run.query_types", func(r Report) (string, bool) { return joinInts(r.Run.QueryTypes), len(r.Run.QueryTypes) > 0 },
		"different record types are different questions"},
	{"run.corpus_mode", func(r Report) (string, bool) { return orDash(r.Run.CorpusMode), true },
		"a warm-cache run and a cache-miss run measure different things"},
	{"provenance.corpus_sha256", func(r Report) (string, bool) { return optString(r.Run.Provenance.CorpusSHA256) },
		"a different corpus is a different set of names"},
	{"provenance.corpus_entries", func(r Report) (string, bool) { return optInt(r.Run.Provenance.CorpusEntries) },
		"a different corpus size is a different population"},
	{"provenance.timeout_ms", func(r Report) (string, bool) { return optInt64(r.Run.Provenance.TimeoutMS) },
		"the timeout decides which slow queries become failures, which moves every count this diff reports"},
	{"provenance.concurrency", func(r Report) (string, bool) { return optInt(r.Run.Provenance.Concurrency) },
		"concurrency changes in-flight contention, and so the loss rate the counts are read against"},
	{"provenance.family", func(r Report) (string, bool) { return optString(r.Run.Provenance.Family) },
		"the address family decides which targets exist and which address is dialled"},
	{"provenance.dnssec", func(r Report) (string, bool) { return optBool(r.Run.Provenance.DNSSEC) },
		"DNSSEC probing sets the EDNS(0) DO bit on every measured query, changing the wire format of the thing being measured"},
	{"provenance.speedns_version", func(r Report) (string, bool) { return majorMinor(r.Run.Provenance.Version), true },
		"a different minor version may classify results differently, and a tool change misread as a resolver change is exactly what this diff exists to prevent"},
}

// Gate applies the comparability contract. A non-empty result means no
// comparison is produced and no count from either report is shown.
func Gate(baseline, current Report) []Blocker {
	blockers := make([]Blocker, 0)

	// A cache-miss run can never be compared with anything, including another
	// cache-miss run: the generated names are fresh per run, so no two of them
	// asked the same questions -- and an equal nonce would prove the second run
	// read the first run's cached answers, which is worse.
	for _, side := range []struct {
		label  string
		report Report
	}{{"baseline", baseline}, {"current", current}} {
		if side.report.Run.CorpusMode == "cache-miss" {
			blockers = append(blockers, Blocker{
				Field:    "run.corpus_mode",
				Baseline: orDash(baseline.Run.CorpusMode),
				Current:  orDash(current.Run.CorpusMode),
				Reason:   "cache-miss runs generate fresh names each time, so no two of them measured the same questions; there is no sound comparison between them",
			})
			return blockers
		}
	}

	for _, field := range runIdentity {
		left, leftOK := field.value(baseline)
		right, rightOK := field.value(current)
		if !leftOK || !rightOK {
			missing := "baseline"
			if leftOK {
				missing = "current"
			}
			blockers = append(blockers, Blocker{
				Field: field.name, Baseline: presence(leftOK, left), Current: presence(rightOK, right),
				Reason: fmt.Sprintf("the %s report does not record this field, so the runs cannot be shown to have measured the same thing", missing),
			})
			continue
		}
		if left != right {
			blockers = append(blockers, Blocker{Field: field.name, Baseline: left, Current: right, Reason: field.reason})
		}
	}
	return blockers
}

// Disclosures lists what a reader must weigh for a comparison that proceeded.
// None of these blocks a comparison; all of them bound what it means.
func Disclosures(baseline, current Report) []Disclosure {
	found := make([]Disclosure, 0)

	gap := current.Run.StartedAt.Sub(baseline.Run.StartedAt)
	if !baseline.Run.StartedAt.IsZero() && !current.Run.StartedAt.IsZero() {
		if gap < 0 {
			found = append(found, Disclosure{"argument-order", fmt.Sprintf(
				"the current report started %s BEFORE the baseline; the arguments may be reversed, and they were not silently swapped",
				(-gap).Round(1e9))})
		} else {
			found = append(found, Disclosure{"elapsed", fmt.Sprintf(
				"the runs are %s apart (%s and %s UTC); a resolver reached over a different network path at a different hour is a different measurement, and no field in either report records the path",
				gap.Round(1e9), baseline.Run.StartedAt.UTC().Format("2006-01-02 15:04"), current.Run.StartedAt.UTC().Format("2006-01-02 15:04"))})
		}
	}
	if bv, cv := baseline.Run.Provenance.Version, current.Run.Provenance.Version; bv != cv {
		found = append(found, Disclosure{"build", fmt.Sprintf("built by different versions: %s and %s", orDash(bv), orDash(cv))})
	} else if bv == "" || bv == "dev" {
		found = append(found, Disclosure{"build", "both reports were produced by an unversioned development build; they may not be the same code"})
	} else if baseline.Run.Provenance.Commit != current.Run.Provenance.Commit {
		found = append(found, Disclosure{"build", fmt.Sprintf("same version but different commits: %s and %s",
			shortCommit(baseline.Run.Provenance.Commit), shortCommit(current.Run.Provenance.Commit))})
	}
	if baseline.Run.Provenance.OS != current.Run.Provenance.OS ||
		baseline.Run.Provenance.Architecture != current.Run.Provenance.Architecture {
		found = append(found, Disclosure{"position", fmt.Sprintf("measured from different platforms: %s/%s and %s/%s; a resolver's answers can differ by vantage point",
			baseline.Run.Provenance.OS, baseline.Run.Provenance.Architecture,
			current.Run.Provenance.OS, current.Run.Provenance.Architecture)})
	} else {
		found = append(found, Disclosure{"position", "matching platform is consistent with the same measuring position but does not establish it; a resolver's answers can differ by vantage point"})
	}
	if added, removed := setDifference(baseline.Run.Provenance.Interfaces, current.Run.Provenance.Interfaces); len(added)+len(removed) > 0 {
		found = append(found, Disclosure{"interfaces", fmt.Sprintf(
			"the interface inventory differs (added %s, removed %s); this cannot tell a new container from a new network",
			listOrNone(added), listOrNone(removed))})
	}
	if family := baseline.Run.Provenance.Family; family != nil && *family == "auto" {
		found = append(found, Disclosure{"family-auto", "both runs used --family auto, which records the request rather than what it resolved to; the target lists below are what actually differed"})
	}
	return found
}

func joinInts(values []int) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, fmt.Sprintf("%d", value))
	}
	return strings.Join(parts, ",")
}

func optInt(value *int) (string, bool) {
	if value == nil {
		return "", false
	}
	return fmt.Sprintf("%d", *value), true
}

func optInt64(value *int64) (string, bool) {
	if value == nil {
		return "", false
	}
	return fmt.Sprintf("%d", *value), true
}

func optString(value *string) (string, bool) {
	if value == nil {
		return "", false
	}
	return orDash(*value), true
}

func optBool(value *bool) (string, bool) {
	if value == nil {
		return "", false
	}
	return fmt.Sprintf("%t", *value), true
}

func presence(ok bool, value string) string {
	if !ok {
		return "(not recorded)"
	}
	return value
}

// majorMinor keeps only the feature version. A patch difference is disclosed
// rather than refused: patches fix behaviour without changing how a result is
// classified, and refusing on them would make the gate fire on every upgrade.
func majorMinor(version string) string {
	if version == "" {
		return "dev"
	}
	trimmed := strings.TrimPrefix(version, "v")
	parts := strings.SplitN(trimmed, ".", 3)
	if len(parts) < 2 {
		return trimmed
	}
	return parts[0] + "." + parts[1]
}

func shortCommit(commit string) string {
	if len(commit) > 8 {
		return commit[:8]
	}
	return orDash(commit)
}

func orDash(value string) string {
	if value == "" {
		return "—"
	}
	return value
}

func setDifference(before, after []string) (added, removed []string) {
	inBefore := make(map[string]bool, len(before))
	for _, item := range before {
		inBefore[item] = true
	}
	inAfter := make(map[string]bool, len(after))
	for _, item := range after {
		inAfter[item] = true
	}
	for item := range inAfter {
		if !inBefore[item] {
			added = append(added, item)
		}
	}
	for item := range inBefore {
		if !inAfter[item] {
			removed = append(removed, item)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func listOrNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ", ")
}
