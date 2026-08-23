#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

coverage_dir=$(mktemp -d "${TMPDIR:-/tmp}/speedns-coverage.XXXXXX")
trap 'rm -rf -- "$coverage_dir"' EXIT

profile="$coverage_dir/merged.out"
first_profile=true
package_index=0

while IFS= read -r package; do
	part="$coverage_dir/package-${package_index}.out"
	package_index=$((package_index + 1))
	go test -count=1 -covermode=atomic -coverprofile="$part" "$package"
	if [[ "$first_profile" == true ]]; then
		cat "$part" > "$profile"
		first_profile=false
	else
		tail -n +2 "$part" >> "$profile"
	fi
done < <(go list ./...)

# The percentage is computed from the merged profile rather than from
# `go tool cover -func`, which aggregates per *declared* function and therefore
# omits the body of a package-level `var x = func(...)` entirely — not as 0%,
# but absent from its total. Those bodies are production code (test seams are
# written that way throughout this repo), so a gate that cannot see them can
# report 100.0% while real statements go unexecuted.
read -r covered statements total < <(
	awk 'NR > 1 { total += $2; if ($3 + 0 > 0) covered += $2 }
	     END { printf "%d %d %.1f\n", covered, total, (total ? 100 * covered / total : 0) }' "$profile"
)
printf 'total statement coverage: %s%% (%s/%s statements)\n' "$total" "$covered" "$statements"

if [[ -n "${COVERAGE_OUTPUT:-}" ]]; then
	mkdir -p "$(dirname "$COVERAGE_OUTPUT")"
	cp "$profile" "$COVERAGE_OUTPUT"
fi

# Compared as counts, not as the printed percentage: 3337 of 3338 statements
# rounds to "100.0" and would slip through a string comparison.
if [[ "$covered" != "$statements" ]]; then
	printf 'coverage gate failed: expected 100.0%%\n' >&2
	awk 'NR > 1 && $3 + 0 == 0 { print "  uncovered: " $1 }' "$profile" >&2
	exit 1
fi
