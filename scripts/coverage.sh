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

total=$(go tool cover -func="$profile" | awk '$1 == "total:" { gsub("%", "", $3); print $3 }')
printf 'total statement coverage: %s%%\n' "$total"

if [[ -n "${COVERAGE_OUTPUT:-}" ]]; then
	mkdir -p "$(dirname "$COVERAGE_OUTPUT")"
	cp "$profile" "$COVERAGE_OUTPUT"
fi

if [[ "$total" != "100.0" ]]; then
	printf 'coverage gate failed: expected 100.0%%\n' >&2
	exit 1
fi
