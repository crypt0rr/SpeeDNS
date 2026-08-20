#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary_dir="$(mktemp -d)"
trap 'rm -rf "${temporary_dir}"' EXIT

run_case() {
	local name="$1"
	local mode="$2"
	local attempts="$3"
	local case_dir="${temporary_dir}/${name}"
	mkdir -p "${case_dir}"
	SPEEDNS_BINARY="${root_dir}/scripts/live-smoke-fake.sh" \
	SPEEDNS_SMOKE_DIR="${case_dir}" \
	SPEEDNS_SMOKE_ATTEMPTS="${attempts}" \
	SPEEDNS_SMOKE_RETRY_DELAY=0 \
	SPEEDNS_FAKE_MODE="${mode}" \
	SPEEDNS_FAKE_STATE="${case_dir}/state" \
	bash "${root_dir}/scripts/live-smoke.sh" >"${case_dir}/log" 2>&1
}

run_case pass pass 1
run_case transient transient 2
grep -q 'retrying after 0s' "${temporary_dir}/transient/log"

if run_case persistent fail 2; then
	echo "persistent smoke failure unexpectedly passed" >&2
	exit 1
fi
[[ "$(wc -l <"${temporary_dir}/persistent/failures.txt" | tr -d ' ')" == 5 ]]
grep -q 'exhausted 2 attempts' "${temporary_dir}/persistent/failures.txt"

echo "live smoke fixture passed"
