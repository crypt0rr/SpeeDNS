#!/usr/bin/env bash
set -euo pipefail

binary="${SPEEDNS_BINARY:-}"
smoke_dir="${SPEEDNS_SMOKE_DIR:-}"
attempts="${SPEEDNS_SMOKE_ATTEMPTS:-3}"
retry_delay="${SPEEDNS_SMOKE_RETRY_DELAY:-5}"

if [[ -z "${binary}" || ! -x "${binary}" ]]; then
	echo "SPEEDNS_BINARY must name an executable speedns binary" >&2
	exit 2
fi
if [[ -z "${smoke_dir}" ]]; then
	echo "SPEEDNS_SMOKE_DIR must name an evidence directory" >&2
	exit 2
fi
if [[ ! "${attempts}" =~ ^[1-9][0-9]*$ ]]; then
	echo "SPEEDNS_SMOKE_ATTEMPTS must be a positive integer" >&2
	exit 2
fi
mkdir -p "${smoke_dir}"
: >"${smoke_dir}/failures.txt"

run_smoke() {
	local name="$1"
	local protocol="$2"
	local resolver="$3"
	local output="${smoke_dir}/${name}.json"
	local stdout_file="${smoke_dir}/${name}.stdout"
	local stderr_file="${smoke_dir}/${name}.stderr"
	local attempt status

	echo "::group::${name} (${protocol})"
	for ((attempt = 1; attempt <= attempts; attempt++)); do
		echo "${name}: attempt ${attempt}/${attempts}"
		set +e
		"${binary}" \
			--no-defaults \
			--protocol "${protocol}" \
			--resolver "${resolver}" \
			--sample 1 \
			--type A \
			--seed 42 \
			--timeout 5s \
			--concurrency 1 \
			--format json \
			--output "${output}" \
			>"${stdout_file}" \
			2>"${stderr_file}"
		status=$?
		set -e
		if [[ "${status}" -eq 0 ]]; then
			echo "${name} passed on attempt ${attempt}"
			cat "${stderr_file}"
			cat "${stdout_file}"
			echo "::endgroup::"
			return 0
		fi
		echo "${name} failed with exit code ${status}"
		if [[ "${attempt}" -lt "${attempts}" ]]; then
			echo "${name}: retrying after ${retry_delay}s"
			sleep "${retry_delay}"
		fi
	done

	printf '%s (%s): exhausted %s attempts\n' "${name}" "${protocol}" "${attempts}" >>"${smoke_dir}/failures.txt"
	cat "${stderr_file}"
	cat "${stdout_file}"
	echo "::endgroup::"
}

run_smoke udp udp 'google=udp://8.8.8.8:53'
run_smoke tcp tcp 'google=tcp://8.8.8.8:53'
run_smoke doh doh 'google=https://dns.google/dns-query'
run_smoke dot dot 'google=tls://dns.google:853'
run_smoke doq doq 'quad9=quic://dns.quad9.net:853'

if [[ -s "${smoke_dir}/failures.txt" ]]; then
	{
		echo '## Live DNS smoke failures'
		echo
		cat "${smoke_dir}/failures.txt"
	} >>"${GITHUB_STEP_SUMMARY:-/dev/null}"
	exit 1
fi

echo '## Live DNS smoke passed' >>"${GITHUB_STEP_SUMMARY:-/dev/null}"
