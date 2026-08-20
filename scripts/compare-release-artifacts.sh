#!/usr/bin/env bash
set -euo pipefail

usage() {
	echo "usage: $0 FIRST-DIST SECOND-DIST" >&2
}

first_dir="${1:-}"
second_dir="${2:-}"
if [[ -z "${first_dir}" || -z "${second_dir}" || ! -d "${first_dir}" || ! -d "${second_dir}" ]]; then
	usage
	exit 2
fi

temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/speedns-reproducibility.XXXXXX")"
trap 'rm -rf -- "${temporary_dir}"' EXIT

artifact_names() {
	local directory="$1"
	find "${directory}" -maxdepth 1 -type f \
		\( -name '*.tar.gz' -o -name '*.deb' -o -name 'checksums.txt' \) \
		-exec basename {} \; |
		sort -u
}

artifact_names "${first_dir}" >"${temporary_dir}/first.names"
artifact_names "${second_dir}" >"${temporary_dir}/second.names"
if ! cmp -s "${temporary_dir}/first.names" "${temporary_dir}/second.names"; then
	echo "reproducibility artifact sets differ" >&2
	diff -u "${temporary_dir}/first.names" "${temporary_dir}/second.names" >&2 || true
	exit 1
fi
if [[ ! -s "${temporary_dir}/first.names" ]]; then
	echo "no release artifacts were found to compare" >&2
	exit 1
fi

while IFS= read -r name; do
	first_hash="$(sha256sum "${first_dir}/${name}" | awk '{print $1}')"
	second_hash="$(sha256sum "${second_dir}/${name}" | awk '{print $1}')"
	if [[ "${first_hash}" != "${second_hash}" ]]; then
		echo "reproducibility mismatch: ${name}" >&2
		echo "first:  ${first_hash}" >&2
		echo "second: ${second_hash}" >&2
		exit 1
	fi
done <"${temporary_dir}/first.names"

echo "reproducibility check passed"
