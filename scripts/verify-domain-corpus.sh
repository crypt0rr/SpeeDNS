#!/usr/bin/env bash
set -euo pipefail

corpus_dir="${1:-}"
if [[ -z "${corpus_dir}" ]]; then
	echo "usage: scripts/verify-domain-corpus.sh CORPUS-DIRECTORY" >&2
	exit 2
fi

domains_file="${corpus_dir}/domains.txt"
metadata_file="${corpus_dir}/domains.meta.json"
if [[ ! -f "${domains_file}" || ! -f "${metadata_file}" ]]; then
	echo "corpus directory is missing domains.txt or domains.meta.json: ${corpus_dir}" >&2
	exit 1
fi

metadata_entries="$(awk -F: '$1 ~ /"entries"/ {gsub(/[^0-9]/, "", $2); print $2; exit}' "${metadata_file}")"
metadata_sha256="$(awk -F'"' '$2 == "sha256" {print $4; exit}' "${metadata_file}")"
if [[ ! "${metadata_entries}" =~ ^[0-9]+$ ]]; then
	echo "corpus metadata has no valid entries count: ${metadata_file}" >&2
	exit 1
fi
if [[ ! "${metadata_sha256}" =~ ^[0-9a-fA-F]{64}$ ]]; then
	echo "corpus metadata has no valid SHA-256: ${metadata_file}" >&2
	exit 1
fi

actual_entries="$(wc -l <"${domains_file}" | tr -d '[:space:]')"
if [[ "${actual_entries}" != "${metadata_entries}" ]]; then
	echo "corpus entry count mismatch: metadata=${metadata_entries}, file=${actual_entries}" >&2
	exit 1
fi

sha256_file() {
	local file="$1"
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "${file}" | awk '{print $1}'
		return
	fi
	if command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "${file}" | awk '{print $1}'
		return
	fi
	echo "a SHA-256 utility (sha256sum or shasum) is required" >&2
	exit 1
}

actual_sha256="$(sha256_file "${domains_file}")"
if [[ "${actual_sha256}" != "${metadata_sha256}" ]]; then
	echo "corpus checksum mismatch: metadata=${metadata_sha256}, file=${actual_sha256}" >&2
	exit 1
fi

echo "domain corpus verified (${actual_entries} entries, sha256 ${actual_sha256})"
