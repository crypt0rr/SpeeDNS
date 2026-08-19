#!/usr/bin/env bash
set -euo pipefail

# Maintainer-only helper for refreshing the pinned 1,000-name Tranco snapshot.
# Runtime SpeeDNS execution never downloads domain data.
list_id="${1:?usage: scripts/update-domains.sh TRANCO_LIST_ID}"
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary_dir="$(mktemp -d)"
trap 'rm -rf "$temporary_dir"' EXIT

curl --fail --location --silent --show-error \
  "https://tranco-list.eu/download/${list_id}/1000" \
  -o "${temporary_dir}/tranco.csv"

LC_ALL=C awk -F, '
function invalid(name, labels, count, index) {
  if (name !~ /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/) {
    return "malformed label"
  }
  if (length(name) > 253) {
    return "name exceeds 253 bytes"
  }
  count = split(name, labels, "\\.")
  for (index = 1; index <= count; index++) {
    if (length(labels[index]) > 63) {
      return "label exceeds 63 bytes"
    }
  }
  return ""
}

NF >= 2 {
  name = tolower($2)
  sub(/\.$/, "", name)
  if (!name) {
    next
  }
  reason = invalid(name)
  if (reason) {
    printf "invalid Tranco domain on CSV line %d (%s): %s\n", NR, name, reason > "/dev/stderr"
    exit 1
  }
  if (!seen[name]++) {
    print name
  }
}
' "${temporary_dir}/tranco.csv" > "${temporary_dir}/domains.txt"

entry_count="$(wc -l < "${temporary_dir}/domains.txt" | tr -d ' ')"
if [[ "${entry_count}" != 1000 ]]; then
  echo "expected 1000 unique domains, got ${entry_count}" >&2
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

corpus_sha256="$(sha256_file "${temporary_dir}/domains.txt")"
if [[ ! "${corpus_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
  echo "failed to calculate a SHA-256 checksum for the normalized corpus" >&2
  exit 1
fi

cp "${temporary_dir}/domains.txt" "${root_dir}/data/domains.txt"
retrieved_at="$(date -u +%F)"
cat > "${root_dir}/data/domains.meta.json" <<EOF
{
  "source": "Tranco daily list",
  "list_id": "${list_id}",
  "retrieved_at": "${retrieved_at}",
  "download_url": "https://tranco-list.eu/download/${list_id}/1000",
  "entries": 1000,
  "sha256": "${corpus_sha256}",
  "license_note": "Tranco aggregates providers with their own attribution and license terms; retain this metadata when redistributing the snapshot."
}
EOF

echo "updated data/domains.txt from Tranco list ${list_id} (sha256 ${corpus_sha256})"
