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

awk -F, 'NF >= 2 { print tolower($2) }' "${temporary_dir}/tranco.csv" \
  | sed 's/\.$//' \
  | awk 'NF && !seen[$0]++' \
  > "${temporary_dir}/domains.txt"

entry_count="$(wc -l < "${temporary_dir}/domains.txt" | tr -d ' ')"
if [[ "${entry_count}" != 1000 ]]; then
  echo "expected 1000 unique domains, got ${entry_count}" >&2
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
  "license_note": "Tranco aggregates providers with their own attribution and license terms; retain this metadata when redistributing the snapshot."
}
EOF

echo "updated data/domains.txt from Tranco list ${list_id}"
