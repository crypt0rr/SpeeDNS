#!/usr/bin/env bash
set -euo pipefail

usage() {
	echo "usage: $0 RELEASE-TAG [REPOSITORY]" >&2
}

release_tag="${1:-}"
repository="${2:-crypt0rr/homebrew-speedns}"
canonical_path="Casks/speedns.rb"
if [[ -z "${release_tag}" ]]; then
	usage
	exit 2
fi
if [[ "${release_tag}" != v* ]]; then
	echo "release tag must start with v: ${release_tag}" >&2
	exit 2
fi
: "${GH_TOKEN:?GH_TOKEN is required}"

version="${release_tag#v}"
tap_branch="$(gh api "repos/${repository}" --jq .default_branch)"
tree_paths="$(gh api "repos/${repository}/git/trees/${tap_branch}?recursive=1" \
	--jq '.tree[] | select(.type == "blob") | .path')"

if ! printf '%s\n' "${tree_paths}" | grep -Fqx -- "${canonical_path}"; then
	echo "${repository} does not contain ${canonical_path}" >&2
	echo "cask paths in the tap:" >&2
	printf '%s\n' "${tree_paths}" | grep -E '^Casks/' >&2 || true
	exit 1
fi

case_variant_paths="$(printf '%s\n' "${tree_paths}" | awk -v expected="${canonical_path}" \
	'tolower($0) == tolower(expected) && $0 != expected { print }')"
if [[ -n "${case_variant_paths}" ]]; then
	echo "case-variant SpeeDNS cask path exists in ${repository}:" >&2
	printf '%s\n' "${case_variant_paths}" >&2
	exit 1
fi

duplicate_paths="$(printf '%s\n' "${tree_paths}" | awk '
	NF {
		key = tolower($0)
		paths[key] = paths[key] (paths[key] ? "\n" : "") $0
		counts[key]++
	}
	END {
		for (key in counts) {
			if (counts[key] > 1) {
				print paths[key]
			}
		}
	}
')"
if [[ -n "${duplicate_paths}" ]]; then
	echo "case-insensitive duplicate paths exist in ${repository}:" >&2
	printf '%s\n' "${duplicate_paths}" >&2
	exit 1
fi

cask_content="$(gh api "repos/${repository}/contents/${canonical_path}?ref=${tap_branch}" \
	--jq .content | tr -d '\n' | base64 --decode)"
if ! printf '%s\n' "${cask_content}" | grep -Fqx -- 'cask "speedns" do'; then
	echo "${canonical_path} does not declare cask speedns" >&2
	exit 1
fi
if ! printf '%s\n' "${cask_content}" | grep -Fqx -- "  version \"${version}\""; then
	echo "${canonical_path} does not declare version ${version}" >&2
	exit 1
fi

echo "Homebrew tap validated: ${repository}/${canonical_path} (${release_tag})"
