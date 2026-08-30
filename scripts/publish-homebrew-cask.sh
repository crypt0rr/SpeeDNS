#!/usr/bin/env bash
set -euo pipefail

usage() {
	echo "usage: $0 CASK-FILE RELEASE-TAG [REPOSITORY] [PATH]" >&2
}

cask_file="${1:-}"
release_tag="${2:-}"
repository="${3:-crypt0rr/homebrew-speedns}"
canonical_path="Casks/speedns.rb"
path="${4:-${canonical_path}}"
if [[ -z "${cask_file}" || -z "${release_tag}" ]]; then
	usage
	exit 2
fi
if [[ "${path}" != "${canonical_path}" ]]; then
	echo "Homebrew cask publication path must be ${canonical_path}, got ${path}" >&2
	exit 2
fi
if [[ ! -f "${cask_file}" ]]; then
	echo "cask file does not exist: ${cask_file}" >&2
	exit 1
fi
: "${HOMEBREW_TAP_TOKEN:?HOMEBREW_TAP_TOKEN is required}"
if ! command -v gh >/dev/null 2>&1; then
	echo "gh is required to publish the Homebrew cask" >&2
	exit 1
fi

tap_branch="$(GH_TOKEN="${HOMEBREW_TAP_TOKEN}" gh api "repos/${repository}" --jq .default_branch)"
remote_paths="$(GH_TOKEN="${HOMEBREW_TAP_TOKEN}" gh api \
	"repos/${repository}/git/trees/${tap_branch}?recursive=1" \
	--jq '.tree[] | select(.type == "blob") | .path')"
case_variant_paths="$(printf '%s\n' "${remote_paths}" | awk -v expected="${canonical_path}" \
	'tolower($0) == tolower(expected) && $0 != expected { print }')"
if [[ -n "${case_variant_paths}" ]]; then
	echo "case-variant SpeeDNS cask path exists in ${repository}:" >&2
	printf '%s\n' "${case_variant_paths}" >&2
	echo "remove the legacy path before publishing ${canonical_path}" >&2
	exit 1
fi
current_sha=""
if current_sha="$(GH_TOKEN="${HOMEBREW_TAP_TOKEN}" gh api "repos/${repository}/contents/${path}?ref=${tap_branch}" --jq .sha 2>/dev/null)"; then
	:
fi

content="$(base64 <"${cask_file}" | tr -d '\n')"
api_args=(
	--method PUT
	--raw-field "message=Update SpeeDNS cask for ${release_tag}"
	--raw-field "content=${content}"
	--raw-field "branch=${tap_branch}"
)
if [[ -n "${current_sha}" ]]; then
	api_args+=(--raw-field "sha=${current_sha}")
fi

GH_TOKEN="${HOMEBREW_TAP_TOKEN}" gh api "repos/${repository}/contents/${path}" \
	"${api_args[@]}" \
	--jq '.commit.sha'

echo "published ${path} to ${repository}"
