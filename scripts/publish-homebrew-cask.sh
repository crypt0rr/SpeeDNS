#!/usr/bin/env bash
set -euo pipefail

usage() {
	echo "usage: $0 CASK-FILE RELEASE-TAG [REPOSITORY] [PATH]" >&2
}

cask_file="${1:-}"
release_tag="${2:-}"
repository="${3:-crypt0rr/homebrew-speedns}"
path="${4:-Casks/speedns.rb}"
if [[ -z "${cask_file}" || -z "${release_tag}" ]]; then
	usage
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
