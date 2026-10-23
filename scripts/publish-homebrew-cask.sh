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
# The version derived from the tag is compared with the tap's below, so it gets
# the same strict shape scripts/homebrew-cask.sh enforces (see the reasons there).
valid_release_tag() {
	local LC_ALL=C
	[[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]
}
if ! valid_release_tag "${release_tag}"; then
	echo "release tag must match vMAJOR.MINOR.PATCH[-PRERELEASE]: ${release_tag}" >&2
	exit 2
fi
if [[ ! -f "${cask_file}" ]]; then
	echo "cask file does not exist: ${cask_file}" >&2
	exit 1
fi
if grep -Fq 'verified:' "${cask_file}"; then
	echo "cask contains deprecated Homebrew verified: parameter; refusing to publish" >&2
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
# Read the sha and the content in one request, so the version checked below
# belongs to exactly the blob the PUT replaces: the PUT carries this sha, and
# GitHub rejects it if the cask changed in between. A failed read counts as no
# cask yet (first publication). That cannot slip a downgrade past the check:
# without a sha the PUT can only create the file, and GitHub refuses it when
# one already exists.
current_sha=""
current_version=""
current_found=false
if current_blob="$(GH_TOKEN="${HOMEBREW_TAP_TOKEN}" gh api "repos/${repository}/contents/${path}?ref=${tap_branch}" --jq '.sha, .content' 2>/dev/null)"; then
	current_found=true
	current_sha="$(printf '%s\n' "${current_blob}" | sed -n 1p)"
	current_cask="$(printf '%s\n' "${current_blob}" | sed 1d | tr -d '\n' | base64 --decode)"
	# awk reads to the end rather than exiting at the first match: under
	# pipefail, an early exit could fail printf with SIGPIPE on a large cask.
	current_version="$(printf '%s\n' "${current_cask}" |
		awk -F'"' '!found && /^[[:space:]]*version "[^"]*"[[:space:]]*$/ { print $2; found = 1 }')"
fi

# Homebrew upgrades whenever the tap's version differs from the installed one,
# so publishing an older release here would move every `brew upgrade` user
# backwards. Refuse unless the maintainer asked for it explicitly. sort -V is
# a sound order because both sides are stable versions: the tap only ever
# holds one, and validate-published-release.sh refuses prereleases. (It would
# rank 1.0.0 below 1.0.0-rc.1.)
new_version="${release_tag#v}"
downgrade_allowed() {
	[[ "${ALLOW_DOWNGRADE:-0}" == 1 ]]
}
if [[ "${current_found}" != true ]]; then
	echo "no readable ${path} in ${repository}; publishing ${new_version} as the first cask"
elif [[ -z "${current_version}" ]]; then
	if ! downgrade_allowed; then
		echo "${repository}/${path} declares no version, so a downgrade cannot be ruled out;" \
			"refusing to replace it without ALLOW_DOWNGRADE=1" >&2
		exit 1
	fi
	echo "ALLOW_DOWNGRADE=1: replacing ${path}, which declares no version, with ${new_version}" >&2
else
	lowest_version="$(printf '%s\n' "${current_version}" "${new_version}" | sort -V | sed -n 1p)"
	if [[ "${new_version}" != "${current_version}" && "${lowest_version}" == "${new_version}" ]]; then
		if ! downgrade_allowed; then
			echo "refusing to downgrade ${repository}/${path} from ${current_version} to ${new_version};" \
				"set ALLOW_DOWNGRADE=1 (the allow_downgrade workflow input) to publish an older release" >&2
			exit 1
		fi
		echo "ALLOW_DOWNGRADE=1: downgrading ${path} from ${current_version} to ${new_version}" >&2
	fi
	echo "${repository}/${path} holds ${current_version}; publishing ${new_version}"
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
