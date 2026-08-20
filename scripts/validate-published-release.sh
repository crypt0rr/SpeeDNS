#!/usr/bin/env bash
set -euo pipefail

usage() {
	echo "usage: $0 RELEASE-TAG [REPOSITORY]" >&2
}

release_tag="${1:-}"
repository="${2:-${GITHUB_REPOSITORY:-crypt0rr/SpeeDNS}}"
if [[ -z "${release_tag}" || "${release_tag}" != v* ]]; then
	usage
	exit 2
fi
if ! command -v gh >/dev/null 2>&1; then
	echo "gh is required to inspect the published release" >&2
	exit 1
fi
: "${GH_TOKEN:?GH_TOKEN is required}"

if ! release_status="$(gh release view "${release_tag}" \
	--repo "${repository}" \
	--json isDraft \
	--jq '.isDraft')"; then
	echo "could not inspect GitHub release ${release_tag} in ${repository}" >&2
	exit 1
fi

case "${release_status}" in

false)
	echo "release ${release_tag} is published"
	;;
true)
	echo "release ${release_tag} is still a draft; publish it before updating Homebrew" >&2
	exit 1
	;;
*)
	echo "unexpected draft status for release ${release_tag}: ${release_status}" >&2
	exit 1
	;;
esac
