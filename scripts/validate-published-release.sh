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

# isPrerelease is read alongside isDraft because the Homebrew workflow triggers
# on `release: published` for EVERY release. Without this, publishing a release
# candidate overwrites the stable cask and hands a prerelease to every
# `brew upgrade` user. This project has shipped -rc tags before, so the case is
# real rather than theoretical.
if ! release_status="$(gh release view "${release_tag}" \
	--repo "${repository}" \
	--json isDraft,isPrerelease \
	--jq '.isDraft, .isPrerelease')"; then
	echo "could not inspect GitHub release ${release_tag} in ${repository}" >&2
	exit 1
fi
release_draft="$(printf '%s\n' "${release_status}" | sed -n 1p)"
release_prerelease="$(printf '%s\n' "${release_status}" | sed -n 2p)"

case "${release_draft}" in
false) ;;
true)
	echo "release ${release_tag} is still a draft; publish it before updating Homebrew" >&2
	exit 1
	;;
*)
	echo "unexpected draft status for release ${release_tag}: ${release_draft}" >&2
	exit 1
	;;
esac

case "${release_prerelease}" in
false)
	echo "release ${release_tag} is published"
	;;
true)
	echo "release ${release_tag} is a prerelease; Homebrew serves the stable cask and must not be pointed at it" >&2
	exit 1
	;;
*)
	echo "unexpected prerelease status for release ${release_tag}: ${release_prerelease}" >&2
	exit 1
	;;
esac
