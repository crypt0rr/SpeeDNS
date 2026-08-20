#!/usr/bin/env bash
set -euo pipefail

usage() {
	echo "usage: $0 RELEASE-TAG [NOTES-FILE]" >&2
}

release_tag="${1:-}"
notes_file="${2:-}"
repository="${GITHUB_REPOSITORY:-crypt0rr/SpeeDNS}"

if [[ -z "${release_tag}" || "${release_tag}" != v* ]]; then
	usage
	exit 2
fi
if [[ -n "${notes_file}" && ! -f "${notes_file}" ]]; then
	echo "release notes file does not exist: ${notes_file}" >&2
	exit 2
fi

release_view() {
	gh release view "${release_tag}" \
		--repo "${repository}" \
		--json isDraft \
		--jq '.isDraft'
}

existing_status=""
if existing_status="$(release_view 2>/dev/null)"; then
	case "${existing_status}" in
		true)
			echo "reusing existing draft release ${release_tag}"
			exit 0
			;;
		false)
			echo "release ${release_tag} is already published; refusing to rebuild it" >&2
			exit 1
			;;
		*)
			echo "unexpected draft status for release ${release_tag}: ${existing_status}" >&2
			exit 1
			;;
	esac
fi

release_args=(
	release create "${release_tag}"
	--repo "${repository}"
	--verify-tag
	--draft
	--title "SpeeDNS ${release_tag}"
)
if [[ "${release_tag}" == *-* ]]; then
	release_args+=(--prerelease)
fi
if [[ -n "${notes_file}" ]]; then
	release_args+=(--notes-file "${notes_file}")
else
	release_args+=(--generate-notes)
fi

if gh "${release_args[@]}"; then
	echo "created draft release ${release_tag}"
	exit 0
fi

# A concurrent retry can create the release between the initial view and the
# create call. Re-check the state before failing so retries remain safe while
# a published release is still protected from accidental mutation.
if existing_status="$(release_view 2>/dev/null)" && [[ "${existing_status}" == true ]]; then
	echo "reusing existing draft release ${release_tag}"
	exit 0
fi

echo "could not create or reuse draft release ${release_tag}" >&2
exit 1
