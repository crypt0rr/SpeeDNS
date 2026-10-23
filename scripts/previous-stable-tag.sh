#!/usr/bin/env bash
set -euo pipefail

usage() {
	echo "usage: git tag --list 'v*' | $0 RELEASE-TAG" >&2
}

# Prints the stable tag a stable release's notes are measured from: the
# highest stable tag that sorts strictly below RELEASE-TAG. Candidate tags are
# read one per line on standard input; nothing is printed when there is none.
#
# "Highest stable tag other than this one" is not the same thing once a
# maintenance branch exists. Releasing v0.5.3 after v0.6.1 would otherwise
# compare against v0.6.1, and the notes would cover v0.6.1..v0.5.3 -- a range
# that has nothing to do with the backport being published.
release_tag="${1:-}"
if [[ -z "${release_tag}" ]]; then
	usage
	exit 2
fi
# The C locale keeps [0-9] to the ASCII digits; see scripts/homebrew-cask.sh.
stable_tag() {
	local LC_ALL=C
	[[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
}
# Prereleases keep GoReleaser's default range, and sort -V orders v1.0.0 below
# v1.0.0-rc.1, so it cannot rank them here. Refuse rather than guess.
if ! stable_tag "${release_tag}"; then
	echo "release tag must be a stable vMAJOR.MINOR.PATCH tag: ${release_tag}" >&2
	exit 2
fi

lower_stable_tags() {
	local candidate lowest
	# The second test keeps a final line that has no trailing newline.
	while IFS= read -r candidate || [[ -n "${candidate}" ]]; do
		# A regex rather than `grep -v -- '-'`, whose argument handling differs
		# between grep implementations. It also drops anything that is not a
		# release tag at all, which sort -V would otherwise rank somewhere.
		if ! stable_tag "${candidate}" || [[ "${candidate}" == "${release_tag}" ]]; then
			continue
		fi
		lowest="$(printf '%s\n' "${candidate}" "${release_tag}" | sort -V | sed -n 1p)"
		if [[ "${lowest}" == "${candidate}" ]]; then
			printf '%s\n' "${candidate}"
		fi
	done
}

lower_stable_tags | sort -V | tail -n 1
