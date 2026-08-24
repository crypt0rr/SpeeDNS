#!/usr/bin/env bash
set -euo pipefail

state_file="${FAKE_GH_RELEASE_STATE:?FAKE_GH_RELEASE_STATE is required}"
log_file="${FAKE_GH_RELEASE_LOG:?FAKE_GH_RELEASE_LOG is required}"
command_name="${1:-}"
action="${2:-}"
# Two callers ask different questions of the same fake: ensure-release.sh reads
# isDraft alone, validate-published-release.sh reads isDraft and isPrerelease.
# Answer whichever was asked rather than guessing, so neither caller has to
# tolerate a field it did not request.
wants_prerelease=false
for argument in "$@"; do
	case "${argument}" in
	*isPrerelease*) wants_prerelease=true ;;
	esac
done

printf '%s %s\n' "${command_name}" "${action}" >>"${log_file}"

if [[ "${command_name}" != release ]]; then
	echo "unsupported fake gh command: ${command_name}" >&2
	exit 2
fi

case "${action}" in
	view)
		case "$(<"${state_file}")" in
			missing) exit 1 ;;
			draft) draft=true; prerelease=false ;;
			published) draft=false; prerelease=false ;;
			prerelease) draft=false; prerelease=true ;;
			*) echo "invalid fake release state" >&2; exit 2 ;;
		esac
		if [[ "${wants_prerelease}" == true ]]; then
			printf '%s\n%s\n' "${draft}" "${prerelease}"
		else
			printf '%s\n' "${draft}"
		fi
		;;
	create)
		case "$(<"${state_file}")" in
			missing)
				printf 'draft\n' >"${state_file}"
				printf 'https://example.test/release\n'
				;;
			draft|published)
				echo 'release already exists' >&2
				exit 1
				;;
			*) echo "invalid fake release state" >&2; exit 2 ;;
		esac
		;;
	*)
		echo "unsupported fake gh release action: ${action}" >&2
		exit 2
		;;
esac
