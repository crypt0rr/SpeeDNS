#!/usr/bin/env bash
set -euo pipefail

state_file="${FAKE_GH_RELEASE_STATE:?FAKE_GH_RELEASE_STATE is required}"
log_file="${FAKE_GH_RELEASE_LOG:?FAKE_GH_RELEASE_LOG is required}"
command_name="${1:-}"
action="${2:-}"

printf '%s %s\n' "${command_name}" "${action}" >>"${log_file}"

if [[ "${command_name}" != release ]]; then
	echo "unsupported fake gh command: ${command_name}" >&2
	exit 2
fi

case "${action}" in
	view)
		case "$(<"${state_file}")" in
			missing) exit 1 ;;
			draft) printf 'true\n' ;;
			published) printf 'false\n' ;;
			*) echo "invalid fake release state" >&2; exit 2 ;;
		esac
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
