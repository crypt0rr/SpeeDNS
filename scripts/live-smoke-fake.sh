#!/usr/bin/env bash
set -euo pipefail

output=""
while (($#)); do
	case "$1" in
		--output)
			output="$2"
			shift 2
			;;
		*) shift ;;
	esac
done

case "${SPEEDNS_FAKE_MODE:-pass}" in
	pass) ;;
	transient)
		state="${SPEEDNS_FAKE_STATE:?SPEEDNS_FAKE_STATE is required}"
		if [[ -e "${state}" ]]; then
			rm "${state}"
		else
			: >"${state}"
			exit 7
		fi
		;;
	fail) exit 7 ;;
	*) echo "unknown fake mode" >&2; exit 2 ;;
esac

printf '{}\n' >"${output}"
