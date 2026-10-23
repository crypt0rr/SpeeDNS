#!/usr/bin/env bash
set -euo pipefail

# A stand-in for syft that scripts/release-fixture.sh puts on PATH. It varies
# the two fields a real SPDX document changes between scans of one file -- a
# random document namespace and the wall-clock creation time -- and records
# its arguments, what each file named with --config held, and the SYFT_
# settings it ran with, so the fixture can check that
# scripts/reproducible-syft.sh normalizes the first and keeps Syft offline.
document=""
arguments=()
configs=()
config_follows=false
for argument in "$@"; do
	if [[ "${config_follows}" == true ]]; then
		configs+=("${argument}")
		config_follows=false
		continue
	fi
	case "${argument}" in
	--config | -c)
		config_follows=true
		continue
		;;
	--config=*)
		configs+=("${argument#--config=}")
		continue
		;;
	spdx-json=*)
		document="${argument#spdx-json=}"
		;;
	esac
	arguments+=("${argument}")
done
if [[ -z "${document}" ]]; then
	echo "fake syft: no spdx-json output requested" >&2
	exit 2
fi

# The process ID differs between two runs; RANDOM covers a reused one.
scan="$$-${RANDOM}${RANDOM}"
name="$(basename "${1:?fake syft: no scan target}")"
# One JSON string per argument, passed as data: jq would read an argument such
# as --output as one of its own options.
arguments_json="$(printf '%s\n' "${arguments[@]}" | jq -R . | jq -s .)"
# What each named configuration file held while the scan ran, or null for a
# file that did not exist. Not the path: the wrapper's is a new temporary file
# on every run, and the fixture compares two scans byte for byte.
configs_json="$(
	for config in ${configs[@]+"${configs[@]}"}; do
		if [[ -f "${config}" ]]; then
			jq -n --rawfile content "${config}" '$content'
		else
			jq -n 'null'
		fi
	done | jq -s .
)"
jq -n \
	--arg name "${name}" \
	--argjson arguments "${arguments_json}" \
	--argjson configs "${configs_json}" \
	--arg namespace "https://anchore.com/syft/file/${name}-${scan}" \
	--arg created "${scan}" \
	'{
		spdxVersion: "SPDX-2.3",
		name: $name,
		documentNamespace: $namespace,
		creationInfo: {created: $created, creators: ["Tool: fake-syft"]},
		fixture: {
			arguments: $arguments,
			configs: $configs,
			settings: ($ENV | with_entries(select(.key | startswith("SYFT_"))))
		}
	}' >"${document}"
