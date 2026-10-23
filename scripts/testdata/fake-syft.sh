#!/usr/bin/env bash
set -euo pipefail

# A stand-in for syft that scripts/release-fixture.sh puts on PATH. It varies
# the two fields a real SPDX document changes between scans of one file -- a
# random document namespace and the wall-clock creation time -- and records
# the arguments and SYFT_ settings it ran with, so the fixture can check that
# scripts/reproducible-syft.sh normalizes the first and keeps Syft offline.
document=""
for argument in "$@"; do
	if [[ "${argument}" == spdx-json=* ]]; then
		document="${argument#spdx-json=}"
	fi
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
arguments="$(printf '%s\n' "$@" | jq -R . | jq -s .)"
jq -n \
	--arg name "${name}" \
	--argjson arguments "${arguments}" \
	--arg namespace "https://anchore.com/syft/file/${name}-${scan}" \
	--arg created "${scan}" \
	'{
		spdxVersion: "SPDX-2.3",
		name: $name,
		documentNamespace: $namespace,
		creationInfo: {created: $created, creators: ["Tool: fake-syft"]},
		fixture: {
			arguments: $arguments,
			settings: ($ENV | with_entries(select(.key | startswith("SYFT_"))))
		}
	}' >"${document}"
