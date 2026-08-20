#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: $0 BINARY" >&2
	exit 2
fi

# GoReleaser invokes this hook after each cross-build. Use a portable touch
# timestamp and UTC so archive member metadata is identical on every runner.
TZ=UTC touch -t 200801020304.05 "$1"
