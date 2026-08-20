#!/usr/bin/env bash
set -euo pipefail

# GoReleaser runs the SBOM command from dist/. Syft's SPDX JSON contains a
# wall-clock creation time and a random document namespace, so normalize those
# fields after Syft scans the deterministic release archive. This keeps the
# SBOM itself, and therefore checksums.txt, reproducible between identical
# release builds.

document=""
for argument in "$@"; do
	if [[ "${argument}" == *spdx-json=* ]]; then
		document="${argument#*spdx-json=}"
	fi
done

if [[ -z "${document}" ]]; then
	echo "Syft output must include an spdx-json document path" >&2
	exit 2
fi

syft "$@"

source_date_epoch="${SOURCE_DATE_EPOCH:-}"
if [[ -z "${source_date_epoch}" ]]; then
	source_date_epoch="$(git show -s --format=%ct HEAD)"
fi

python3 - "${document}" "${source_date_epoch}" <<'PY'
import json
import sys
import uuid
from datetime import datetime, timezone

document_path = sys.argv[1]
source_date_epoch = int(sys.argv[2])

with open(document_path, encoding="utf-8") as stream:
    document = json.load(stream)

name = document.get("name")
if not isinstance(name, str) or not name:
    raise SystemExit("Syft SPDX document has no deterministic name")

namespace_seed = f"https://github.com/crypt0rr/SpeeDNS/sbom/{name}"
namespace_id = uuid.uuid5(uuid.NAMESPACE_URL, namespace_seed)
document["documentNamespace"] = (
    f"https://anchore.com/syft/file/{name}-{namespace_id}"
)

creation_info = document.setdefault("creationInfo", {})
creation_info["created"] = datetime.fromtimestamp(
    source_date_epoch, timezone.utc
).strftime("%Y-%m-%dT%H:%M:%SZ")

with open(document_path, "w", encoding="utf-8") as stream:
    json.dump(document, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    stream.write("\n")
PY

printf 'normalized reproducible SBOM: %s\n' "${document}"
