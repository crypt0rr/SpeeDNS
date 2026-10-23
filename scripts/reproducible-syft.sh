#!/usr/bin/env bash
set -euo pipefail

# GoReleaser runs the SBOM command from dist/. Syft's SPDX JSON contains a
# wall-clock creation time and a random document namespace, so normalize those
# fields after Syft scans the deterministic release archive. This keeps the
# SBOM itself, and therefore checksums.txt, reproducible between identical
# release builds.

document=""
for argument in "$@"; do
	case "${argument}" in
	--enrich | --enrich=*)
		echo "reproducible-syft.sh keeps Syft offline; remove ${argument} from the SBOM arguments" >&2
		exit 2
		;;
	esac
	if [[ "${argument}" == *spdx-json=* ]]; then
		document="${argument#*spdx-json=}"
	fi
done

if [[ -z "${document}" ]]; then
	echo "Syft output must include an spdx-json document path" >&2
	exit 2
fi

# The release compares two builds of one commit, made on different runners,
# byte for byte, SBOMs included. Syft's online enrichment (--enrich) fetches
# module licenses from the Go proxy, so a lookup that succeeds in one build
# and times out in the other, or a tag the proxy has not fetched yet, fails
# that comparison for a reason that has nothing to do with the artifacts.
# Licenses come from the local module cache instead, which the build itself
# has just filled with every module linked into the binary, and never from
# the network. Syft's update check is network traffic too, and adds nothing
# to an SBOM.
#
# Each variable is the environment form Syft reads a configuration key from:
# SYFT_, then the key upper-cased with . and - as _. The keys are
#   golang.search-local-mod-cache-licenses
#   golang.local-mod-cache-dir
#   golang.search-remote-licenses
#   check-for-app-update
# Syft ignores a name it does not know, so a future rename would not make the
# SBOMs nondeterministic: remote lookups stay off without --enrich, and only
# the licenses would go missing.
#
# GoReleaser runs this command with HOME, USER, TMPDIR, PATH and a few others
# only, so go env resolves the cache from HOME and Go's env file. A GOMODCACHE
# or GOPATH set only in a job's environment would not reach it, and the
# licenses would go missing in the same way, from both builds alike.
module_cache="$(go env GOMODCACHE)"
SYFT_CHECK_FOR_APP_UPDATE=false \
	SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES=true \
	SYFT_GOLANG_LOCAL_MOD_CACHE_DIR="${module_cache}" \
	SYFT_GOLANG_SEARCH_REMOTE_LICENSES=false \
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
