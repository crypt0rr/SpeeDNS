#!/usr/bin/env bash
set -euo pipefail

# GoReleaser runs the SBOM command from dist/. Syft's SPDX JSON contains a
# wall-clock creation time and a random document namespace, so normalize those
# fields after Syft scans the deterministic release archive. This keeps the
# SBOM itself, and therefore checksums.txt, reproducible between identical
# release builds.

# Syft merges every file named with --config into the one below, enrich:
# lists included. The short form -c takes its value attached too, and can end
# a cluster of the short flags that take no value, -h, -q and -v: Syft's flag
# parser reads a cluster one letter at a time until a letter whose flag takes
# a value, so -qc planted.yaml names planted.yaml. schema/workflows_test.go
# refuses the same arguments in .goreleaser.yaml, with this expression, which
# it checks is the one set here.
config_option='^(--config|-[hqv]*c)'

document=""
for argument in "$@"; do
	case "${argument}" in
	--enrich | --enrich=*)
		echo "reproducible-syft.sh keeps Syft offline; remove ${argument} from the SBOM arguments" >&2
		exit 2
		;;
	esac
	if [[ "${argument}" =~ ${config_option} ]]; then
		echo "reproducible-syft.sh names Syft's configuration file itself; remove ${argument} from the SBOM arguments" >&2
		exit 2
	fi
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
#
# Syft also reads configuration files. Unless one is named, it merges every
# one it finds: .syft.yaml and .syft/config.yaml in the working directory
# (dist/, under GoReleaser), ~/.syft.yaml, and syft/config.yaml in each XDG
# configuration directory, each name tried with every extension viper
# supports, .yml, .json and .toml among them, not only .yaml. The variables
# below outrank a file, but enrich: all in one would still turn on the
# network lookups no variable here turns off, Java's and JavaScript's among
# them. A file named with --config replaces that search, and the first
# --config replaces SYFT_CONFIG as well; a second would be merged in, so the
# loop above refuses one. The file is the wrapper's own and sets nothing, so
# every key keeps Syft's default unless a variable sets it, and it ends in
# .yaml because viper takes the format from the extension. This is how Syft
# v1.42.3, the release the pinned anchore/sbom-action/download-syft
# installs, loads its configuration through anchore/fangs and spf13/pflag,
# as their sources read at the versions it builds with; check it again when
# Renovate moves that pin to a new Syft.
syft_config_dir="$(mktemp -d "${TMPDIR:-/tmp}/speedns-syft.XXXXXX")"
trap 'rm -rf -- "${syft_config_dir}"' EXIT
syft_config="${syft_config_dir}/config.yaml"
printf '{}\n' >"${syft_config}"

module_cache="$(go env GOMODCACHE)"
SYFT_CHECK_FOR_APP_UPDATE=false \
	SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES=true \
	SYFT_GOLANG_LOCAL_MOD_CACHE_DIR="${module_cache}" \
	SYFT_GOLANG_SEARCH_REMOTE_LICENSES=false \
	syft "$@" --config "${syft_config}"

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
