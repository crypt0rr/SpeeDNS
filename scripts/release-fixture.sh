#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/speedns-release-fixture.XXXXXX")"
trap 'rm -rf -- "${fixture_dir}"' EXIT

make_dist() {
	local destination="$1"
	local version="$2"
	mkdir -p "${destination}"
	for artifact in \
		"SpeeDNS_${version}_darwin_amd64.tar.gz" \
		"SpeeDNS_${version}_darwin_arm64.tar.gz" \
		"SpeeDNS_${version}_linux_amd64.tar.gz" \
		"SpeeDNS_${version}_linux_arm64.tar.gz" \
		"speedns_${version}_linux_amd64.deb" \
		"speedns_${version}_linux_arm64.deb" \
		"speedns_${version}_linux_amd64.rpm" \
		"speedns_${version}_linux_arm64.rpm" \
		"speedns_${version}_linux_amd64.apk" \
		"speedns_${version}_linux_arm64.apk" \
		"speedns_${version}_linux_amd64.pkg.tar.zst" \
		"speedns_${version}_linux_arm64.pkg.tar.zst" \
		"SpeeDNS_${version}_linux_amd64.tar.gz.sbom.json" \
		"speedns_${version}_linux_amd64.rpm.sbom.json"; do
		printf 'fixture %s\n' "${artifact}" >"${destination}/${artifact}"
	done
	(
		cd "${destination}"
		sha256sum \
			"SpeeDNS_${version}_darwin_amd64.tar.gz" \
			"SpeeDNS_${version}_darwin_arm64.tar.gz" \
			"SpeeDNS_${version}_linux_amd64.tar.gz" \
			"SpeeDNS_${version}_linux_arm64.tar.gz" \
			"speedns_${version}_linux_amd64.deb" \
			"speedns_${version}_linux_arm64.deb" \
			"speedns_${version}_linux_amd64.rpm" \
			"speedns_${version}_linux_arm64.rpm" \
			"speedns_${version}_linux_amd64.apk" \
			"speedns_${version}_linux_arm64.apk" \
			"speedns_${version}_linux_amd64.pkg.tar.zst" \
			"speedns_${version}_linux_arm64.pkg.tar.zst" \
			"SpeeDNS_${version}_linux_amd64.tar.gz.sbom.json" \
			"speedns_${version}_linux_amd64.rpm.sbom.json" \
			>checksums.txt
	)
	jq -n \
		--arg version "${version}" \
		'[{type:"Archive", path:("dist/SpeeDNS_"+$version+"_darwin_amd64.tar.gz")}, {type:"Archive", path:("dist/SpeeDNS_"+$version+"_darwin_arm64.tar.gz")}, {type:"Archive", path:("dist/SpeeDNS_"+$version+"_linux_amd64.tar.gz")}, {type:"Archive", path:("dist/SpeeDNS_"+$version+"_linux_arm64.tar.gz")}, {type:"Linux Package", path:("dist/speedns_"+$version+"_linux_amd64.deb")}, {type:"Linux Package", path:("dist/speedns_"+$version+"_linux_arm64.deb")}, {type:"Linux Package", path:("dist/speedns_"+$version+"_linux_amd64.rpm")}, {type:"Linux Package", path:("dist/speedns_"+$version+"_linux_arm64.rpm")}, {type:"Linux Package", path:("dist/speedns_"+$version+"_linux_amd64.apk")}, {type:"Linux Package", path:("dist/speedns_"+$version+"_linux_arm64.apk")}, {type:"Linux Package", path:("dist/speedns_"+$version+"_linux_amd64.pkg.tar.zst")}, {type:"Linux Package", path:("dist/speedns_"+$version+"_linux_arm64.pkg.tar.zst")}, {type:"SBOM", path:("dist/SpeeDNS_"+$version+"_linux_amd64.tar.gz.sbom.json")}, {type:"SBOM", path:("dist/speedns_"+$version+"_linux_amd64.rpm.sbom.json")}, {type:"Checksum", path:"dist/checksums.txt"}]' >"${destination}/artifacts.json"
}

version="0.1.0-fixture"
make_dist "${fixture_dir}/first" "${version}"
make_dist "${fixture_dir}/second" "${version}"

fake_bin="${fixture_dir}/fake-bin"
mkdir -p "${fake_bin}"
ln -s "${root_dir}/scripts/testdata/fake-gh-release.sh" "${fake_bin}/gh"
release_state="${fixture_dir}/release-state"
release_log="${fixture_dir}/release-log"
printf '%s\n' missing >"${release_state}"
: >"${release_log}"
PATH="${fake_bin}:${PATH}" \
	FAKE_GH_RELEASE_STATE="${release_state}" \
	FAKE_GH_RELEASE_LOG="${release_log}" \
	bash "${root_dir}/scripts/ensure-release.sh" "v${version}"
grep -Fqx 'release view' "${release_log}"
grep -Fqx 'release create' "${release_log}"

PATH="${fake_bin}:${PATH}" \
	FAKE_GH_RELEASE_STATE="${release_state}" \
	FAKE_GH_RELEASE_LOG="${release_log}" \
	bash "${root_dir}/scripts/ensure-release.sh" "v${version}"
if [[ "$(grep -Fc 'release create' "${release_log}")" -ne 1 ]]; then
	echo "draft release was recreated during retry" >&2
	exit 1
fi

printf '%s\n' published >"${release_state}"
if PATH="${fake_bin}:${PATH}" \
	FAKE_GH_RELEASE_STATE="${release_state}" \
	FAKE_GH_RELEASE_LOG="${release_log}" \
	bash "${root_dir}/scripts/ensure-release.sh" "v${version}"; then
	echo "published release was unexpectedly accepted" >&2
	exit 1
fi

validate_bin="${fixture_dir}/validate-bin"
mkdir -p "${validate_bin}"
fake_state="${fixture_dir}/validate-release-state"
fake_gh="${validate_bin}/gh"
# shellcheck disable=SC2016 # These strings are source for the temporary fake CLI.
printf '%s\n' '#!/usr/bin/env bash' \
	'set -euo pipefail' \
	'if [[ "${1:-}" != release || "${2:-}" != view ]]; then exit 2; fi' \
	'wants=false; for a in "$@"; do case "$a" in *isPrerelease*) wants=true ;; esac; done' \
	'case "$(<"${FAKE_RELEASE_STATE}")" in' \
	'published) d=false; p=false ;;' \
	'draft) d=true; p=false ;;' \
	'prerelease) d=false; p=true ;;' \
	'*) exit 1 ;;' \
	'esac' \
	'if [[ "$wants" == true ]]; then printf "%s\\n%s\\n" "$d" "$p"; else printf "%s\\n" "$d"; fi' >"${fake_gh}"
chmod +x "${fake_gh}"
printf '%s\n' published >"${fake_state}"
PATH="${validate_bin}:${PATH}" \
	GH_TOKEN=fixture-token \
	FAKE_RELEASE_STATE="${fake_state}" \
	bash "${root_dir}/scripts/validate-published-release.sh" "v${version}" "example/repository"
printf '%s\n' draft >"${fake_state}"
if PATH="${validate_bin}:${PATH}" \
	GH_TOKEN=fixture-token \
	FAKE_RELEASE_STATE="${fake_state}" \
	bash "${root_dir}/scripts/validate-published-release.sh" "v${version}" "example/repository"; then
	echo "draft release was unexpectedly accepted" >&2
	exit 1
fi
printf '%s\n' missing >"${fake_state}"
if PATH="${validate_bin}:${PATH}" \
	GH_TOKEN=fixture-token \
	FAKE_RELEASE_STATE="${fake_state}" \
	bash "${root_dir}/scripts/validate-published-release.sh" "v${version}" "example/repository"; then
	echo "missing release was unexpectedly accepted" >&2
	exit 1
fi
# A prerelease must be refused: the Homebrew workflow fires on every published
# release, so accepting one would point the stable cask at a release candidate.
printf '%s\n' prerelease >"${fake_state}"
if PATH="${validate_bin}:${PATH}" \
	GH_TOKEN=fixture-token \
	FAKE_RELEASE_STATE="${fake_state}" \
	bash "${root_dir}/scripts/validate-published-release.sh" "v${version}" "example/repository"; then
	echo "prerelease was unexpectedly accepted for the Homebrew cask" >&2
	exit 1
fi

bash "${root_dir}/scripts/release-assets.sh" verify "${fixture_dir}/first" \
	"${fixture_dir}/first/release-assets.txt"
bash "${root_dir}/scripts/homebrew-cask.sh" "v${version}" "${fixture_dir}/first" \
	"${fixture_dir}/first/speedns.rb"
bash "${root_dir}/scripts/compare-release-artifacts.sh" \
	"${fixture_dir}/first" "${fixture_dir}/second"

grep -Fq 'version "0.1.0-fixture"' "${fixture_dir}/first/speedns.rb"
grep -Fq 'github.com/crypt0rr/SpeeDNS/releases/download' "${fixture_dir}/first/speedns.rb"
if grep -Fq 'license "' "${fixture_dir}/first/speedns.rb"; then
	echo "generated Homebrew cask contains unsupported license stanza" >&2
	exit 1
fi

cask_file="${fixture_dir}/first/speedns.rb"

# Homebrew's cask style requires on_arm before on_intel, so the four blocks are
# not emitted in the order the checksums are read. A mis-paired checksum would
# hand one platform another archive's digest, and brew would refuse to install
# on exactly that platform while every other one kept working.
pairs_checked=0
while read -r checksum platform; do
	expected="$(awk -v target="SpeeDNS_${version}_${platform}.tar.gz" \
		'$2 == target { print $1; exit }' "${fixture_dir}/first/checksums.txt")"
	if [[ "${checksum}" != "${expected}" ]]; then
		echo "cask pairs ${platform} with the wrong checksum" >&2
		exit 1
	fi
	pairs_checked=$((pairs_checked + 1))
done < <(awk '
	/^ *sha256 "/ { split($0, parts, "\""); pending = parts[2]; next }
	/^ *url "/ && pending != "" {
		match($0, /SpeeDNS_#\{version\}_[a-z0-9_]+\.tar\.gz/)
		asset = substr($0, RSTART, RLENGTH)
		sub(/^SpeeDNS_#\{version\}_/, "", asset)
		sub(/\.tar\.gz$/, "", asset)
		print pending, asset
		pending = ""
	}
' "${cask_file}")
# Without this the loop above passes vacuously when the cask stops matching the
# awk patterns at all.
if [[ "${pairs_checked}" -ne 4 ]]; then
	echo "expected 4 checksum/platform pairs in the cask, found ${pairs_checked}" >&2
	exit 1
fi

# The remaining checks encode what `brew style` enforces, so a regression is
# caught here rather than after the cask is already published. Homebrew is far
# too heavy to install in CI, so the rules are asserted directly.
stanza_order="$(grep -oE 'on_(macos|linux|arm|intel) do' "${cask_file}" | tr '\n' ' ')"
if [[ "${stanza_order}" != "on_macos do on_arm do on_intel do on_linux do on_arm do on_intel do " ]]; then
	echo "cask stanzas are out of the order brew style requires: ${stanza_order}" >&2
	exit 1
fi
# A continuation argument aligns under the first argument of the call it
# continues, which puts `verified:` at the column where the url string starts.
if [[ "$(grep -cE '^ {10}verified: "' "${cask_file}")" -ne 4 ]]; then
	echo "cask verified: lines are not aligned under the url argument" >&2
	exit 1
fi
# Stanzas within one group take no blank line between them, and a block body
# does not end on one.
if awk '/^  on_linux do$/ && previous == "" { found = 1 } { previous = $0 } END { exit !found }' "${cask_file}"; then
	echo "cask has a blank line between the on_macos and on_linux stanzas" >&2
	exit 1
fi
if awk '/^end$/ && previous == "" { found = 1 } { previous = $0 } END { exit !found }' "${cask_file}"; then
	echo "cask has a blank line before the closing end" >&2
	exit 1
fi

printf 'changed\n' >>"${fixture_dir}/second/SpeeDNS_${version}_linux_amd64.tar.gz"
if bash "${root_dir}/scripts/compare-release-artifacts.sh" \
	"${fixture_dir}/first" "${fixture_dir}/second"; then
	echo "expected reproducibility mismatch was not detected" >&2
	exit 1
fi

echo "release script fixture passed"
