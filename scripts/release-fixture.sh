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

# Crafted tags. homebrew-cask.sh prints the version into a Ruby double-quoted
# string, so each tag gets a checksums.txt that matches it exactly: the tag
# check is then the only thing left to refuse it, and it must do so before
# anything is written. The published-release check sees a release that exists
# and is stable, so it too can only refuse on the tag. Both run under a UTF-8
# locale, where bracket ranges follow collation order and [A-Za-z] would also
# match the é below unless the check pins the C locale. (Where en_US.UTF-8 is
# not installed, bash stays in C and that one case passes trivially.)
printf '%s\n' published >"${fake_state}"
# shellcheck disable=SC2016 # The backticks are the payload, not a command.
crafted_tags=('v1.0.0#{`id`}' 'v1.0.0";system("id");"' 'v1.0.0;id' 'v1.0.0-rc.1#{1}' 'v1.0' 'v1.0.0-é')
crafted_index=0
for crafted_tag in "${crafted_tags[@]}"; do
	crafted_dir="${fixture_dir}/crafted-${crafted_index}"
	crafted_index=$((crafted_index + 1))
	mkdir -p "${crafted_dir}"
	for platform in darwin_amd64 darwin_arm64 linux_amd64 linux_arm64; do
		printf '%064d  SpeeDNS_%s_%s.tar.gz\n' 0 "${crafted_tag#v}" "${platform}"
	done >"${crafted_dir}/checksums.txt"
	if LC_ALL=en_US.UTF-8 bash "${root_dir}/scripts/homebrew-cask.sh" "${crafted_tag}" "${crafted_dir}" \
		"${crafted_dir}/out/speedns.rb"; then
		echo "homebrew-cask.sh accepted crafted tag ${crafted_tag}" >&2
		exit 1
	fi
	if [[ -e "${crafted_dir}/out" ]]; then
		echo "homebrew-cask.sh wrote output before refusing crafted tag ${crafted_tag}" >&2
		exit 1
	fi
	if PATH="${validate_bin}:${PATH}" \
		GH_TOKEN=fixture-token \
		FAKE_RELEASE_STATE="${fake_state}" \
		LC_ALL=en_US.UTF-8 \
		bash "${root_dir}/scripts/validate-published-release.sh" "${crafted_tag}" "example/repository"; then
		echo "validate-published-release.sh accepted crafted tag ${crafted_tag}" >&2
		exit 1
	fi
done

# Release-notes base. A stable release is measured from the highest stable tag
# BELOW it, so a backport cut after a newer release (v0.5.3 after v0.6.1) does
# not inherit the newer release as its base. v0.10.0 checks that the order is
# by version rather than by text, and the non-release tags must be ignored.
tag_list="$(printf '%s\n' v0.1.0-rc.1 v0.1.0 v0.5.1 v0.5.2 v0.6.0 v0.6.1 v0.7.0-rc.1 v0.10.0 v1.0 latest)"
for case_spec in 'v0.5.3 v0.5.2' 'v0.6.2 v0.6.1' 'v0.6.1 v0.6.0' 'v0.7.0 v0.6.1' 'v0.11.0 v0.10.0' 'v0.1.0 none'; do
	read -r release expected <<<"${case_spec}"
	if [[ "${expected}" == none ]]; then
		expected=""
	fi
	actual="$(printf '%s\n' "${tag_list}" | bash "${root_dir}/scripts/previous-stable-tag.sh" "${release}")"
	if [[ "${actual}" != "${expected}" ]]; then
		echo "previous stable tag for ${release} is '${actual}', expected '${expected}'" >&2
		exit 1
	fi
done
# Prereleases keep GoReleaser's default range, and sort -V cannot rank them.
if printf '%s\n' "${tag_list}" | bash "${root_dir}/scripts/previous-stable-tag.sh" v0.7.0-rc.2; then
	echo "previous-stable-tag.sh accepted a prerelease tag" >&2
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
if grep -Fq 'verified:' "${fixture_dir}/first/speedns.rb"; then
	echo "generated Homebrew cask contains deprecated verified: parameter" >&2
	exit 1
fi
url_lines="$(grep -cE '^      url "[^"]+"$' "${fixture_dir}/first/speedns.rb")"
if [[ "${url_lines}" -ne 4 ]]; then
	echo "generated Homebrew cask has ${url_lines} direct URL stanzas, expected 4" >&2
	exit 1
fi

cask_file="${fixture_dir}/first/speedns.rb"

# Each arch block must carry the archive for the platform its ENCLOSING stanzas
# name. Checking only that a sha256 matches the asset named on the url line
# beside it is not enough: swapping two whole blocks keeps every sha/url pair
# self-consistent while serving, say, the Linux arm64 archive to Apple Silicon.
# Homebrew would verify that checksum happily, install it, and the binary would
# not run. So the platform is derived from the on_macos/on_linux and
# on_arm/on_intel stanzas the block sits inside, never from the url itself.
pairs_checked=0
while read -r checksum asset stanza_platform; do
	if [[ "${asset}" != "${stanza_platform}" ]]; then
		echo "cask serves the ${asset} archive under the ${stanza_platform} stanzas" >&2
		exit 1
	fi
	expected="$(awk -v target="SpeeDNS_${version}_${asset}.tar.gz" \
		'$2 == target { print $1; exit }' "${fixture_dir}/first/checksums.txt")"
	if [[ "${checksum}" != "${expected}" ]]; then
		echo "cask pairs ${asset} with the wrong checksum" >&2
		exit 1
	fi
	pairs_checked=$((pairs_checked + 1))
done < <(awk '
	/^  on_macos do$/ { operating_system = "darwin"; next }
	/^  on_linux do$/ { operating_system = "linux"; next }
	/^    on_arm do$/ { architecture = "arm64"; next }
	/^    on_intel do$/ { architecture = "amd64"; next }
	/^ *sha256 "/ { split($0, parts, "\""); pending = parts[2]; next }
	/^ *url "/ && pending != "" {
		match($0, /SpeeDNS_#\{version\}_[a-z0-9_]+\.tar\.gz/)
		asset = substr($0, RSTART, RLENGTH)
		sub(/^SpeeDNS_#\{version\}_/, "", asset)
		sub(/\.tar\.gz$/, "", asset)
		print pending, asset, operating_system "_" architecture
		pending = ""
	}
' "${cask_file}")
# Without this the loop above passes vacuously when the cask stops matching the
# awk patterns at all.
if [[ "${pairs_checked}" -ne 4 ]]; then
	echo "expected 4 checksum/platform pairs in the cask, found ${pairs_checked}" >&2
	exit 1
fi
# Four blocks that each match their own stanzas still leaves room for two of
# them to name the same platform, which would drop a platform silently.
distinct_platforms="$(grep -oE 'SpeeDNS_#\{version\}_[a-z0-9_]+\.tar\.gz' "${cask_file}" | sort -u | wc -l)"
if [[ "${distinct_platforms}" -ne 4 ]]; then
	echo "cask covers ${distinct_platforms} distinct platforms, expected 4" >&2
	exit 1
fi

# A cask is Ruby, and the generator emits it as text: an unbalanced quote or a
# dropped trailing comma produces a file every assertion here still passes and
# `brew install` cannot load. Both CI runners ship Ruby; skip loudly elsewhere.
if command -v ruby >/dev/null 2>&1; then
	if ! ruby -c "${cask_file}" >/dev/null 2>&1; then
		echo "generated Homebrew cask is not valid Ruby" >&2
		ruby -c "${cask_file}" >&2 || true
		exit 1
	fi
else
	echo "note: ruby is unavailable, skipping cask syntax check" >&2
fi

# The remaining checks encode what `brew style` enforces, so a regression is
# caught here rather than after the cask is already published. Homebrew is far
# too heavy to install in CI, so the rules are asserted directly.
stanza_order="$(grep -oE 'on_(macos|linux|arm|intel) do' "${cask_file}" | tr '\n' ' ')"
if [[ "${stanza_order}" != "on_macos do on_arm do on_intel do on_linux do on_arm do on_intel do " ]]; then
	echo "cask stanzas are out of the order brew style requires: ${stanza_order}" >&2
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

# SBOMs. The release compares two builds of one commit, made on different
# runners, byte for byte, so two scans of the same archive must yield the same
# SBOM: reproducible-syft.sh replaces the fields Syft varies on every scan,
# and runs Syft with its license lookup confined to the local module cache
# and with a configuration file of its own, which keeps Syft from loading any
# other. The caller's environment asks for the opposite; the wrapper must
# win. The fake syft records what it ran with.
syft_bin="${fixture_dir}/syft-bin"
mkdir -p "${syft_bin}"
ln -s "${root_dir}/scripts/testdata/fake-syft.sh" "${syft_bin}/syft"
sbom_dir="${fixture_dir}/sbom"
sbom_archive="${sbom_dir}/SpeeDNS_${version}_linux_amd64.tar.gz"
# The wrapper's temporary directory, empty again once it exits.
sbom_tmp="${sbom_dir}/tmp"
mkdir -p "${sbom_dir}/first" "${sbom_dir}/second" "${sbom_tmp}"
printf 'fixture archive\n' >"${sbom_archive}"
# Both scans write the same path, as the two release builds each write
# dist/<artifact>.sbom.json; the fake records its arguments, path included.
for scan in first second; do
	PATH="${syft_bin}:${PATH}" \
		TMPDIR="${sbom_tmp}" \
		SOURCE_DATE_EPOCH=1700000000 \
		SYFT_GOLANG_SEARCH_REMOTE_LICENSES=true \
		SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES=false \
		SYFT_CHECK_FOR_APP_UPDATE=true \
		bash "${root_dir}/scripts/reproducible-syft.sh" "${sbom_archive}" \
		--output "spdx-json=${sbom_dir}/archive.sbom.json" >/dev/null
	mv "${sbom_dir}/archive.sbom.json" "${sbom_dir}/${scan}/archive.sbom.json"
done
if ! cmp -s "${sbom_dir}/first/archive.sbom.json" "${sbom_dir}/second/archive.sbom.json"; then
	echo "two scans of one archive produced different SBOMs" >&2
	diff -u "${sbom_dir}/first/archive.sbom.json" "${sbom_dir}/second/archive.sbom.json" >&2 || true
	exit 1
fi
# Exactly one configuration file, holding the wrapper's empty mapping while
# Syft ran: a second would be merged with it.
if ! jq -e --arg cache "$(go env GOMODCACHE)" '
	.creationInfo.created == "2023-11-14T22:13:20Z" and
	(.fixture.arguments | index("--enrich") | not) and
	.fixture.configs == ["{}\n"] and
	.fixture.settings.SYFT_GOLANG_SEARCH_REMOTE_LICENSES == "false" and
	.fixture.settings.SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES == "true" and
	.fixture.settings.SYFT_GOLANG_LOCAL_MOD_CACHE_DIR == $cache and
	.fixture.settings.SYFT_CHECK_FOR_APP_UPDATE == "false"
' "${sbom_dir}/first/archive.sbom.json" >/dev/null; then
	echo "reproducible-syft.sh did not run Syft offline, on its own configuration file, with a normalized creation time:" >&2
	jq '{created: .creationInfo.created, fixture}' "${sbom_dir}/first/archive.sbom.json" >&2
	exit 1
fi
if [[ -n "$(find "${sbom_tmp}" -mindepth 1 -print -quit)" ]]; then
	echo "reproducible-syft.sh left its Syft configuration behind:" >&2
	find "${sbom_tmp}" -mindepth 1 >&2
	exit 1
fi
# --enrich turns the network lookups back on, and another --config would be
# merged into the wrapper's, enrich: lists included, so both are refused
# before Syft runs, as separate, =-joined and attached values alike.
for refused_option in '--enrich all' '--enrich=golang' '--config planted.yaml' '--config=planted.yaml' '-c planted.yaml' '-cplanted.yaml'; do
	read -r -a refused_arguments <<<"${refused_option}"
	refused="${sbom_dir}/refused.sbom.json"
	if PATH="${syft_bin}:${PATH}" SOURCE_DATE_EPOCH=1700000000 \
		bash "${root_dir}/scripts/reproducible-syft.sh" "${sbom_archive}" \
		--output "spdx-json=${refused}" "${refused_arguments[@]}" 2>/dev/null; then
		echo "reproducible-syft.sh accepted ${refused_option}" >&2
		exit 1
	fi
	if [[ -e "${refused}" ]]; then
		echo "reproducible-syft.sh ran Syft before refusing ${refused_option}" >&2
		exit 1
	fi
done

bash "${root_dir}/scripts/homebrew-tap-fixture.sh"

echo "release script fixture passed"
