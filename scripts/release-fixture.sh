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
		"speedns_${version}_linux_arm64.deb"; do
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
			>checksums.txt
	)
	jq -n \
		--arg version "${version}" \
		'[{type:"Archive", path:("dist/SpeeDNS_"+$version+"_darwin_amd64.tar.gz")}, {type:"Archive", path:("dist/SpeeDNS_"+$version+"_darwin_arm64.tar.gz")}, {type:"Archive", path:("dist/SpeeDNS_"+$version+"_linux_amd64.tar.gz")}, {type:"Archive", path:("dist/SpeeDNS_"+$version+"_linux_arm64.tar.gz")}, {type:"Linux Package", path:("dist/speedns_"+$version+"_linux_amd64.deb")}, {type:"Linux Package", path:("dist/speedns_"+$version+"_linux_arm64.deb")}, {type:"Checksum", path:"dist/checksums.txt"}]' >"${destination}/artifacts.json"
}

version="0.1.0-fixture"
make_dist "${fixture_dir}/first" "${version}"
make_dist "${fixture_dir}/second" "${version}"

bash "${root_dir}/scripts/release-assets.sh" verify "${fixture_dir}/first" \
	"${fixture_dir}/first/release-assets.txt"
bash "${root_dir}/scripts/homebrew-cask.sh" "v${version}" "${fixture_dir}/first" \
	"${fixture_dir}/first/speedns.rb"
bash "${root_dir}/scripts/compare-release-artifacts.sh" \
	"${fixture_dir}/first" "${fixture_dir}/second"

grep -Fq 'version "0.1.0-fixture"' "${fixture_dir}/first/speedns.rb"
grep -Fq 'github.com/crypt0rr/SpeeDNS/releases/download' "${fixture_dir}/first/speedns.rb"

printf 'changed\n' >>"${fixture_dir}/second/SpeeDNS_${version}_linux_amd64.tar.gz"
if bash "${root_dir}/scripts/compare-release-artifacts.sh" \
	"${fixture_dir}/first" "${fixture_dir}/second"; then
	echo "expected reproducibility mismatch was not detected" >&2
	exit 1
fi

echo "release script fixture passed"
