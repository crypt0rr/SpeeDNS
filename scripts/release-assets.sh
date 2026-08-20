#!/usr/bin/env bash
set -euo pipefail

usage() {
	echo "usage: $0 list|verify DIST [MANIFEST]" >&2
}

mode="${1:-}"
dist_dir="${2:-dist}"
manifest="${3:-}"

if [[ ! -d "${dist_dir}" ]]; then
	echo "release directory does not exist: ${dist_dir}" >&2
	exit 2
fi
if [[ ! -f "${dist_dir}/artifacts.json" || ! -f "${dist_dir}/checksums.txt" ]]; then
	echo "GoReleaser metadata or checksums are missing from ${dist_dir}" >&2
	exit 1
fi
if [[ "${mode}" != list && "${mode}" != verify ]]; then
	usage
	exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
	echo "jq is required to inspect GoReleaser artifacts.json" >&2
	exit 1
fi

artifact_path() {
	local path="$1"
	case "${path}" in
		"${dist_dir}"/*)
			printf '%s\n' "${path}"
			;;
		dist/*)
			printf '%s/%s\n' "${dist_dir}" "${path#dist/}"
			;;
		*)
			printf '%s/%s\n' "${dist_dir}" "${path}"
			;;
	esac
}

list_release_assets() {
	jq -r '
		.[] |
		select(
			.type == "Archive" or
			.type == "Linux Package" or
			.type == "Checksum" or
			.type == "Signature" or
			.type == "SBOM"
		) |
		.path
	' "${dist_dir}/artifacts.json" |
		while IFS= read -r path; do
			[[ -n "${path}" ]] || continue
			artifact_path "${path}"
		done |
		sort -u
}

mapfile -t assets < <(list_release_assets)
if [[ "${#assets[@]}" -eq 0 ]]; then
	echo "GoReleaser did not produce any publishable release assets" >&2
	exit 1
fi

if [[ "${mode}" == list ]]; then
	printf '%s\n' "${assets[@]}"
	exit 0
fi

for asset in "${assets[@]}"; do
	case "${asset}" in
		"${dist_dir}"/*) ;;
		*)
			echo "release asset escapes the release directory: ${asset}" >&2
			exit 1
			;;
	esac
	if [[ ! -f "${asset}" ]]; then
		echo "release asset listed by GoReleaser is missing: ${asset}" >&2
		exit 1
	fi
done

checksum_asset="${dist_dir}/checksums.txt"
if ! printf '%s\n' "${assets[@]}" | grep -Fqx -- "${checksum_asset}"; then
	echo "checksums.txt is not listed as a release asset" >&2
	exit 1
fi

(
	cd "${dist_dir}"
	sha256sum --strict --check checksums.txt
)

if [[ -n "${manifest}" ]]; then
	mkdir -p "$(dirname "${manifest}")"
	printf '%s\n' "${assets[@]}" >"${manifest}"
fi

echo "release asset verification passed (${#assets[@]} assets)"
