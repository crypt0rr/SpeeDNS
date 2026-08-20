#!/usr/bin/env bash
set -euo pipefail

usage() {
	echo "usage: $0 linux|macos|macos-archives [dist-directory] [release-manifest]" >&2
}

mode="${1:-}"
dist_dir="${2:-dist}"
release_manifest="${3:-}"
if [[ ! -d "${dist_dir}" ]]; then
	usage
	exit 2
fi
case "${mode}" in
	linux|macos|macos-archives) ;;
	*)
		usage
		exit 2
		;;
esac

smoke_dir="$(mktemp -d "${TMPDIR:-/tmp}/speedns-artifact-smoke.XXXXXX")"
trap 'rm -rf -- "${smoke_dir}"' EXIT

find_artifact() {
	local pattern="$1"
	find "${dist_dir}" -type f -iname "${pattern}" -print -quit
}

require_artifact() {
	local pattern="$1"
	local artifact
	artifact="$(find_artifact "${pattern}")"
	if [[ -z "${artifact}" ]]; then
		echo "missing artifact matching ${pattern} in ${dist_dir}" >&2
		exit 1
	fi
	if [[ -n "${release_manifest}" ]] && ! grep -Fqx -- "${artifact}" "${release_manifest}"; then
		echo "${artifact} is not present in the release asset manifest" >&2
		exit 1
	fi
	echo "using ${artifact}" >&2
	printf '%s\n' "${artifact}"
}

extract_archive() {
	local archive="$1"
	local label="$2"
	local destination="${smoke_dir}/${label}"
	mkdir -p "${destination}"
	tar -xzf "${archive}" -C "${destination}"
	local binary
	binary="$(find "${destination}" -type f -name speedns -print -quit)"
	if [[ -z "${binary}" ]]; then
		echo "${archive} does not contain a speedns binary" >&2
		exit 1
	fi
	if [[ ! -x "${binary}" ]]; then
		echo "packaged binary is not executable: ${binary}" >&2
		exit 1
	fi
	if [[ -z "$(find "${destination}" -type f -name speedns.1 -print -quit)" ]]; then
		echo "${archive} does not contain the speedns.1 man page" >&2
		exit 1
	fi
	printf '%s\n' "${binary}"
}

check_archive() {
	local archive="$1"
	local label="$2"
	local binary
	binary="$(extract_archive "${archive}" "${label}")"
	if [[ "${3:-false}" == true ]]; then
		"${binary}" version | grep -q '^speedns '
	fi
}

check_linux() {
	local archive deb binary deb_root package architecture
	archive="$(require_artifact '*linux*amd64*.tar.gz')"
	check_archive "${archive}" linux-archive true

	if ! command -v dpkg-deb >/dev/null 2>&1; then
		echo "dpkg-deb is required for Debian package smoke tests" >&2
		exit 1
	fi
	deb="$(require_artifact '*linux*amd64*.deb')"
	package="$(dpkg-deb -f "${deb}" Package)"
	architecture="$(dpkg-deb -f "${deb}" Architecture)"
	if [[ "${package}" != speedns || "${architecture}" != amd64 ]]; then
		echo "unexpected Debian metadata: package=${package} architecture=${architecture}" >&2
		exit 1
	fi
	deb_root="${smoke_dir}/debian"
	dpkg-deb -x "${deb}" "${deb_root}"
	binary="${deb_root}/usr/bin/speedns"
	if [[ ! -f "${binary}" || ! -x "${binary}" ]]; then
		echo "Debian package does not install executable /usr/bin/speedns" >&2
		exit 1
	fi
	if [[ ! -f "${deb_root}/usr/share/man/man1/speedns.1" ]]; then
		echo "Debian package does not install /usr/share/man/man1/speedns.1" >&2
		exit 1
	fi
	"${binary}" version | grep -q '^speedns '

	check_package_format rpm
	check_package_format apk
	check_package_format 'pkg.tar.zst'
}

check_package_format() {
	local format="$1"
	local -a package_artifacts=()
	local artifact basename amd64_artifact arm64_artifact expected_arch package_name package_arch package_version package_license package_entries package_info
	mapfile -t package_artifacts < <(find "${dist_dir}" -type f -iname "*.${format}" -print | sort)
	if [[ "${#package_artifacts[@]}" -ne 2 ]]; then
		echo "expected exactly two Linux ${format} packages, found ${#package_artifacts[@]}" >&2
		exit 1
	fi

	for artifact in "${package_artifacts[@]}"; do
		basename="$(basename "${artifact}")"
		case "${basename}" in
			*amd64*|*x86_64*)
				if [[ -n "${amd64_artifact:-}" ]]; then
					echo "multiple amd64 Linux ${format} packages found" >&2
					exit 1
				fi
				amd64_artifact="${artifact}"
				;;
			*arm64*|*aarch64*)
				if [[ -n "${arm64_artifact:-}" ]]; then
					echo "multiple arm64 Linux ${format} packages found" >&2
					exit 1
				fi
				arm64_artifact="${artifact}"
				;;
			*)
				echo "Linux ${format} package has no recognized architecture: ${artifact}" >&2
				exit 1
				;;
		esac
	done

	for artifact in "${amd64_artifact}" "${arm64_artifact}"; do
		basename="$(basename "${artifact}")"
		case "${basename}" in
			*amd64*|*x86_64*) expected_arch=x86_64 ;;
			*arm64*|*aarch64*) expected_arch=aarch64 ;;
			*) echo "Linux ${format} package has no recognized architecture: ${artifact}" >&2; exit 1 ;;
		esac
		if [[ -n "${release_manifest}" ]] && ! grep -Fqx -- "${artifact}" "${release_manifest}"; then
			echo "${artifact} is not present in the release asset manifest" >&2
			exit 1
		fi
		if [[ ! -s "${artifact}" ]]; then
			echo "Linux ${format} package is empty: ${artifact}" >&2
			exit 1
		fi
		echo "using ${artifact}" >&2

		case "${format}" in
			rpm)
				if ! command -v rpm >/dev/null 2>&1; then
					echo "rpm is required for RPM package smoke tests" >&2
					exit 1
				fi
				package_name="$(rpm -qp --queryformat '%{NAME}' "${artifact}")"
				package_arch="$(rpm -qp --queryformat '%{ARCH}' "${artifact}")"
				package_version="$(rpm -qp --queryformat '%{VERSION}' "${artifact}")"
				package_license="$(rpm -qp --queryformat '%{LICENSE}' "${artifact}")"
				if [[ "${package_name}" != speedns || "${package_arch}" != "${expected_arch}" || -z "${package_version}" || "${package_license}" != MIT ]]; then
					echo "unexpected RPM metadata: package=${package_name} architecture=${package_arch} version=${package_version} license=${package_license}" >&2
					exit 1
				fi
				if ! rpm -qpl "${artifact}" | sed 's#^/##;s#^\./##' | grep -Fqx 'usr/bin/speedns'; then
					echo "RPM package does not contain /usr/bin/speedns" >&2
					exit 1
				fi
				;;
			apk)
				package_entries="$(tar -tzf "${artifact}" 2>/dev/null | sed 's#^\./##')"
				package_info="$(tar -xOzf "${artifact}" .PKGINFO 2>/dev/null)"
				;;
			pkg.tar.zst)
				package_entries="$(tar --zstd -tf "${artifact}" 2>/dev/null | sed 's#^\./##')"
				package_info="$(tar --zstd -xOf "${artifact}" .PKGINFO 2>/dev/null)"
				;;
		esac
		if [[ "${format}" != rpm ]]; then
			if ! grep -Fqx 'usr/bin/speedns' <<<"${package_entries}"; then
				echo "Linux ${format} package does not contain /usr/bin/speedns" >&2
				exit 1
			fi
			if ! grep -Fqx 'pkgname = speedns' <<<"${package_info}" ||
				! grep -Fqx "arch = ${expected_arch}" <<<"${package_info}" ||
				! grep -Eq '^pkgver = .+$' <<<"${package_info}" ||
				! grep -Fqx 'license = MIT' <<<"${package_info}"; then
				echo "unexpected Linux ${format} package metadata: ${artifact}" >&2
				exit 1
			fi
		fi
	done

	if [[ -f "${dist_dir}/artifacts.json" ]]; then
		if ! command -v jq >/dev/null 2>&1; then
			echo "jq is required to validate the GoReleaser package catalog" >&2
			exit 1
		fi
		if ! jq -e --arg extension ".${format}" '
			[.[] | select(.type == "Linux Package" and (.name | endswith($extension))) | .goarch] |
			sort == ["amd64", "arm64"]
		' "${dist_dir}/artifacts.json" >/dev/null; then
			echo "GoReleaser package catalog is incomplete for .${format}" >&2
			exit 1
		fi
	fi
}

check_macos_archives() {
	local goarch archive
	for goarch in amd64 arm64; do
		archive="$(require_artifact "*darwin*_${goarch}.tar.gz")"
		check_archive "${archive}" "macos-${goarch}"
	done
}

check_macos_native() {
	local machine goarch archive binary
	machine="$(uname -m)"
	case "${machine}" in
		x86_64) goarch=amd64 ;;
		arm64) goarch=arm64 ;;
		*) echo "unsupported macOS runner architecture: ${machine}" >&2; exit 1 ;;
	esac
	archive="$(require_artifact "*darwin*_${goarch}.tar.gz")"
	binary="$(extract_archive "${archive}" "macos-native")"
	"${binary}" version | grep -q '^speedns '
}

case "${mode}" in
	linux) check_linux ;;
	macos) check_macos_native ;;
	macos-archives) check_macos_archives ;;
esac

echo "artifact smoke checks passed (${mode})"
