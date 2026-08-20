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
