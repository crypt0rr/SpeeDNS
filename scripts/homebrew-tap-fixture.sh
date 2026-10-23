#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/speedns-homebrew-tap-fixture.XXXXXX")"
trap 'rm -rf -- "${fixture_dir}"' EXIT

fake_bin="${fixture_dir}/bin"
mkdir -p "${fake_bin}"
fake_log="${fixture_dir}/gh.log"
cask_file="${fixture_dir}/speedns.rb"
printf '%s\n' \
	'# generated fixture' \
	'cask "speedns" do' \
	'  version "0.6.3-fixture"' \
	'end' >"${cask_file}"
fake_cask_content="$(base64 <"${cask_file}" | tr -d '\n')"
deprecated_cask_file="${fixture_dir}/deprecated-speedns.rb"
printf '%s\n' \
	'# generated fixture' \
	'cask "speedns" do' \
	'  version "0.6.3-fixture"' \
	'  url "https://example.test/speedns.tar.gz",' \
	'      verified: "example.test"' \
	'end' >"${deprecated_cask_file}"
deprecated_cask_content="$(base64 <"${deprecated_cask_file}" | tr -d '\n')"
# tap_cask_content builds the base64 the fake tap serves as the CURRENT cask,
# declaring the version given (or no version line at all for an empty one).
tap_cask_content() {
	{
		printf '%s\n' '# generated fixture' 'cask "speedns" do'
		if [[ -n "$1" ]]; then
			printf '  version "%s"\n' "$1"
		fi
		printf '%s\n' '  binary "speedns"' 'end'
	} | base64 | tr -d '\n'
}

fake_gh="${fake_bin}/gh"
cat >"${fake_gh}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" != api ]]; then
	echo "unsupported fake gh command" >&2
	exit 2
fi
endpoint="${2:-}"
shift 2
method=GET
jq_filter=""
sha_field=""
while (($# > 0)); do
	case "${1}" in
		--method)
			method="${2}"
			shift 2
			;;
		--jq)
			jq_filter="${2}"
			shift 2
			;;
		--raw-field)
			case "${2}" in
				sha=*) sha_field=" ${2}" ;;
			esac
			shift 2
			;;
		*)
			shift
			;;
	esac
done
# The sha is logged because it is what makes a PUT an update rather than a
# create: GitHub refuses a sha-less PUT over an existing file.
printf '%s %s %s%s\n' "${method}" "${endpoint}" "${jq_filter}" "${sha_field}" >>"${FAKE_GH_LOG}"

# GitHub wraps the base64 in a contents response every 60 characters, so the
# fake does too rather than serving a single line no real response has.
serve_cask_content() {
	printf '%s\n' "${FAKE_CASK_CONTENT_B64}" | fold -w 60
}

case "${endpoint}" in
	repos/example/tap)
		printf '%s\n' main
		;;
	repos/example/tap/git/trees/main\?recursive=1)
		case "${FAKE_TAP_MODE:-clean}" in
			clean)
				printf '%s\n' LICENSE Casks/speedns.rb
				;;
			legacy)
				printf '%s\n' LICENSE Casks/SpeeDNS.rb Casks/speedns.rb
				;;
			uppercase)
				printf '%s\n' LICENSE Casks/SpeeDNS.rb
				;;
			empty)
				printf '%s\n' LICENSE
				;;
			*)
				echo "unknown fake tap mode" >&2
				exit 2
				;;
		esac
		;;
	repos/example/tap/contents/Casks/speedns.rb\?ref=main)
		if [[ "${FAKE_TAP_MODE:-clean}" == empty ]]; then
			echo "gh: Not Found (HTTP 404)" >&2
			exit 1
		fi
		case "${jq_filter}" in
			.content)
				serve_cask_content
				;;
			'.sha, .content')
				printf '%s\n' fixture-sha
				serve_cask_content
				;;
			*)
				echo "unexpected fake contents filter: ${jq_filter}" >&2
				exit 2
				;;
		esac
		;;
	repos/example/tap/contents/Casks/speedns.rb)
		if [[ "${method}" != PUT ]]; then
			echo "unexpected fake contents method" >&2
			exit 2
		fi
		printf '%s\n' fixture-commit
		;;
	*)
		echo "unexpected fake gh endpoint: ${endpoint}" >&2
		exit 2
		;;
esac
EOF
chmod +x "${fake_gh}"

common_env=(
	PATH="${fake_bin}:${PATH}"
	GH_TOKEN=fixture-token
	HOMEBREW_TAP_TOKEN=fixture-token
	FAKE_GH_LOG="${fake_log}"
	FAKE_CASK_CONTENT_B64="${fake_cask_content}"
)

env "${common_env[@]}" FAKE_TAP_MODE=clean \
	bash "${root_dir}/scripts/validate-homebrew-tap.sh" v0.6.3-fixture example/tap

if env "${common_env[@]}" FAKE_TAP_MODE=clean \
	FAKE_CASK_CONTENT_B64="${deprecated_cask_content}" \
	bash "${root_dir}/scripts/validate-homebrew-tap.sh" v0.6.3-fixture example/tap; then
	echo "deprecated verified: cask was unexpectedly accepted by validation" >&2
	exit 1
fi

if env "${common_env[@]}" FAKE_TAP_MODE=legacy \
	bash "${root_dir}/scripts/validate-homebrew-tap.sh" v0.6.3-fixture example/tap; then
	echo "legacy cask path was unexpectedly accepted" >&2
	exit 1
fi

if env "${common_env[@]}" FAKE_TAP_MODE=clean \
	bash "${root_dir}/scripts/publish-homebrew-cask.sh" "${cask_file}" \
	v0.6.3-fixture example/tap Casks/SpeeDNS.rb; then
	echo "case-variant publication path was unexpectedly accepted" >&2
	exit 1
fi

: >"${fake_log}"
env "${common_env[@]}" FAKE_TAP_MODE=clean \
	bash "${root_dir}/scripts/publish-homebrew-cask.sh" "${cask_file}" \
	v0.6.3-fixture example/tap
grep -Fq 'PUT repos/example/tap/contents/Casks/speedns.rb' "${fake_log}"

: >"${fake_log}"
if env "${common_env[@]}" FAKE_TAP_MODE=clean \
	bash "${root_dir}/scripts/publish-homebrew-cask.sh" "${deprecated_cask_file}" \
	v0.6.3-fixture example/tap; then
	echo "deprecated verified: cask was unexpectedly published" >&2
	exit 1
fi
if [[ -s "${fake_log}" ]]; then
	echo "publisher contacted GitHub before rejecting deprecated verified: cask" >&2
	exit 1
fi

: >"${fake_log}"
if env "${common_env[@]}" FAKE_TAP_MODE=legacy \
	bash "${root_dir}/scripts/publish-homebrew-cask.sh" "${cask_file}" \
	v0.6.3-fixture example/tap; then
	echo "legacy remote cask path was unexpectedly accepted" >&2
	exit 1
fi
if grep -Fq 'PUT repos/example/tap/contents/Casks/speedns.rb' "${fake_log}"; then
	echo "publisher wrote before rejecting the legacy path" >&2
	exit 1
fi

# Downgrade guard. Homebrew moves every user to whatever version the tap
# declares, so an older release must not replace a newer cask by accident.
: >"${fake_log}"
if env "${common_env[@]}" FAKE_TAP_MODE=clean \
	FAKE_CASK_CONTENT_B64="$(tap_cask_content 0.7.0)" \
	bash "${root_dir}/scripts/publish-homebrew-cask.sh" "${cask_file}" \
	v0.6.9 example/tap; then
	echo "v0.6.9 unexpectedly replaced a 0.7.0 cask" >&2
	exit 1
fi
if grep -Fq 'PUT ' "${fake_log}"; then
	echo "publisher wrote before refusing the downgrade" >&2
	exit 1
fi

# sort -V, not a string comparison: 0.9.0 sorts above 0.10.0 as text.
: >"${fake_log}"
if env "${common_env[@]}" FAKE_TAP_MODE=clean \
	FAKE_CASK_CONTENT_B64="$(tap_cask_content 0.10.0)" \
	bash "${root_dir}/scripts/publish-homebrew-cask.sh" "${cask_file}" \
	v0.9.0 example/tap; then
	echo "v0.9.0 unexpectedly replaced a 0.10.0 cask" >&2
	exit 1
fi
if grep -Fq 'PUT ' "${fake_log}"; then
	echo "publisher wrote before refusing the downgrade" >&2
	exit 1
fi

# The explicit override, and the versions that are not downgrades at all.
for case_spec in 'v0.6.9 1' 'v0.7.0 0' 'v0.7.1 0' 'v0.10.0 0'; do
	read -r publish_tag allow_downgrade <<<"${case_spec}"
	: >"${fake_log}"
	env "${common_env[@]}" FAKE_TAP_MODE=clean \
		FAKE_CASK_CONTENT_B64="$(tap_cask_content 0.7.0)" \
		ALLOW_DOWNGRADE="${allow_downgrade}" \
		bash "${root_dir}/scripts/publish-homebrew-cask.sh" "${cask_file}" \
		"${publish_tag}" example/tap
	if ! grep -Fqx 'PUT repos/example/tap/contents/Casks/speedns.rb .commit.sha sha=fixture-sha' "${fake_log}"; then
		echo "${publish_tag} (ALLOW_DOWNGRADE=${allow_downgrade}) over 0.7.0 did not update the cask in place" >&2
		cat "${fake_log}" >&2
		exit 1
	fi
done

# A cask with no readable version cannot be ordered, so it is not replaced
# unless the override is set.
: >"${fake_log}"
if env "${common_env[@]}" FAKE_TAP_MODE=clean \
	FAKE_CASK_CONTENT_B64="$(tap_cask_content '')" \
	bash "${root_dir}/scripts/publish-homebrew-cask.sh" "${cask_file}" \
	v0.7.1 example/tap; then
	echo "a cask without a version line was unexpectedly replaced" >&2
	exit 1
fi
if grep -Fq 'PUT ' "${fake_log}"; then
	echo "publisher wrote before refusing a cask without a version line" >&2
	exit 1
fi
: >"${fake_log}"
env "${common_env[@]}" FAKE_TAP_MODE=clean \
	FAKE_CASK_CONTENT_B64="$(tap_cask_content '')" \
	ALLOW_DOWNGRADE=1 \
	bash "${root_dir}/scripts/publish-homebrew-cask.sh" "${cask_file}" \
	v0.7.1 example/tap
grep -Fqx 'PUT repos/example/tap/contents/Casks/speedns.rb .commit.sha sha=fixture-sha' "${fake_log}"

# No cask yet is the first publication: allowed, and created without a sha.
: >"${fake_log}"
env "${common_env[@]}" FAKE_TAP_MODE=empty \
	bash "${root_dir}/scripts/publish-homebrew-cask.sh" "${cask_file}" \
	v0.1.0 example/tap
if ! grep -Fqx 'PUT repos/example/tap/contents/Casks/speedns.rb .commit.sha' "${fake_log}"; then
	echo "first publication did not create the cask without a sha" >&2
	cat "${fake_log}" >&2
	exit 1
fi

# Crafted tags. The version is interpolated into a Ruby string and matched as a
# whole line, so both scripts must refuse it before contacting GitHub. The tap
# serves the very line such a tag would produce, so the version check alone
# would have passed it.
# shellcheck disable=SC2016 # The backticks are the payload, not a command.
crafted_tags=('v0.7.0#{`id`}' 'v0.7.0";system("id");"' 'v0.7.0;id' 'v0.7.0 ' 'v0.7')
for crafted_tag in "${crafted_tags[@]}"; do
	: >"${fake_log}"
	if env "${common_env[@]}" FAKE_TAP_MODE=clean \
		FAKE_CASK_CONTENT_B64="$(tap_cask_content "${crafted_tag#v}")" \
		bash "${root_dir}/scripts/validate-homebrew-tap.sh" "${crafted_tag}" example/tap; then
		echo "tap validation accepted crafted tag ${crafted_tag}" >&2
		exit 1
	fi
	if env "${common_env[@]}" FAKE_TAP_MODE=clean \
		bash "${root_dir}/scripts/publish-homebrew-cask.sh" "${cask_file}" \
		"${crafted_tag}" example/tap; then
		echo "publisher accepted crafted tag ${crafted_tag}" >&2
		exit 1
	fi
	if [[ -s "${fake_log}" ]]; then
		echo "GitHub was contacted before crafted tag ${crafted_tag} was refused" >&2
		exit 1
	fi
done

echo "Homebrew tap fixture passed"
