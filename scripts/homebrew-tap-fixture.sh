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
		*)
			shift
			;;
	esac
done
printf '%s %s %s\n' "${method}" "${endpoint}" "${jq_filter}" >>"${FAKE_GH_LOG}"

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
			*)
				echo "unknown fake tap mode" >&2
				exit 2
				;;
		esac
		;;
	repos/example/tap/contents/Casks/speedns.rb\?ref=main)
		if [[ "${jq_filter}" == .content ]]; then
			printf '%s\n' "${FAKE_CASK_CONTENT_B64}"
		else
			printf '%s\n' fixture-sha
		fi
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

echo "Homebrew tap fixture passed"
