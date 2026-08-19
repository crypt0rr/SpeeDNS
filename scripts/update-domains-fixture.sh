#!/usr/bin/env bash
set -euo pipefail

# Offline regression test for update-domains.sh. It exercises the same curl and
# awk path used by maintainers without contacting Tranco or changing data/.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary_dir="$(mktemp -d)"
trap 'rm -rf "${temporary_dir}"' EXIT

fixture="${temporary_dir}/tranco.csv"
output_dir="${temporary_dir}/data"
fake_bin="${temporary_dir}/bin"
mkdir -p "${fake_bin}"

{
	printf '1,Example.COM.\n'
	printf '2,example.com\n'
	for index in $(seq 1 999); do
		printf '%d,site-%d.example\n' "$((index + 2))" "${index}"
	done
} >"${fixture}"

cat >"${fake_bin}/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output=""
while (($#)); do
	if [[ "$1" == "-o" ]]; then
		output="$2"
		shift 2
		continue
	fi
	shift
done
cp "${SPEEDNS_FIXTURE}" "${output}"
EOF
chmod +x "${fake_bin}/curl"

PATH="${fake_bin}:${PATH}" SPEEDNS_FIXTURE="${fixture}" \
	SPEEDNS_TRANCO_DOWNLOAD_URL="fixture://tranco" SPEEDNS_DOMAINS_OUTPUT_DIR="${output_dir}" \
	bash "${root_dir}/scripts/update-domains.sh" fixture-list

[[ "$(wc -l <"${output_dir}/domains.txt" | tr -d ' ')" == "1000" ]]
[[ "$(head -n 1 "${output_dir}/domains.txt")" == "example.com" ]]
[[ "$(grep -c '^example.com$' "${output_dir}/domains.txt")" == "1" ]]
grep -q '"entries": 1000' "${output_dir}/domains.meta.json"
grep -Eq '"sha256": "[0-9a-f]{64}"' "${output_dir}/domains.meta.json"

printf '1,bad..example\n' >"${fixture}"
if PATH="${fake_bin}:${PATH}" SPEEDNS_FIXTURE="${fixture}" \
	SPEEDNS_TRANCO_DOWNLOAD_URL="fixture://invalid" SPEEDNS_DOMAINS_OUTPUT_DIR="${temporary_dir}/invalid" \
	bash "${root_dir}/scripts/update-domains.sh" invalid-list; then
	echo "invalid fixture unexpectedly succeeded" >&2
	exit 1
fi

echo "update-domains fixture passed"
