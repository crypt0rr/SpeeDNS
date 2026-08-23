#!/usr/bin/env bash
set -euo pipefail

# Offline regression test for publish-live-results.py. Every evidence file is
# encoded by the real speedns report writer, so a shape the encoder cannot
# produce can never make this fixture pass. Nothing contacts a resolver.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary_dir="$(mktemp -d)"
trap 'rm -rf "${temporary_dir}"' EXIT

evidence_dir="${temporary_dir}/evidence"
results_dir="${temporary_dir}/results"

# Evidence is produced by the real report encoder instead of a hand-written
# literal, so the publisher is only ever asked to accept JSON that speedns can
# actually emit. The generator never dials a resolver.
generate_evidence() {
	local target_dir="$1"
	local failed="${2:-}"
	(cd "${root_dir}" && go run ./scripts/testdata/live-results-evidence \
		--output-dir "${target_dir}" \
		--failed "${failed}")
}

# Published records are checked against the schema the publisher ships beside
# them rather than against this script's expectations.
validate_record() {
	local published="$1"
	python3 "${root_dir}/scripts/testdata/validate-json-schema.py" \
		--schema "${published}/live-results-v1.schema.json" \
		--instance "${published}/latest.json"
}

generate_evidence "${evidence_dir}"
cp -R "${evidence_dir}" "${temporary_dir}/original-evidence"

export SPEEDNS_RESULTS_RUN_ID=fixture-run
export SPEEDNS_RESULTS_PUBLISHED_AT=2026-01-02T03:04:05.000Z
export GITHUB_REPOSITORY=crypt0rr/SpeeDNS
export GITHUB_SHA=0123456789abcdef0123456789abcdef01234567
export GITHUB_REF_NAME=main
export GITHUB_RUN_ID=local
export GITHUB_RUN_ATTEMPT=1

python3 "${root_dir}/scripts/publish-live-results.py" \
  --evidence-dir "${evidence_dir}" \
  --output-dir "${results_dir}"
python3 "${root_dir}/scripts/publish-live-results.py" \
  --evidence-dir "${evidence_dir}" \
  --output-dir "${results_dir}"

[[ -s "${results_dir}/runs/fixture-run.json" ]]
[[ -s "${results_dir}/latest.json" ]]
[[ -s "${results_dir}/index.html" ]]
[[ -s "${results_dir}/live-results-v1.schema.json" ]]
[[ -f "${results_dir}/.nojekyll" ]]
grep -Fq '&lt;script&gt;' "${results_dir}/index.html"
if grep -Fq '<script>' "${results_dir}/index.html"; then
	echo "HTML escaping fixture failed" >&2
	exit 1
fi
validate_record "${results_dir}"
python3 - "${results_dir}/latest.json" <<'PY'
import json
import pathlib
import sys

record = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert record["run"]["outcome"] == "passed"
assert record["run"]["seed"] == 42
assert record["failures"] == []
assert len(record["transports"]) == 5
assert len(record["summary"]) == 5
PY

python3 - "${evidence_dir}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1]) / "udp.json"
report = json.loads(path.read_text(encoding="utf-8"))
report["results"][0]["target"]["owner"] = "changed"
path.write_text(json.dumps(report) + "\n", encoding="utf-8")
PY
if python3 "${root_dir}/scripts/publish-live-results.py" \
	--evidence-dir "${evidence_dir}" \
	--output-dir "${results_dir}"; then
	echo "immutable record fixture unexpectedly passed" >&2
	exit 1
fi

cp -R "${temporary_dir}/results" "${temporary_dir}/malformed-results"
cp -R "${temporary_dir}/original-evidence" "${temporary_dir}/malformed-evidence"
rm "${temporary_dir}/malformed-evidence/doh.json"
if python3 "${root_dir}/scripts/publish-live-results.py" \
	--evidence-dir "${temporary_dir}/malformed-evidence" \
	--output-dir "${temporary_dir}/malformed-results"; then
	echo "malformed evidence fixture unexpectedly passed" >&2
	exit 1
fi

cp -R "${temporary_dir}/original-evidence" "${temporary_dir}/malformed-ranking-evidence"
python3 - "${temporary_dir}/malformed-ranking-evidence/udp.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
report = json.loads(path.read_text(encoding="utf-8"))
report["rankings"][0]["target_id"] = "unrelated-target"
path.write_text(json.dumps(report) + "\n", encoding="utf-8")
PY
if python3 "${root_dir}/scripts/publish-live-results.py" \
	--evidence-dir "${temporary_dir}/malformed-ranking-evidence" \
	--output-dir "${temporary_dir}/malformed-ranking-results"; then
	echo "malformed ranking fixture unexpectedly passed" >&2
	exit 1
fi

generate_evidence "${temporary_dir}/no-comparable-evidence" doq
python3 - "${temporary_dir}/no-comparable-evidence/doq.json" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert report["rankings"] == [], report["rankings"]
stats = report["results"][0]["stats"]
for key in ("cold_median_ms", "ci_low_ms", "ci_high_ms", "tie"):
    assert key in stats, f"encoder dropped stats.{key} for a failed transport"
    assert not stats[key], (key, stats[key])
PY
export SPEEDNS_RESULTS_RUN_ID=fixture-no-comparable-run
python3 "${root_dir}/scripts/publish-live-results.py" \
	--evidence-dir "${temporary_dir}/no-comparable-evidence" \
	--output-dir "${temporary_dir}/no-comparable-results"
validate_record "${temporary_dir}/no-comparable-results"
python3 - "${temporary_dir}/no-comparable-results/latest.json" <<'PY'
import json
import pathlib
import sys

record = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert record["run"]["outcome"] == "failed"
assert record["failures"] == ["doq: no comparable ranking"]
assert record["summary"][-1]["status"] == "failed"
assert record["summary"][-1]["winner"] is None
assert record["transports"][-1]["status"] == "failed"
PY

generate_evidence "${temporary_dir}/all-failed-evidence" udp,tcp,doh,dot,doq
export SPEEDNS_RESULTS_RUN_ID=fixture-all-failed-run
python3 "${root_dir}/scripts/publish-live-results.py" \
	--evidence-dir "${temporary_dir}/all-failed-evidence" \
	--output-dir "${temporary_dir}/all-failed-results"
validate_record "${temporary_dir}/all-failed-results"
python3 - "${temporary_dir}/all-failed-results/latest.json" <<'PY'
import json
import pathlib
import sys

record = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert record["run"]["outcome"] == "failed"
assert record["failures"] == [
    "udp: no comparable ranking",
    "tcp: no comparable ranking",
    "doh: no comparable ranking",
    "dot: no comparable ranking",
    "doq: no comparable ranking",
]
assert all(item["status"] == "failed" for item in record["transports"])
assert all(item["status"] == "failed" and item["winner"] is None for item in record["summary"])
PY

cp -R "${temporary_dir}/original-evidence" "${temporary_dir}/failed-evidence"
python3 - "${temporary_dir}/failed-evidence" <<'PY'
import pathlib
import sys

evidence = pathlib.Path(sys.argv[1])
(evidence / "failures.txt").write_text("doq (quic): exhausted 3 attempts\n", encoding="utf-8")
PY
export SPEEDNS_RESULTS_RUN_ID=fixture-failed-run
python3 "${root_dir}/scripts/publish-live-results.py" \
	--evidence-dir "${temporary_dir}/failed-evidence" \
	--output-dir "${temporary_dir}/failed-results"
validate_record "${temporary_dir}/failed-results"
python3 - "${temporary_dir}/failed-results/latest.json" <<'PY'
import json
import pathlib
import sys

record = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert record["run"]["outcome"] == "failed"
assert record["failures"] == ["doq (quic): exhausted 3 attempts"]
PY

echo "publish live results fixture passed"
