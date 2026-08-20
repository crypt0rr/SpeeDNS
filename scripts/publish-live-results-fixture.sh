#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary_dir="$(mktemp -d)"
trap 'rm -rf "${temporary_dir}"' EXIT

evidence_dir="${temporary_dir}/evidence"
results_dir="${temporary_dir}/results"
mkdir -p "${evidence_dir}"

python3 - "${evidence_dir}" <<'PY'
import json
import pathlib
import sys

output = pathlib.Path(sys.argv[1])
endpoints = {
    "udp": {"address": "8.8.8.8"},
    "tcp": {"address": "8.8.8.8"},
    "doh": {
        "address": "dns.google",
        "endpoint_url": "https://dns.google/dns-query",
        "tls_server_name": "dns.google",
    },
    "dot": {"address": "dns.google", "tls_server_name": "dns.google"},
    "doq": {"address": "dns.quad9.net", "tls_server_name": "dns.quad9.net"},
}
protocols = list(endpoints)
for protocol, endpoint in endpoints.items():
    target = {
        "id": f"fixture-{protocol}",
        "name": "Fixture resolver",
        "owner": "Fixture <script>",
        "policy": "unfiltered & <test>",
        "address": endpoint["address"],
        "protocol": protocol,
        **endpoint,
    }
    stats = {
        "total": 1,
        "successes": 1,
        "failures": 0,
        "usable_responses": 1,
        "resolver_failures": 0,
        "scored": 1,
        "divergent": 0,
        "truncated": 0,
        "reconnects": 0,
        "success_rate": 1.0,
        "failure_rate": 0.0,
        "usable_rate": 1.0,
        "resolver_failure_rate": 0.0,
        "scoring_failure_rate": 0.0,
        "median_ms": 12.34,
        "p95_ms": 15.67,
        "min_ms": 10.0,
        "max_ms": 17.0,
        "mad_ms": 1.0,
        "cold_median_ms": 20.0,
        "score_ms": 13.67,
        "ci_low_ms": 11.0,
        "ci_high_ms": 16.0,
        "recommended": True,
        "tie": False,
    }
    report = {
        "schema_version": 1,
        "run": {
            "started_at": "2026-01-02T03:00:00.000Z",
            "finished_at": "2026-01-02T03:00:01.000Z",
            "seed": 42,
            "corpus_mode": "warm-cache",
            "corpus_zone": "",
            "sample_size": 1,
            "queries_per_target": 1,
            "query_types": [1],
            "provenance": {
                "speedns_version": "fixture",
                "commit": "0123456789abcdef0123456789abcdef01234567",
                "build_date": "fixture",
                "os": "linux",
                "architecture": "amd64",
                "interfaces": [],
                "protocols": [protocol],
                "corpus_entries": 1000,
                "corpus_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "timeout_ms": 5000,
                "concurrency": 1,
                "duration_ms": 1000.0,
            },
        },
        "results": [{"target": target, "stats": stats}],
        "rankings": [{"protocol": protocol, "target_id": target["id"], "rank": 1, "tie": False}],
        "warnings": [],
    }
    (output / f"{protocol}.json").write_text(json.dumps(report) + "\n", encoding="utf-8")
PY
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
python3 - "${results_dir}/latest.json" <<'PY'
import json
import pathlib
import sys

record = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert record["run"]["outcome"] == "passed"
assert record["run"]["seed"] == 42
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

cp -R "${temporary_dir}/original-evidence" "${temporary_dir}/no-comparable-evidence"
python3 - "${temporary_dir}/no-comparable-evidence/doq.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
report = json.loads(path.read_text(encoding="utf-8"))
stats = report["results"][0]["stats"]
stats.update(
    {
        "successes": 0,
        "failures": 1,
        "usable_responses": 0,
        "resolver_failures": 0,
        "scored": 0,
        "success_rate": 0.0,
        "failure_rate": 1.0,
        "usable_rate": 0.0,
        "resolver_failure_rate": 0.0,
        "scoring_failure_rate": 1.0,
        "median_ms": 0.0,
        "p95_ms": 0.0,
        "min_ms": 0.0,
        "max_ms": 0.0,
        "mad_ms": 0.0,
        "cold_median_ms": 0.0,
        "score_ms": 0.0,
        "ci_low_ms": 0.0,
        "ci_high_ms": 0.0,
        "recommended": False,
        "tie": False,
    }
)
report["rankings"] = []
path.write_text(json.dumps(report) + "\n", encoding="utf-8")
PY
export SPEEDNS_RESULTS_RUN_ID=fixture-no-comparable-run
python3 "${root_dir}/scripts/publish-live-results.py" \
	--evidence-dir "${temporary_dir}/no-comparable-evidence" \
	--output-dir "${temporary_dir}/no-comparable-results"
python3 - "${temporary_dir}/no-comparable-results/latest.json" <<'PY'
import json
import pathlib
import sys

record = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert record["run"]["outcome"] == "failed"
assert record["failures"] == ["doq: no comparable ranking"]
assert record["summary"][-1]["status"] == "failed"
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
python3 - "${temporary_dir}/failed-results/latest.json" <<'PY'
import json
import pathlib
import sys

record = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert record["run"]["outcome"] == "failed"
assert record["failures"] == ["doq (quic): exhausted 3 attempts"]
PY

echo "publish live results fixture passed"
