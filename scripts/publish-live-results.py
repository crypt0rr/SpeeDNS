#!/usr/bin/env python3
"""Validate live smoke reports and build a small static results site.

The live smoke workflow deliberately keeps this publisher dependency-free. It
accepts one JSON report for each transport, rejects incomplete or unsafe
evidence, and writes immutable run records plus a Pages-ready index.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import math
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any


PROTOCOLS = ("udp", "tcp", "doh", "dot", "doq")
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schema" / "live-results-v1.json"
OFFICIAL_ENDPOINTS = {
    "udp": {"resolver": "google", "uri": "udp://8.8.8.8:53", "address": "8.8.8.8"},
    "tcp": {"resolver": "google", "uri": "tcp://8.8.8.8:53", "address": "8.8.8.8"},
    "doh": {
        "resolver": "google",
        "uri": "https://dns.google/dns-query",
        "address": "dns.google",
        "endpoint_url": "https://dns.google/dns-query",
        "tls_server_name": "dns.google",
    },
    "dot": {
        "resolver": "google",
        "uri": "tls://dns.google:853",
        "address": "dns.google",
        "tls_server_name": "dns.google",
    },
    "doq": {
        "resolver": "quad9",
        "uri": "quic://dns.quad9.net:853",
        "address": "dns.quad9.net",
        "tls_server_name": "dns.quad9.net",
    },
}
STAT_KEYS = (
    "total",
    "successes",
    "failures",
    "usable_responses",
    "resolver_failures",
    "scored",
    "divergent",
    "truncated",
    "reconnects",
    "success_rate",
    "failure_rate",
    "usable_rate",
    "resolver_failure_rate",
    "scoring_failure_rate",
    "median_ms",
    "p95_ms",
    "min_ms",
    "max_ms",
    "mad_ms",
    "cold_median_ms",
    "score_ms",
    "ci_low_ms",
    "ci_high_ms",
    "recommended",
    "tie",
)
INTEGER_STATS = {
    "total",
    "successes",
    "failures",
    "usable_responses",
    "resolver_failures",
    "scored",
    "divergent",
    "truncated",
    "reconnects",
}
BOOLEAN_STATS = {"recommended", "tie"}
LOCAL_PATH = re.compile(r"(?i)(/home/|/tmp/|runner\.temp|speedns[_-]smoke|\\users\\)")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
SAFE_COMMIT = re.compile(r"^(?:[0-9a-fA-F]{7,64}|dev|unknown)$")
SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
MAX_REPORT_BYTES = 4 * 1024 * 1024
MAX_FAILURE_BYTES = 64 * 1024
MAX_FAILURE_LINES = 100
MAX_FAILURE_LINE = 512


class PublishError(Exception):
    """A user-actionable validation or publication error."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PublishError(message)


def require_dict(value: Any, name: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{name} must be an object")
    return value


def require_list(value: Any, name: str) -> list[Any]:
    require(isinstance(value, list), f"{name} must be an array")
    return value


def require_string(value: Any, name: str, allow_empty: bool = False) -> str:
    require(isinstance(value, str), f"{name} must be a string")
    if not allow_empty:
        require(bool(value.strip()), f"{name} must not be empty")
    return value


def require_integer(value: Any, name: str) -> int:
    require(isinstance(value, int) and not isinstance(value, bool), f"{name} must be an integer")
    return value


def require_number(value: Any, name: str) -> float | int:
    require(
        isinstance(value, (int, float)) and not isinstance(value, bool),
        f"{name} must be a number",
    )
    require(math.isfinite(float(value)), f"{name} must be finite")
    return value


def parse_timestamp(value: Any, name: str) -> dt.datetime:
    raw = require_string(value, name)
    try:
        parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PublishError(f"{name} is not an ISO-8601 timestamp") from exc
    require(parsed.tzinfo is not None, f"{name} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def timestamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def reject_local_paths(value: Any, path: str = "report") -> None:
    if isinstance(value, str):
        require(not LOCAL_PATH.search(value), f"{path} contains a local path")
    elif isinstance(value, dict):
        for key, child in value.items():
            reject_local_paths(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_local_paths(child, f"{path}[{index}]")


def read_json(path: Path) -> dict[str, Any]:
    require(path.is_file(), f"missing evidence file: {path.name}")
    require(path.stat().st_size <= MAX_REPORT_BYTES, f"evidence file is too large: {path.name}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublishError(f"invalid JSON evidence in {path.name}") from exc
    report = require_dict(data, f"{path.name} root")
    reject_local_paths(report)
    return report


def validate_stats(stats: dict[str, Any], protocol: str) -> None:
    for key in STAT_KEYS:
        require(key in stats, f"{protocol}: stats.{key} is missing")
        if key in INTEGER_STATS:
            value = require_integer(stats[key], f"{protocol}: stats.{key}")
            require(value >= 0, f"{protocol}: stats.{key} cannot be negative")
        elif key in BOOLEAN_STATS:
            require(isinstance(stats[key], bool), f"{protocol}: stats.{key} must be boolean")
        else:
            value = require_number(stats[key], f"{protocol}: stats.{key}")
            require(float(value) >= 0, f"{protocol}: stats.{key} cannot be negative")
    for key in ("success_rate", "failure_rate", "usable_rate", "resolver_failure_rate", "scoring_failure_rate"):
        require(0 <= float(stats[key]) <= 1, f"{protocol}: stats.{key} must be between zero and one")
    require(stats["total"] > 0, f"{protocol}: stats.total must be greater than zero")
    require(stats["successes"] + stats["failures"] == stats["total"], f"{protocol}: success/failure counts do not add up")
    require(stats["usable_responses"] <= stats["successes"], f"{protocol}: usable responses exceed successes")
    require(stats["scored"] <= stats["usable_responses"], f"{protocol}: scored samples exceed usable responses")


def validate_report(report: dict[str, Any], protocol: str) -> dict[str, Any]:
    require(report.get("schema_version") == 1, f"{protocol}: unsupported report schema")
    run = require_dict(report.get("run"), f"{protocol}: run")
    started = parse_timestamp(run.get("started_at"), f"{protocol}: run.started_at")
    finished = parse_timestamp(run.get("finished_at"), f"{protocol}: run.finished_at")
    require(finished >= started, f"{protocol}: run finished before it started")
    seed = require_integer(run.get("seed"), f"{protocol}: run.seed")
    sample_size = require_integer(run.get("sample_size"), f"{protocol}: run.sample_size")
    require(sample_size > 0, f"{protocol}: run.sample_size must be positive")
    query_types = require_list(run.get("query_types"), f"{protocol}: run.query_types")
    require(query_types, f"{protocol}: run.query_types must not be empty")
    for index, query_type in enumerate(query_types):
        value = require_integer(query_type, f"{protocol}: run.query_types[{index}]")
        require(1 <= value <= 65535, f"{protocol}: run.query_types[{index}] is invalid")

    provenance = require_dict(run.get("provenance"), f"{protocol}: run.provenance")
    provenance_protocols = require_list(provenance.get("protocols"), f"{protocol}: provenance.protocols")
    require(protocol in provenance_protocols, f"{protocol}: provenance does not identify this protocol")
    corpus_entries = require_integer(provenance.get("corpus_entries"), f"{protocol}: provenance.corpus_entries")
    require(corpus_entries > 0, f"{protocol}: provenance.corpus_entries must be positive")
    corpus_sha256 = require_string(provenance.get("corpus_sha256"), f"{protocol}: provenance.corpus_sha256")
    require(SHA256.fullmatch(corpus_sha256) is not None, f"{protocol}: provenance.corpus_sha256 is invalid")
    commit = require_string(provenance.get("commit"), f"{protocol}: provenance.commit")
    require(SAFE_COMMIT.fullmatch(commit) is not None, f"{protocol}: provenance.commit is unsafe")
    require_integer(provenance.get("timeout_ms"), f"{protocol}: provenance.timeout_ms")
    require_integer(provenance.get("concurrency"), f"{protocol}: provenance.concurrency")

    results = require_list(report.get("results"), f"{protocol}: results")
    require(len(results) == 1, f"{protocol}: expected one endpoint result")
    result = require_dict(results[0], f"{protocol}: results[0]")
    require("samples" not in result and "cold" not in result, f"{protocol}: raw observations are not publishable")
    target = require_dict(result.get("target"), f"{protocol}: result.target")
    target_id = require_string(target.get("id"), f"{protocol}: target.id")
    require_string(target.get("name"), f"{protocol}: target.name")
    require_string(target.get("owner"), f"{protocol}: target.owner")
    require_string(target.get("policy"), f"{protocol}: target.policy")
    address = require_string(target.get("address"), f"{protocol}: target.address")
    require(target.get("protocol") == protocol, f"{protocol}: target protocol does not match file name")
    expected = OFFICIAL_ENDPOINTS[protocol]
    require(address == expected["address"], f"{protocol}: target address is not the official smoke endpoint")
    if "endpoint_url" in expected:
        require(target.get("endpoint_url") == expected["endpoint_url"], f"{protocol}: endpoint URL is not official")
    if "tls_server_name" in expected:
        require(target.get("tls_server_name") == expected["tls_server_name"], f"{protocol}: TLS name is not official")
    stats = require_dict(result.get("stats"), f"{protocol}: result.stats")
    validate_stats(stats, protocol)
    open_error = result.get("open_error", "")
    require_string(open_error, f"{protocol}: result.open_error", allow_empty=True)
    incomplete = result.get("incomplete", False)
    require(isinstance(incomplete, bool), f"{protocol}: result.incomplete must be boolean")

    rankings = require_list(report.get("rankings"), f"{protocol}: rankings")
    require(len(rankings) <= 1, f"{protocol}: single-endpoint evidence cannot contain multiple rankings")
    for index, ranking in enumerate(rankings):
        ranking = require_dict(ranking, f"{protocol}: rankings[{index}]")
        require(ranking.get("protocol") == protocol, f"{protocol}: ranking protocol does not match")
        require(ranking.get("target_id") == target_id, f"{protocol}: ranking target does not match the measured endpoint")
        rank = require_integer(ranking.get("rank"), f"{protocol}: ranking.rank")
        require(rank == 1, f"{protocol}: single-endpoint ranking must be rank one")
        require(isinstance(ranking.get("tie"), bool), f"{protocol}: ranking.tie must be boolean")
        require(not incomplete and stats["scored"] > 0, f"{protocol}: an incomplete or unscored result cannot be ranked")
    warnings = require_list(report.get("warnings", []), f"{protocol}: warnings")
    for index, warning in enumerate(warnings):
        warning = require_string(warning, f"{protocol}: warnings[{index}]")
        require(len(warning) <= MAX_FAILURE_LINE, f"{protocol}: warning is too long")
    return {
        "protocol": protocol,
        "path": str(target_id),
        "report": report,
        "run": run,
        "started": started,
        "finished": finished,
        "provenance": provenance,
        "result": result,
        "target": target,
        "stats": stats,
        "rankings": rankings,
        "warnings": warnings,
        "seed": seed,
        "sample_size": sample_size,
        "query_types": query_types,
    }


def read_failures(evidence_dir: Path) -> list[str]:
    path = evidence_dir / "failures.txt"
    if not path.exists():
        return []
    require(path.is_file(), "failures.txt is not a regular file")
    require(path.stat().st_size <= MAX_FAILURE_BYTES, "failures.txt is too large")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise PublishError("failures.txt is not valid UTF-8") from exc
    require(len(lines) <= MAX_FAILURE_LINES, "failures.txt has too many lines")
    cleaned = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        require(len(line) <= MAX_FAILURE_LINE, "a failures.txt line is too long")
        require(not LOCAL_PATH.search(line), "failures.txt contains a local path")
        cleaned.append(line)
    return cleaned


def compact_stats(stats: dict[str, Any]) -> dict[str, Any]:
    return {
        key: stats[key]
        for key in (
            "total",
            "successes",
            "failures",
            "usable_responses",
            "resolver_failures",
            "scored",
            "divergent",
            "truncated",
            "success_rate",
            "usable_rate",
            "median_ms",
            "p95_ms",
            "mad_ms",
            "cold_median_ms",
            "score_ms",
            "ci_low_ms",
            "ci_high_ms",
            "recommended",
            "tie",
        )
    }


def endpoint_view(item: dict[str, Any]) -> dict[str, Any]:
    target = item["target"]
    return {
        "target_id": target["id"],
        "name": target["name"],
        "owner": target["owner"],
        "policy": target["policy"],
        "address": target["address"],
        "endpoint_url": target.get("endpoint_url", ""),
        "tls_server_name": target.get("tls_server_name", ""),
    }


def build_record(items: list[dict[str, Any]], failure_lines: list[str]) -> dict[str, Any]:
    first = items[0]
    for item in items[1:]:
        require(item["seed"] == first["seed"], "reports use different seeds")
        require(item["sample_size"] == first["sample_size"], "reports use different sample sizes")
        require(item["query_types"] == first["query_types"], "reports use different query types")
        for key in ("corpus_entries", "corpus_sha256"):
            require(item["provenance"].get(key) == first["provenance"].get(key), f"reports use different corpus {key}")

    source_commit = os.environ.get("GITHUB_SHA", first["provenance"]["commit"])
    require(SAFE_COMMIT.fullmatch(source_commit) is not None, "source commit is unsafe")
    repository = os.environ.get("GITHUB_REPOSITORY", "local")
    require(1 <= len(repository) <= 200 and not LOCAL_PATH.search(repository), "repository name is unsafe")
    ref = os.environ.get("GITHUB_REF_NAME", "local")
    require(1 <= len(ref) <= 200 and not LOCAL_PATH.search(ref), "ref name is unsafe")
    workflow_run_id = os.environ.get("GITHUB_RUN_ID", "local")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    if workflow_run_id == "local":
        run_id = os.environ.get("SPEEDNS_RESULTS_RUN_ID", "local-run")
    else:
        require(workflow_run_id.isdigit(), "workflow run id is invalid")
        require(attempt.isdigit() and int(attempt) > 0, "workflow run attempt is invalid")
        run_id = f"{workflow_run_id}-attempt-{attempt}"
    require(SAFE_ID.fullmatch(run_id) is not None, "results run id is unsafe")
    published_raw = os.environ.get("SPEEDNS_RESULTS_PUBLISHED_AT")
    if published_raw:
        published_at = timestamp(parse_timestamp(published_raw, "published timestamp"))
    else:
        published_at = timestamp(dt.datetime.now(dt.timezone.utc))

    warnings: list[str] = []
    transports: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    derived_failures = list(failure_lines)
    for item in items:
        protocol = item["protocol"]
        stats = item["stats"]
        rankings = item["rankings"]
        rank_one = next((ranking for ranking in rankings if ranking["rank"] == 1), None)
        if rank_one is None:
            derived_failures.append(f"{protocol}: no comparable ranking")
        if stats["recommended"]:
            status = "recommended"
        elif stats["scored"] > 0:
            status = "measured"
        elif stats["successes"] > 0:
            status = "ineligible"
        else:
            status = "failed"
        transports.append(
            {
                "protocol": protocol,
                "status": status,
                "endpoint": endpoint_view(item),
                "stats": compact_stats(stats),
            }
        )
        winner = endpoint_view(item) if rank_one else None
        summary_status = "recommended" if stats["recommended"] else ("provisional" if rank_one else "failed")
        summaries.append(
            {
                "protocol": protocol,
                "status": summary_status,
                "winner": winner,
                "stats": compact_stats(stats),
            }
        )
        warnings.extend(f"{protocol}: {warning}" for warning in item["warnings"])

    unique_failures = list(dict.fromkeys(derived_failures))
    unique_warnings = list(dict.fromkeys(warnings))
    outcome = "passed" if not unique_failures else "failed"
    first_provenance = first["provenance"]
    commands = {
        protocol: [
            "speedns",
            "--no-defaults",
            "--protocol",
            protocol,
            "--resolver",
            f"{OFFICIAL_ENDPOINTS[protocol]['resolver']}={OFFICIAL_ENDPOINTS[protocol]['uri']}",
            "--sample",
            str(first["sample_size"]),
            "--type",
            ",".join("A" if value == 1 else "AAAA" if value == 28 else str(value) for value in first["query_types"]),
            "--seed",
            str(first["seed"]),
            "--timeout",
            f"{first_provenance['timeout_ms']}ms",
            "--concurrency",
            str(first_provenance["concurrency"]),
            "--format",
            "json",
        ]
        for protocol in PROTOCOLS
    }
    return {
        "schema_version": 1,
        "run": {
            "id": run_id,
            "outcome": outcome,
            "published_at": published_at,
            "started_at": timestamp(min(item["started"] for item in items)),
            "finished_at": timestamp(max(item["finished"] for item in items)),
            "seed": first["seed"],
            "sample_size": first["sample_size"],
            "query_types": first["query_types"],
            "protocols": list(PROTOCOLS),
            "source": {
                "repository": repository,
                "commit": source_commit,
                "ref": ref,
                "workflow_run_id": workflow_run_id,
                "workflow_run_attempt": attempt,
                "workflow_run_number": os.environ.get("GITHUB_RUN_NUMBER", "local"),
            },
            "corpus": {
                "entries": first_provenance["corpus_entries"],
                "sha256": first_provenance["corpus_sha256"],
                "mode": first["run"].get("corpus_mode", ""),
                "zone": first["run"].get("corpus_zone", ""),
            },
            "commands": commands,
        },
        "transports": transports,
        "summary": summaries,
        "warnings": unique_warnings,
        "failures": unique_failures,
    }


def load_history(output_dir: Path) -> list[dict[str, Any]]:
    runs_dir = output_dir / "runs"
    if not runs_dir.exists():
        return []
    records = []
    for path in sorted(runs_dir.glob("*.json")):
        require(path.stat().st_size <= MAX_REPORT_BYTES, f"historical record is too large: {path.name}")
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PublishError(f"invalid historical record: {path.name}") from exc
        record = require_dict(record, f"historical record {path.name}")
        require(record.get("schema_version") == 1, f"unsupported historical record: {path.name}")
        run = require_dict(record.get("run"), f"historical record {path.name}.run")
        run_id = require_string(run.get("id"), f"historical record {path.name}.run.id")
        require(SAFE_ID.fullmatch(run_id) is not None, f"unsafe historical run id: {path.name}")
        parse_timestamp(run.get("published_at"), f"historical record {path.name}.run.published_at")
        reject_local_paths(record, f"historical record {path.name}")
        records.append(record)
    return sorted(records, key=lambda record: record["run"]["published_at"])


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def write_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
            temporary = handle.name
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def write_immutable_record(path: Path, record: dict[str, Any]) -> None:
    content = json_bytes(record)
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PublishError(f"existing run record is invalid: {path.name}") from exc
        require(existing == record, f"immutable run record already exists with different content: {path.name}")
        return
    write_atomic(path, content)


def text(value: Any) -> str:
    return html.escape(str(value), quote=True)


def metric(stats: dict[str, Any], key: str, suffix: str = "") -> str:
    value = stats.get(key)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f"{value:.2f}{suffix}"
    return "—"


def render_index(records: list[dict[str, Any]]) -> str:
    latest = records[-1]
    latest_run = latest["run"]
    latest_summary = latest.get("summary", [])
    summary_rows = []
    for item in latest_summary:
        winner = item.get("winner") or {}
        stats = item.get("stats") or {}
        summary_rows.append(
            "<tr>"
            f"<td>{text(item.get('protocol', ''))}</td>"
            f"<td>{text(item.get('status', ''))}</td>"
            f"<td>{text(winner.get('owner', '—'))}</td>"
            f"<td>{text(winner.get('address', '—'))}</td>"
            f"<td>{text(winner.get('policy', '—'))}</td>"
            f"<td>{text(metric(stats, 'median_ms', ' ms'))}</td>"
            f"<td>{text(metric(stats, 'p95_ms', ' ms'))}</td>"
            f"<td>{text(metric(stats, 'success_rate'))}</td>"
            f"<td>{text(metric(stats, 'score_ms', ' ms'))}</td>"
            "</tr>"
        )
    history_rows = []
    for record in reversed(records):
        run = record["run"]
        failures = len(record.get("failures", []))
        history_rows.append(
            "<tr>"
            f"<td><a href=\"{text('runs/' + run['id'] + '.json')}\">{text(run['id'])}</a></td>"
            f"<td>{text(run.get('published_at', ''))}</td>"
            f"<td>{text(run.get('outcome', ''))}</td>"
            f"<td>{text(run.get('commit', run.get('source', {}).get('commit', '')))}</td>"
            f"<td>{text(failures)}</td>"
            "</tr>"
        )
    warnings = latest.get("warnings", [])
    failures = latest.get("failures", [])
    diagnostics = ""
    if warnings:
        diagnostics += "<h2>Warnings</h2><ul>" + "".join(f"<li>{text(value)}</li>" for value in warnings) + "</ul>"
    if failures:
        diagnostics += "<h2>Failures</h2><ul>" + "".join(f"<li>{text(value)}</li>" for value in failures) + "</ul>"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SpeeDNS live DNS results</title>
<style>
body {{ font: 16px/1.5 system-ui, sans-serif; margin: 2rem auto; max-width: 1100px; padding: 0 1rem; color: #202124; }}
h1 {{ margin-bottom: .25rem; }}
table {{ border-collapse: collapse; margin: 1rem 0 2rem; width: 100%; }}
th, td {{ border-bottom: 1px solid #ddd; padding: .45rem .6rem; text-align: left; white-space: nowrap; }}
th {{ background: #f5f5f5; }}
small {{ color: #666; }}
code {{ word-break: break-all; }}
</style>
</head>
<body>
<h1>SpeeDNS live DNS results</h1>
<p>Latest complete scheduled smoke run: <strong>{text(latest_run.get('outcome', ''))}</strong> at {text(latest_run.get('published_at', ''))}.</p>
<p><small>Source: <code>{text(latest_run.get('source', {}).get('repository', ''))}@{text(latest_run.get('source', {}).get('commit', ''))}</code></small></p>
<h2>Latest comparison</h2>
<table>
<thead><tr><th>Protocol</th><th>Status</th><th>Owner</th><th>Address</th><th>Policy</th><th>Median</th><th>P95</th><th>Success</th><th>Score</th></tr></thead>
<tbody>{''.join(summary_rows)}</tbody>
</table>
{diagnostics}
<h2>Recent runs</h2>
<table>
<thead><tr><th>Run</th><th>Published</th><th>Outcome</th><th>Commit</th><th>Failures</th></tr></thead>
<tbody>{''.join(history_rows)}</tbody>
</table>
<p><a href="latest.json">Download latest.json</a> · Generated by the SpeeDNS live smoke workflow.</p>
</body>
</html>
"""


def update_site(output_dir: Path, record: dict[str, Any]) -> None:
    runs_dir = output_dir / "runs"
    run_path = runs_dir / f"{record['run']['id']}.json"
    write_immutable_record(run_path, record)
    records = load_history(output_dir)
    write_atomic(output_dir / "latest.json", json_bytes(records[-1]))
    write_atomic(output_dir / "index.html", render_index(records[-100:]).encode("utf-8"))
    require(SCHEMA_PATH.is_file(), "live-results schema is missing from the source checkout")
    write_atomic(output_dir / "live-results-v1.schema.json", SCHEMA_PATH.read_bytes())
    write_atomic(output_dir / ".nojekyll", b"")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        require(args.evidence_dir.is_dir(), "evidence directory does not exist")
        items = []
        for protocol in PROTOCOLS:
            items.append(validate_report(read_json(args.evidence_dir / f"{protocol}.json"), protocol))
        record = build_record(items, read_failures(args.evidence_dir))
        update_site(args.output_dir, record)
    except PublishError as exc:
        print(f"publish-live-results: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"publish-live-results: filesystem error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
