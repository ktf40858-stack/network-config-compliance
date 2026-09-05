"""Render results as Markdown, JSON, or a terminal summary."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .engine import Benchmark, Result, Status


def _counts(results: list[Result]) -> dict[str, int]:
    return {
        "total": len(results),
        "pass": sum(1 for r in results if r.status is Status.PASS),
        "fail": sum(1 for r in results if r.status is Status.FAIL),
        "error": sum(1 for r in results if r.status is Status.ERROR),
        "na": sum(1 for r in results if r.status is Status.NOT_APPLICABLE),
    }


def score(results: list[Result]) -> float:
    """Percentage of applicable checks that pass. N/A is excluded from the base.

    Counting a control as passed because it does not apply is how a compliance
    number ends up meaning nothing.
    """
    applicable = [r for r in results if r.status in (Status.PASS, Status.FAIL)]
    if not applicable:
        return 100.0
    passed = sum(1 for r in applicable if r.status is Status.PASS)
    return round(100.0 * passed / len(applicable), 1)


def to_json(hostname: str, benchmark: Benchmark, results: list[Result]) -> str:
    summary = _counts(results)
    summary["score_percent"] = score(results)
    payload = {
        "hostname": hostname,
        "benchmark": {"name": benchmark.name, "version": benchmark.version},
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": summary,
        "results": [
            {
                "id": r.check.id,
                "title": r.check.title,
                "severity": r.check.severity.value,
                "status": r.status.value,
                "evidence": r.evidence,
                "remediation": r.check.remediation,
                "references": r.check.references or [],
            }
            for r in results
        ],
    }
    return json.dumps(payload, indent=2)


def to_markdown(hostname: str, benchmark: Benchmark, results: list[Result]) -> str:
    counts = _counts(results)
    failures = sorted(
        (r for r in results if r.failed),
        key=lambda r: (r.check.severity.rank, r.check.id),
    )
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    out: list[str] = []
    out.append("# Compliance report - " + hostname)
    out.append("")
    out.append("**Benchmark:** " + benchmark.name + " v" + benchmark.version + "  ")
    out.append("**Generated:** " + stamp + "  ")
    out.append("**Score:** " + str(score(results)) + "% of applicable checks")
    out.append("")
    out.append("| Result | Count |")
    out.append("|---|---|")
    out.append("| Pass | " + str(counts["pass"]) + " |")
    out.append("| **Fail** | **" + str(counts["fail"]) + "** |")
    out.append("| Not applicable | " + str(counts["na"]) + " |")
    out.append("| Error | " + str(counts["error"]) + " |")
    out.append("")

    if failures:
        out.append("## Findings, most severe first")
        out.append("")
        for r in failures:
            out.append("### " + r.check.id + " - " + r.check.title)
            out.append("")
            out.append("**Severity:** " + r.check.severity.value + "  ")
            out.append("**Evidence:** `" + r.evidence + "`")
            out.append("")
            if r.check.rationale:
                out.append(r.check.rationale.strip())
                out.append("")
            if r.check.remediation:
                out.append("**Remediation**")
                out.append("")
                out.append("```")
                out.append(r.check.remediation.strip())
                out.append("```")
                out.append("")
            for ref in r.check.references or []:
                out.append("- " + ref)
            out.append("")
    else:
        out.append("No findings. Every applicable check passed.")
        out.append("")

    out.append("## All checks")
    out.append("")
    out.append("| ID | Check | Severity | Status |")
    out.append("|---|---|---|---|")
    for r in results:
        out.append(
            "| " + r.check.id + " | " + r.check.title + " | "
            + r.check.severity.value + " | " + r.status.value + " |"
        )
    out.append("")
    return "\n".join(out)


def to_terminal(hostname: str, benchmark: Benchmark, results: list[Result]) -> str:
    counts = _counts(results)
    marks = {
        Status.PASS: "[ PASS ]",
        Status.FAIL: "[ FAIL ]",
        Status.ERROR: "[ ERR  ]",
        Status.NOT_APPLICABLE: "[ n/a  ]",
    }

    out = [hostname + " - " + benchmark.name + " v" + benchmark.version, ""]
    for r in results:
        if r.status is Status.PASS:
            continue
        out.append(marks[r.status] + " " + r.check.id.ljust(14) + " " + r.check.title)
        if r.evidence:
            out.append(" " * 24 + r.evidence)
    out.append("")
    out.append(
        "{p} pass, {f} fail, {n} n/a, {e} error - score {s}%".format(
            p=counts["pass"], f=counts["fail"], n=counts["na"],
            e=counts["error"], s=score(results),
        )
    )
    return "\n".join(out)
