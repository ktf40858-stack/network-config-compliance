"""Evaluate declarative compliance checks against a parsed IOS configuration.

A check is data, not code: adding a CIS or STIG control means adding an entry to a
YAML file, not writing Python. That is deliberate — the people who own the benchmark
are usually not the people who own the tool.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from .parser import IOSConfig


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    NOT_APPLICABLE = "N/A"


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"high": 0, "medium": 1, "low": 2}[self.value]


@dataclass
class Check:
    id: str
    title: str
    severity: Severity
    match_type: str
    rationale: str = ""
    remediation: str = ""
    references: list[str] | None = None
    pattern: str = ""
    block_pattern: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Check":
        match = data.get("match", {})
        return cls(
            id=data["id"],
            title=data["title"],
            severity=Severity(data.get("severity", "medium")),
            rationale=data.get("rationale", ""),
            remediation=data.get("remediation", ""),
            references=data.get("references", []),
            match_type=match["type"],
            pattern=match.get("pattern", ""),
            block_pattern=match.get("block_pattern", ""),
        )


@dataclass
class Result:
    check: Check
    status: Status
    evidence: str = ""

    @property
    def failed(self) -> bool:
        return self.status is Status.FAIL


class Benchmark:
    """A named collection of checks loaded from one YAML file."""

    def __init__(self, name: str, version: str, checks: list[Check]) -> None:
        self.name = name
        self.version = version
        self.checks = checks

    @classmethod
    def from_file(cls, path: str | Path) -> "Benchmark":
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        meta = data.get("metadata", {})
        return cls(
            name=meta.get("name", Path(path).stem),
            version=str(meta.get("version", "0")),
            checks=[Check.from_dict(item) for item in data.get("checks", [])],
        )


class Engine:
    """Runs checks. Each ``match.type`` maps to one method here."""

    def __init__(self, config: IOSConfig) -> None:
        self.config = config

    def run(self, benchmark: Benchmark) -> list[Result]:
        return [self._run_one(check) for check in benchmark.checks]

    def _run_one(self, check: Check) -> Result:
        handler = getattr(self, f"_check_{check.match_type}", None)
        if handler is None:
            return Result(check, Status.ERROR, f"unknown match type '{check.match_type}'")
        try:
            return handler(check)
        except re.error as exc:
            return Result(check, Status.ERROR, f"invalid pattern: {exc}")

    # -- match types --------------------------------------------------------

    def _check_global_present(self, check: Check) -> Result:
        """The configuration must contain a top-level line matching the pattern."""
        hits = self.config.find_global(check.pattern)
        if hits:
            return Result(check, Status.PASS, f"line {hits[0].lineno}: {hits[0].text}")
        return Result(check, Status.FAIL, "no matching global line")

    def _check_global_absent(self, check: Check) -> Result:
        """The configuration must NOT contain a top-level line matching the pattern."""
        hits = self.config.find_global(check.pattern)
        if not hits:
            return Result(check, Status.PASS, "not present")
        found = "; ".join(f"line {h.lineno}: {h.text}" for h in hits[:3])
        return Result(check, Status.FAIL, found)

    def _check_anywhere_absent(self, check: Check) -> Result:
        """The pattern must not appear anywhere, at any nesting level."""
        hits = self.config.find(check.pattern)
        if not hits:
            return Result(check, Status.PASS, "not present")
        found = "; ".join(f"line {h.lineno}: {h.text}" for h in hits[:3])
        return Result(check, Status.FAIL, found)

    def _check_block_present(self, check: Check) -> Result:
        """Every block matching ``block_pattern`` must contain ``pattern``.

        Returns N/A when no block matches, so a switch is not marked non-compliant
        for a router-only control.
        """
        blocks = self.config.blocks(check.block_pattern)
        if not blocks:
            return Result(check, Status.NOT_APPLICABLE, "no matching block in this config")

        offenders = [b for b in blocks if not b.find_children(check.pattern)]
        if not offenders:
            return Result(check, Status.PASS, f"{len(blocks)} block(s) compliant")
        names = ", ".join(b.text for b in offenders[:5])
        more = f" (+{len(offenders) - 5} more)" if len(offenders) > 5 else ""
        return Result(check, Status.FAIL, f"missing in: {names}{more}")

    def _check_block_absent(self, check: Check) -> Result:
        """No block matching ``block_pattern`` may contain ``pattern``."""
        blocks = self.config.blocks(check.block_pattern)
        if not blocks:
            return Result(check, Status.NOT_APPLICABLE, "no matching block in this config")

        offenders = [b for b in blocks if b.find_children(check.pattern)]
        if not offenders:
            return Result(check, Status.PASS, f"{len(blocks)} block(s) compliant")
        names = ", ".join(b.text for b in offenders[:5])
        more = f" (+{len(offenders) - 5} more)" if len(offenders) > 5 else ""
        return Result(check, Status.FAIL, f"present in: {names}{more}")
