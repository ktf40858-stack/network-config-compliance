"""Command line entry point.

    python -m netcompliance --config samples/non-compliant-router.cfg
        --benchmark checks/cis-cisco-ios-l1.yaml --format markdown

Exit codes are chosen for CI: 0 clean, 1 findings, 2 tool error. A pipeline can then
fail a merge request that would ship a non-compliant configuration.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import report
from .engine import Benchmark, Engine, Severity, Status
from .parser import IOSConfig

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netcompliance",
        description="Audit Cisco IOS configurations against CIS and DISA STIG controls.",
    )
    parser.add_argument("--config", required=True, nargs="+", help="running-config file(s)")
    parser.add_argument("--benchmark", required=True, nargs="+", help="benchmark YAML file(s)")
    parser.add_argument("--format", choices=["terminal", "markdown", "json"], default="terminal")
    parser.add_argument("--output", help="write to this file instead of stdout")
    parser.add_argument(
        "--fail-on",
        choices=["high", "medium", "low", "never"],
        default="medium",
        help="minimum severity that makes the run exit non-zero (default: medium)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        benchmarks = [Benchmark.from_file(path) for path in args.benchmark]
    except (OSError, KeyError) as exc:
        print("error: cannot load benchmark: {}".format(exc), file=sys.stderr)
        return EXIT_ERROR

    documents: list[str] = []
    findings: list[Severity] = []

    renderers = {
        "terminal": report.to_terminal,
        "markdown": report.to_markdown,
        "json": report.to_json,
    }

    for config_path in args.config:
        try:
            config = IOSConfig.from_file(config_path)
        except OSError as exc:
            print("error: cannot read {}: {}".format(config_path, exc), file=sys.stderr)
            return EXIT_ERROR

        engine = Engine(config)
        for benchmark in benchmarks:
            results = engine.run(benchmark)
            findings += [r.check.severity for r in results if r.status is Status.FAIL]
            documents.append(renderers[args.format](config.hostname, benchmark, results))

    text = "\n\n".join(documents)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print("written: {}".format(args.output))
    else:
        print(text)

    if args.fail_on == "never" or not findings:
        return EXIT_OK
    threshold = Severity(args.fail_on).rank
    if any(severity.rank <= threshold for severity in findings):
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
