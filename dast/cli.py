"""Command-line entry point: ``python -m dast.cli --target URL --out PATH``."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List, Optional, Sequence

from .client import HttpClient
from .detectors import Endpoint, load_endpoints, scan
from .payloads import load_payloads
from .report import build_report, summary_line, write_report


DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "fixtures" / "mock_config.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Standard-library-only dynamic injection detector (DAST)."
    )
    parser.add_argument("--target", required=True, help="Base URL of the target service.")
    parser.add_argument("--out", required=True, help="Path of the JSON report to write.")
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG),
        help="Mock service/endpoint configuration JSON (default: fixtures/mock_config.json).",
    )
    return parser


def run(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    with Path(args.config).open("r", encoding="utf-8") as handle:
        config = json.load(handle)

    endpoints: List[Endpoint] = load_endpoints(config)
    payloads = load_payloads()
    client = HttpClient()
    findings = scan(args.target.rstrip("/"), endpoints, payloads=payloads, client=client)

    report = build_report(findings, endpoint_count=len(endpoints), request_count=client.request_count)
    write_report(report, args.out)
    print(summary_line(report), flush=True)
    return 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
