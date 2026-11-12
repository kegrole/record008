"""JSON report serialisation and stdout summary helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from .detectors import Finding


def build_report(findings: List[Finding], endpoint_count: int, request_count: int) -> Dict[str, Any]:
    records = [finding.as_dict() for finding in findings]
    counts = {verdict: 0 for verdict in ("vulnerable", "safe", "inconclusive")}
    for record in records:
        counts[record["verdict"]] += 1
    return {
        "summary": {
            "endpoints": endpoint_count,
            "requests": request_count,
            "records": len(records),
            "verdict_counts": counts,
        },
        "records": records,
    }


def write_report(report: Dict[str, Any], out_path: str | Path) -> Path:
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    return path


def summary_line(report: Dict[str, Any]) -> str:
    summary = report["summary"]
    vulnerable = summary["verdict_counts"]["vulnerable"]
    return (
        f"DAST complete: endpoints={summary['endpoints']} "
        f"requests={summary['requests']} vulnerable={vulnerable}"
    )
