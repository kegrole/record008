"""Payload catalogue loading.

The catalogue lives in ``fixtures/payloads.json`` so that the detector and the
mock service share one source of truth instead of hard-coding strings.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List


DEFAULT_PAYLOAD_FILE = Path(__file__).resolve().parent.parent / "fixtures" / "payloads.json"


@dataclass(frozen=True)
class Payload:
    family: str
    value: str
    result_features: List[str]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "family": self.family,
            "value": self.value,
            "result_features": list(self.result_features),
        }


def load_payloads(path: str | Path | None = None) -> List[Payload]:
    """Load every payload family from the JSON fixture in catalogue order."""

    fixture_path = Path(path) if path is not None else DEFAULT_PAYLOAD_FILE
    with fixture_path.open("r", encoding="utf-8") as handle:
        catalogue = json.load(handle)

    payloads: List[Payload] = []
    for family_entry in catalogue["families"]:
        family = family_entry["family"]
        for entry in family_entry["payloads"]:
            payloads.append(
                Payload(
                    family=family,
                    value=entry["value"],
                    result_features=list(entry.get("result_features", [])),
                )
            )
    if not payloads:
        raise ValueError("payload catalogue is empty")
    return payloads


def payload_count(path: str | Path | None = None) -> int:
    return len(load_payloads(path))
