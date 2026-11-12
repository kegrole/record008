"""Minimal urllib-based HTTP client used by the scanner.

Only the Python standard library is used.  Each ``get`` call performs exactly
one network request; there is no retry or duplicate-delivery logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, build_opener


class NoRedirectHandler(HTTPRedirectHandler):
    """Prevent urllib from silently issuing extra requests on redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


@dataclass(frozen=True)
class Response:
    url: str
    status: int
    body: str
    headers: Dict[str, str]


class HttpClient:
    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout
        self._opener = build_opener(NoRedirectHandler)
        self.request_log: List[str] = []

    @property
    def request_count(self) -> int:
        return len(self.request_log)

    @staticmethod
    def _encode_query_value(value: str) -> str:
        """Encode every non-alphanumeric character for safe query transport."""

        return quote(value, safe="")

    def build_url(self, base_url: str, path: str, param: str, value: str) -> str:
        query = f"{quote(param, safe='')}={self._encode_query_value(value)}"
        parts = urlsplit(base_url)
        return urlunsplit((parts.scheme, parts.netloc, path, query, ""))

    def get(self, base_url: str, path: str, param: str, value: str) -> Response:
        url = self.build_url(base_url, path, param, value)
        self.request_log.append(url)
        try:
            with self._opener.open(url, timeout=self.timeout) as handle:
                raw = handle.read()
                charset = handle.headers.get_content_charset() or "utf-8"
                headers = {key: value for key, value in handle.headers.items()}
                return Response(
                    url=url,
                    status=handle.status,
                    body=raw.decode(charset, errors="replace"),
                    headers=headers,
                )
        except Exception as exc:  # network/protocol failures stay inconclusive
            body = f"[request-error] {type(exc).__name__}: {exc}"
            status = getattr(exc, "code", 0) or 0
            return Response(url=url, status=int(status), body=body, headers={})
