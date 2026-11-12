"""Response-based injection detectors with vulnerable/safe/inconclusive verdicts.

The logic is intentionally generic and driven by the shared fixtures:

* ``vulnerable`` requires concrete evidence in the response - either the
  unescaped original payload fragment (case-insensitively, so uppercase/lower
  case mutations are recognised) or a declared injection result feature such
  as ``49``, ``root:x:`` or ``uid=``.
* ``safe`` means the probe was demonstrably neutralised: the endpoint performs
  HTML escaping, or the server explicitly blocked the request (HTTP 400/403).
* everything else is ``inconclusive``; encoding transformations are inspected
  after zero, one and two URL-decoding passes.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from typing import Dict, List, Optional

from .client import HttpClient, Response
from .payloads import Payload, load_payloads
from .variants import Variant, decode_variants, make_variants


VERDICTS = ("vulnerable", "safe", "inconclusive")
BLOCKED_STATUSES = frozenset({400, 403})
MAX_EVIDENCE_CHARS = 120


@dataclass(frozen=True)
class Endpoint:
    name: str
    path: str
    param: str
    behavior: str


@dataclass(frozen=True)
class Finding:
    endpoint: str
    family: str
    variant: str
    verdict: str
    evidence: str

    def as_dict(self) -> Dict[str, str]:
        return {
            "endpoint": self.endpoint,
            "family": self.family,
            "variant": self.variant,
            "verdict": self.verdict,
            "evidence": self.evidence,
        }


def load_endpoints(config: Dict[str, Any]) -> List[Endpoint]:
    return [
        Endpoint(
            name=entry["name"],
            path=entry["path"],
            param=entry["param"],
            behavior=entry["behavior"],
        )
        for entry in config["endpoints"]
    ]


def _snippet(body: str, needle: Optional[str] = None) -> str:
    if not body:
        return "[empty response body]"
    if needle is None:
        return body[:MAX_EVIDENCE_CHARS]
    index = body.lower().find(needle.lower())
    if index < 0:
        return body[:MAX_EVIDENCE_CHARS]
    start = max(0, index - 20)
    end = min(len(body), index + len(needle) + 40)
    snippet = body[start:end]
    if start > 0:
        snippet = "..." + snippet
    if end < len(body):
        snippet = snippet + "..."
    return snippet[:MAX_EVIDENCE_CHARS]


def _contains_ignoring_case(haystack: str, needle: str) -> Optional[str]:
    if not needle:
        return None
    index = haystack.lower().find(needle.lower())
    if index < 0:
        return None
    return haystack[index : index + len(needle)]


def _raw_reflection(
    body: str,
    sent_value: str,
    original_payload: str,
    variant_name: str,
) -> Optional[str]:
    """Find an unescaped reflection of the original payload in any decode view."""

    # Confusable replacements must never be normalised back to ASCII: without
    # the original glyphs in the response there is no proof of a real leak.
    if variant_name == "homoglyph":
        return None
    for view in decode_variants(sent_value):
        # Compare against the original payload, never the (possibly homoglyph)
        # sent value, so look-alike characters cannot be reported as leaks.
        matched = _contains_ignoring_case(body, original_payload)
        if matched is not None:
            return matched
        # Also accept the decoded sent view when it differs (encoding variants).
        if view != original_payload:
            matched = _contains_ignoring_case(body, view)
            if matched is not None and html.escape(matched, quote=True) not in body:
                return matched
    return None


def _result_feature(body: str, features: List[str]) -> Optional[str]:
    for feature in features:
        matched = _contains_ignoring_case(body, feature)
        if matched is not None:
            return matched
    return None


def _decoded_traversal_leak(
    body: str, sent_value: str, original_payload: str, family: str, variant_name: str
) -> Optional[str]:
    """Recognise decoded traversal fragments even without /etc/passwd content.

    A regenerated compliant mock may reflect an attempted path or return a
    different file error; seeing the decoded traversal sequence in the response
    proves the encoding boundary was crossed.
    """

    if family != "path_traversal":
        return None
    # Homoglyph variants contain confusable characters and are never proof
    # that the real filesystem path parser was reached.
    if variant_name == "homoglyph":
        return None
    candidates = [original_payload]
    for view in decode_variants(sent_value):
        if view not in candidates:
            candidates.append(view)
    markers = ("../", "..\\", "etc/passwd", "etc\\passwd")
    for candidate in candidates:
        decoded_candidate = candidate.lower()
        if not any(marker in decoded_candidate for marker in markers):
            continue
        for marker in markers:
            index = decoded_candidate.find(marker)
            while index >= 0:
                fragment = candidate[index : index + min(len(candidate) - index, 24)]
                if fragment and _contains_ignoring_case(body, fragment) is not None:
                    return fragment
                index = decoded_candidate.find(marker, index + 1)
    return None


def classify(
    response: Response,
    sent_value: str,
    payload: Payload,
    variant: Variant,
    escaping_endpoint: bool,
) -> Finding:
    body = response.body

    # 1) Concrete injection result features always win when present. Homoglyph
    # probes cannot reach the real parser, so an unrelated numeric/file string
    # in the response is not sufficient proof for them.
    feature = None if variant.name == "homoglyph" else _result_feature(body, payload.result_features)
    if feature is not None:
        return Finding(
            endpoint=response.url,
            family=payload.family,
            variant=variant.name,
            verdict="vulnerable",
            evidence=f"injection result feature {feature!r} in: {_snippet(body, feature)}",
        )

    # 2) Unescaped reflection of the original payload fragment.
    reflected = _raw_reflection(body, sent_value, payload.value, variant.name)
    if reflected is not None and not escaping_endpoint:
        return Finding(
            endpoint=response.url,
            family=payload.family,
            variant=variant.name,
            verdict="vulnerable",
            evidence=f"unescaped payload fragment {reflected!r} in: {_snippet(body, reflected)}",
        )

    traversal = _decoded_traversal_leak(
        body, sent_value, payload.value, payload.family, variant.name
    )
    if traversal is not None and not escaping_endpoint:
        return Finding(
            endpoint=response.url,
            family=payload.family,
            variant=variant.name,
            verdict="vulnerable",
            evidence=f"decoded traversal fragment {traversal!r} in: {_snippet(body, traversal)}",
        )

    # 3) Demonstrable neutralisation.
    if escaping_endpoint:
        escaped_payload = html.escape(payload.value, quote=True)
        marker = escaped_payload if escaped_payload in body else html.escape(sent_value, quote=True)
        if marker and marker in body:
            evidence = f"HTML-escaped output {marker!r} in: {_snippet(body, marker)}"
        else:
            # Encoded/homoglyph probes of an escaping endpoint: show the
            # neutralised reflection that is actually present in the body.
            evidence = f"endpoint HTML-escapes input; response: {_snippet(body)}"
        return Finding(
            endpoint=response.url,
            family=payload.family,
            variant=variant.name,
            verdict="safe",
            evidence=evidence,
        )

    if response.status in BLOCKED_STATUSES:
        return Finding(
            endpoint=response.url,
            family=payload.family,
            variant=variant.name,
            verdict="safe",
            evidence=f"request blocked with HTTP {response.status}; response: {_snippet(body)}",
        )

    # 4) No proof of exploitation and no proof of neutralisation.
    return Finding(
        endpoint=response.url,
        family=payload.family,
        variant=variant.name,
        verdict="inconclusive",
        evidence=f"no exploit marker or neutralisation marker found; response: {_snippet(body)}",
    )


def scan(
    base_url: str,
    endpoints: List[Endpoint],
    payloads: Optional[List[Payload]] = None,
    client: Optional[HttpClient] = None,
) -> List[Finding]:
    payloads = payloads or load_payloads()
    client = client or HttpClient()
    xss_probe = next(payload for payload in payloads if payload.family == "xss")
    findings: List[Finding] = []

    for endpoint in endpoints:
        findings.extend(_scan_endpoint(base_url, endpoint, payloads, xss_probe, client))
    return findings


def _scan_endpoint(
    base_url: str,
    endpoint: Endpoint,
    payloads: List[Payload],
    xss_probe: Payload,
    client: HttpClient,
) -> List[Finding]:
    findings: List[Finding] = []
    # The probe is the first ordinary request for this endpoint (xss/original),
    # so no extra request is needed: total stays endpoints * payloads * variants.
    probe_variant = make_variants(xss_probe.value)[0]
    probe_response = client.get(base_url, endpoint.path, endpoint.param, probe_variant.value)
    escaped_probe = html.escape(xss_probe.value, quote=True)
    if escaped_probe in probe_response.body:
        escaping = True
    elif xss_probe.value in probe_response.body:
        escaping = False
    else:
        escaping = False

    for payload in payloads:
        for variant in make_variants(payload.value):
            if payload is xss_probe and variant.name == probe_variant.name:
                response = probe_response
            else:
                response = client.get(base_url, endpoint.path, endpoint.param, variant.value)
            findings.append(classify(response, variant.value, payload, variant, escaping))
    return findings
