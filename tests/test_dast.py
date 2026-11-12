"""Acceptance tests for the standard-library DAST scanner and mock portal.

Each test method maps directly onto one of the nine judgement rules in the
task specification.
"""

from __future__ import annotations

import json
import threading
import unittest
from types import SimpleNamespace
from http.client import HTTPConnection
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import unquote, urlencode

from dast.client import HttpClient
from dast.detectors import Endpoint, load_endpoints, scan
from dast.payloads import load_payloads
from dast.report import build_report, summary_line, write_report
from dast.variants import VARIANT_NAMES, make_variants
from mock_portal.server import build_server, render_template


REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = REPO_ROOT / "fixtures" / "mock_config.json"
PAYLOADS_PATH = REPO_ROOT / "fixtures" / "payloads.json"


class PortalTestBase(unittest.TestCase):
    server = None
    server_thread = None
    base_url = ""
    findings: List[dict] = []
    client: HttpClient | None = None
    endpoints: List[Endpoint] = []
    payloads = []

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = build_server(host="127.0.0.1", port=0, config_path=CONFIG_PATH)
        host, port = cls.server.server_address
        cls.base_url = f"http://{host}:{port}"
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

        cls.endpoints = load_endpoints(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
        cls.payloads = load_payloads(PAYLOADS_PATH)
        cls.client = HttpClient()
        scanned = scan(cls.base_url, cls.endpoints, payloads=cls.payloads, client=cls.client)
        cls.findings = [finding.as_dict() for finding in scanned]

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.server is not None:
            cls.server.shutdown()
            cls.server.server_close()
        if cls.server_thread is not None:
            cls.server_thread.join(timeout=5)

    def get(self, path: str, param: str, value: str) -> Tuple[int, str]:
        query = urlencode({param: value}, safe="")
        conn = HTTPConnection(
            self.server.server_address[0], self.server.server_address[1], timeout=5
        )
        try:
            conn.request("GET", f"{path}?{query}")
            response = conn.getresponse()
            return response.status, response.read().decode("utf-8")
        finally:
            conn.close()

    def records(self, endpoint_name: str | None = None,
                family: str | None = None, variant: str | None = None) -> List[dict]:
        endpoint_path = None
        if endpoint_name is not None:
            endpoint_path = next(
                endpoint.path for endpoint in self.endpoints if endpoint.name == endpoint_name
            )
        result = []
        for record in self.findings:
            if endpoint_path is not None and not record["endpoint"].startswith(
                f"{self.base_url}{endpoint_path}"
            ):
                continue
            if family is not None and record["family"] != family:
                continue
            if variant is not None and record["variant"] != variant:
                continue
            result.append(record)
        return result

    def verdict(self, endpoint_name: str, family: str, variant: str) -> str:
        records = self.records(endpoint_name, family, variant)
        self.assertEqual(len(records), self._payload_count_for_family(family))
        return {record["verdict"] for record in records}.pop() if len({r["verdict"] for r in records}) == 1 else "mixed"

    def _payload_count_for_family(self, family: str) -> int:
        return sum(1 for payload in self.payloads if payload.family == family)


class Rule1MockBehaviourTests(PortalTestBase):
    def test_search_reflects_q_verbatim(self) -> None:
        probe = "' OR 1=1-- <b>"
        status, body = self.get("/search", "q", probe)
        self.assertEqual(status, 200)
        self.assertIn(probe, body)

    def test_render_evaluates_template_to_49(self) -> None:
        self.assertEqual(render_template("{{7*7}}"), "49")
        status, body = self.get("/render", "t", "{{7*7}}")
        self.assertEqual(status, 200)
        self.assertIn("49", body)
        self.assertNotIn("{{7*7}}", body)

    def test_profile_reads_joined_path(self) -> None:
        status, body = self.get("/profile", "name", "../../../etc/passwd")
        self.assertEqual(status, 200)
        self.assertIn("root:x:", body)

    def test_comment_html_escapes_text(self) -> None:
        probe = "<script>alert(1)</script>"
        status, body = self.get("/comment", "text", probe)
        self.assertEqual(status, 200)
        self.assertIn("&lt;script&gt;", body)
        self.assertNotIn(probe, body)


class Rule2RequiredVulnerableTests(PortalTestBase):
    def test_required_raw_variants_are_vulnerable(self) -> None:
        expected = [
            ("search", "sqli"),
            ("search", "xss"),
            ("render", "ssti"),
            ("profile", "path_traversal"),
        ]
        for endpoint_name, family in expected:
            with self.subTest(endpoint=endpoint_name, family=family):
                self.assertEqual(
                    self.verdict(endpoint_name, family, "original"), "vulnerable"
                )


class Rule3CommentSafeTests(PortalTestBase):
    def test_every_comment_record_is_safe(self) -> None:
        comment_records = self.records("comment")
        self.assertEqual(len(comment_records), len(self.payloads) * len(VARIANT_NAMES))
        self.assertTrue(comment_records)
        self.assertTrue(all(record["verdict"] == "safe" for record in comment_records))
        self.assertNotIn("vulnerable", {record["verdict"] for record in comment_records})


class Rule4EncodedTraversalTests(PortalTestBase):
    def test_url_encoded_traversal_is_vulnerable(self) -> None:
        records = self.records("profile", "path_traversal", "url_encoded")
        self.assertEqual(len(records), 2)
        self.assertTrue(all(record["verdict"] == "vulnerable" for record in records))
        self.assertTrue(all("root:x:" in record["evidence"] for record in records))

    def test_encoded_dot_segments_are_decoded_before_judgement(self) -> None:
        encoded = "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        status, body = self.get("/profile", "name", encoded)
        self.assertEqual(status, 200)
        self.assertIn("root:x:", body)


class Rule5SqlCaseVariantTests(PortalTestBase):
    def test_lowercase_sqli_case_variant_is_vulnerable(self) -> None:
        records = self.records("search", "sqli", "case_swapped")
        self.assertTrue(records)
        self.assertTrue(all(record["verdict"] == "vulnerable" for record in records))
        sent_values = {
            make_variants(payload.value)[3].value
            for payload in self.payloads
            if payload.family == "sqli"
        }
        self.assertIn("' or 1=1--", sent_values)


class Rule6DoubleEncodingTests(PortalTestBase):
    def test_double_encoding_is_never_safe_on_injectable_endpoints(self) -> None:
        for endpoint_name in ("search", "render", "profile"):
            records = self.records(endpoint_name, variant="double_url_encoded")
            self.assertTrue(records)
            for record in records:
                with self.subTest(endpoint=endpoint_name, record=record):
                    self.assertIn(record["verdict"], ("vulnerable", "inconclusive"))
                    self.assertNotEqual(record["verdict"], "safe")

    def test_double_encoded_search_payload_is_confirmed_or_inconclusive(self) -> None:
        records = self.records("search", variant="double_url_encoded")
        self.assertTrue({record["verdict"] for record in records} <= {"vulnerable", "inconclusive"})


class Rule7HomoglyphTests(PortalTestBase):
    def test_no_homoglyph_variant_is_ever_vulnerable(self) -> None:
        records = self.records(variant="homoglyph")
        self.assertEqual(len(records), len(self.endpoints) * len(self.payloads))
        self.assertTrue(records)
        self.assertNotIn("vulnerable", {record["verdict"] for record in records})
        self.assertTrue(
            {record["verdict"] for record in records} <= {"safe", "inconclusive"}
        )


class Rule8NoDuplicateRequestTests(PortalTestBase):
    def test_request_count_equals_endpoints_times_payloads_times_variants(self) -> None:
        expected = len(self.endpoints) * len(self.payloads) * len(VARIANT_NAMES)
        self.assertEqual(self.client.request_count, expected)
        self.assertEqual(len(self.client.request_log), expected)
        self.assertEqual(len(set(self.client.request_log)), expected)

    def test_no_endpoint_receives_the_same_value_twice(self) -> None:
        seen: Dict[str, List[str]] = {}
        for url in self.client.request_log:
            endpoint_key = url.split("?", 1)[0]
            seen.setdefault(endpoint_key, []).append(url)
        for endpoint_url, urls in seen.items():
            with self.subTest(endpoint=endpoint_url):
                self.assertEqual(len(urls), len(set(urls)))

    def test_five_distinct_variants_exist_for_each_payload(self) -> None:
        for payload in self.payloads:
            variants = make_variants(payload.value)
            self.assertEqual([variant.name for variant in variants], list(VARIANT_NAMES))
            self.assertEqual(len({variant.value for variant in variants}), len(variants))


class Rule9ReportShapeTests(PortalTestBase):
    def test_every_record_has_five_non_empty_fields(self) -> None:
        report = build_report(
            [SimpleNamespace(as_dict=lambda record=record: record) for record in self.findings],
            endpoint_count=len(self.endpoints),
            request_count=self.client.request_count,
        )
        required = ("endpoint", "family", "variant", "verdict", "evidence")
        for record in report["records"]:
            self.assertEqual(set(record.keys()), set(required))
            for field in required:
                self.assertTrue(isinstance(record[field], str) and record[field].strip())
            self.assertIn(record["verdict"], ("vulnerable", "safe", "inconclusive"))

    def test_report_writes_and_summary_mentions_counts(self) -> None:
        findings = scan(self.base_url, self.endpoints, payloads=self.payloads, client=HttpClient())
        out_path = REPO_ROOT / "out" / "test_report.json"
        if out_path.exists():
            out_path.unlink()
        report = build_report(
            findings,
            endpoint_count=len(self.endpoints),
            request_count=len(self.endpoints) * len(self.payloads) * len(VARIANT_NAMES),
        )
        write_report(report, out_path)
        loaded = json.loads(out_path.read_text(encoding="utf-8"))
        self.assertEqual(loaded["summary"]["requests"], 200)
        line = summary_line(loaded)
        self.assertIn("endpoints=4", line)
        self.assertIn("requests=200", line)
        self.assertIn("vulnerable=", line)
        out_path.unlink()


class FixtureConsistencyTests(unittest.TestCase):
    def test_catalogue_contains_all_required_payload_families(self) -> None:
        catalogue = json.loads(PAYLOADS_PATH.read_text(encoding="utf-8"))
        families = {entry["family"] for entry in catalogue["families"]}
        self.assertEqual(
            families,
            {"sqli", "ssti", "xss", "path_traversal", "command_injection"},
        )
        values = {
            payload["value"]
            for entry in catalogue["families"]
            for payload in entry["payloads"]
        }
        required = {
            "' OR 1=1--",
            "' UNION SELECT",
            "{{7*7}}",
            "${7*7}",
            "<script>alert(1)</script>",
            '"><img src=x onerror=alert(1)>',
            "../../../etc/passwd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            ";id",
            "|id",
        }
        self.assertTrue(required.issubset(values))

    def test_url_encoding_round_trips(self) -> None:
        from dast.variants import url_encode

        encoded = url_encode("../")
        self.assertEqual(encoded, "%2E%2E%2F")
        self.assertEqual(unquote(encoded), "../")
        self.assertEqual(unquote(unquote(url_encode(url_encode("../")))), "../")

    def test_http_client_encodes_percent_signs_and_keeps_variant_urls_distinct(self) -> None:
        client = HttpClient()
        url = client.build_url(
            "http://example.test", "/profile", "name", "%2E%2E%2Fetc%2Fpasswd"
        )
        self.assertEqual(
            url,
            "http://example.test/profile?name=%252E%252E%252Fetc%252Fpasswd",
        )
        single_url = client.build_url(
            "http://example.test",
            "/profile",
            "name",
            "../../../etc/passwd",
        )
        self.assertIn("name=..%2F..%2F..%2Fetc%2Fpasswd", single_url)
        self.assertNotEqual(url, single_url)


if __name__ == "__main__":
    unittest.main(verbosity=2)
