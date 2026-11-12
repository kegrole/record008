"""Fixed-behaviour mock portal implemented with ``http.server``.

Endpoints (configured in ``fixtures/mock_config.json``):

* ``/search?q=``  - reflects ``q`` verbatim after normal query decoding.
* ``/render?t=``  - evaluates integer arithmetic inside ``{{...}}``/``${...}``.
* ``/profile?name=`` - joins ``name`` onto a root path and reads the file.
* ``/comment?text=`` - HTML-escapes ``text`` before storing/reflecting it.
"""

from __future__ import annotations

import ast
import html
import json
import operator
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, unquote, urlsplit


CONFIG_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "mock_config.json"

ALLOWED_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
ALLOWED_UNARYOPS = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def load_config(path: str | os.PathLike[str] | None = None) -> Dict[str, Any]:
    with Path(path or CONFIG_PATH).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _eval_arith(node: ast.AST) -> int:
    if isinstance(node, ast.Expression):
        return _eval_arith(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in ALLOWED_BINOPS:
        return ALLOWED_BINOPS[type(node.op)](_eval_arith(node.left), _eval_arith(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in ALLOWED_UNARYOPS:
        return ALLOWED_UNARYOPS[type(node.op)](_eval_arith(node.operand))
    raise ValueError("only integer arithmetic expressions are supported")


def render_template(text: str) -> str:
    """Render ``{{expr}}`` and ``${expr}`` integer expressions, leave the rest intact."""

    output = text

    def replace_braces(brace_match: Any) -> str:
        try:
            return str(_eval_arith(ast.parse(brace_match.group(1), mode="eval")))
        except Exception:
            return brace_match.group(0)

    def replace_dollar(dollar_match: Any) -> str:
        try:
            return str(_eval_arith(ast.parse(dollar_match.group(1), mode="eval")))
        except Exception:
            return dollar_match.group(0)

    import re

    output = re.sub(r"\{\{\s*(.+?)\s*\}\}", replace_braces, output)
    output = re.sub(r"\$\{\s*(.+?)\s*\}", replace_dollar, output)
    return output


def bounded_unquote(value: str, max_passes: int = 2) -> str:
    """Decode transport encoding and one payload-level encoding layer."""

    decoded = value
    for _ in range(max_passes):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded


def read_profile_file(name: str, root: str, max_decode_passes: int = 2) -> Tuple[int, str]:
    # The value is decoded once by the WSGI-ish query layer; joining it without
    # containment checks deliberately permits traversal outside ``root``.
    candidate = os.path.normpath(
        os.path.join(root, bounded_unquote(name, max_decode_passes).lstrip("/"))
    )
    try:
        with open(candidate, "r", encoding="utf-8", errors="replace") as handle:
            return 200, handle.read()
    except OSError as exc:
        # Reflecting the attempted decoded path is part of the fixed behaviour.
        return 404, f"file not found: {candidate} ({type(exc).__name__})"


class PortalHandler(BaseHTTPRequestHandler):
    server_version = "MockPortal/1.0"

    @property
    def endpoint_map(self) -> Dict[str, Dict[str, str]]:
        return {entry["path"]: entry for entry in self.server.config["endpoints"]}  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:  # quiet test output
        return

    def _send(self, status: int, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        parts = urlsplit(self.path)
        endpoint = self.endpoint_map.get(parts.path)
        if endpoint is None:
            self._send(404, "unknown endpoint")
            return

        param = endpoint["param"]
        values: List[str] = parse_qs(parts.query, keep_blank_values=True).get(param, [""])
        transport_value = values[0]
        # parse_qs performs the standard one-pass query decoding.  A second,
        # bounded pass models applications that also decode payload-level
        # percent-encoding and keeps every scanner variant a distinct request.
        value = bounded_unquote(transport_value, max_passes=2)
        behavior = endpoint["behavior"]

        if behavior == "raw_reflect":
            self._send(200, f"search results for: {value}")
        elif behavior == "template_eval":
            self._send(200, f"rendered: {render_template(value)}")
        elif behavior == "path_read":
            root = self.server.config["service"]["read_root"]  # type: ignore[attr-defined]
            status, content = read_profile_file(transport_value, root)
            self._send(status, f"profile name={value}\n{content}")
        elif behavior == "escaped_reflect":
            stored = html.escape(value, quote=True)
            self.server.comments.append(stored)  # type: ignore[attr-defined]
            self._send(200, f"stored comment: {stored}\ncomments: {self.server.comments}")  # type: ignore[attr-defined]
        else:
            self._send(500, f"unknown behavior {behavior}")


def build_server(host: str | None = None, port: int | None = None,
                 config_path: str | os.PathLike[str] | None = None) -> ThreadingHTTPServer:
    config = load_config(config_path)
    host = host or config["service"]["host"]
    port = config["service"]["port"] if port is None else port
    server = ThreadingHTTPServer((host, port), PortalHandler)
    server.config = config  # type: ignore[attr-defined]
    server.comments = []  # type: ignore[attr-defined]
    return server


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Run the vulnerable mock portal.")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args()
    server = build_server(args.host, args.port)
    host, port = server.server_address
    print(f"mock portal listening on http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
