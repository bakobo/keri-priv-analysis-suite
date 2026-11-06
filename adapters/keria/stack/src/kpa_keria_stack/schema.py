"""The credential schema the State issues under, and the data-OOBI server every agent loads it from.

KERIA validates a credential against a schema it has resolved by OOBI, as vLEI deployments resolve
theirs from a vLEI server. The scenario's credential carries the population attributes its
presentations disclose, so the schema is built from those names and served the same way.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from keri.core import coring

from .host import HOST, free_port


def build(attributes: list[str]) -> dict:
    """A JSON Schema for a credential whose attribute block holds `attributes`, saidified."""
    fields = {"d": {"type": "string"}, "i": {"type": "string"}, "dt": {"type": "string"}}
    fields |= {name: {"type": "string"} for name in attributes}
    schema = {
        "$id": "",
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "Citizen attributes",
        "description": "The population attributes a scenario's presentations disclose.",
        "type": "object",
        "credentialType": "KpaCitizenAttributes",
        "version": "1.0.0",
        "properties": {
            "v": {"type": "string"}, "d": {"type": "string"}, "u": {"type": "string"},
            "i": {"type": "string"}, "ri": {"type": "string"}, "s": {"type": "string"},
            "a": {"oneOf": [{"type": "string"}, {
                "type": "object", "properties": fields, "additionalProperties": False,
                "required": ["d", "i", "dt", *attributes]}]},
        },
        "additionalProperties": False,
        "required": ["v", "d", "i", "ri", "s", "a"],
    }
    _, schema = coring.Saider.saidify(sad=schema, label=coring.Saids.dollar)
    return schema


class Server:
    """Serves one schema at /oobi/<its SAID>, as a vLEI server does, from a daemon thread."""

    def __init__(self, schema: dict):
        self.said = schema["$id"]
        body = json.dumps(schema).encode()
        path = f"/oobi/{self.said}"

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != path:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/schema+json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.port = free_port()
        self.httpd = ThreadingHTTPServer((HOST, self.port), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def oobi(self) -> str:
        return f"http://{HOST}:{self.port}/oobi/{self.said}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()
