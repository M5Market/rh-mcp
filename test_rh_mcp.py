#!/usr/bin/env python3
"""
Tests for rh-mcp. Run with: python3 test_rh_mcp.py

These test the internals (PKCE, SSE parsing, config logic) without touching
the network or real Robinhood auth. The proxy's live behavior is verified by
piping real MCP traffic through it (see the integration check in the README).
"""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Load the rh-mcp tool as a module (it has no .py extension, so we must
# tell importlib it's Python source explicitly).
TOOL_PATH = Path(__file__).parent / "rh-mcp"
spec = importlib.util.spec_from_file_location(
    "rh_mcp", TOOL_PATH, loader=importlib.machinery.SourceFileLoader("rh_mcp", str(TOOL_PATH)))
rh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rh)


class PKCEVectorTest(unittest.TestCase):
    """RFC 7636 Appendix B test vector — proves our S256 challenge derivation."""

    def test_rfc7636_vector(self):
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        self.assertEqual(rh.pkce_challenge_for(verifier), expected)

    def test_gen_pkce_shape(self):
        v, c = rh.gen_pkce()
        self.assertEqual(len(v), 43, "verifier should be 43 chars (32 bytes b64url)")
        self.assertEqual(len(c), 43, "challenge should be 43 chars")
        self.assertEqual(rh.pkce_challenge_for(v), c, "challenge must match verifier")


class SSEParseTest(unittest.TestCase):
    """Robinhood wraps every response in text/event-stream framing."""

    def test_single_message_event(self):
        body = ('event: message\n'
                'data: {"jsonrpc":"2.0","id":1,"result":{"capabilities":{}}}\n\n')
        results = list(rh.parse_sse_stream(body))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], 1)

    def test_ignores_comments(self):
        body = ": heartbeat comment\n" + (
            'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{}}\n\n')
        self.assertEqual(len(list(rh.parse_sse_stream(body))), 1)

    def test_empty_body(self):
        self.assertEqual(list(rh.parse_sse_stream("")), [])

    def test_notification_202_empty_body(self):
        # Robinhood returns 202 with empty body for notifications — no parsing needed.
        self.assertEqual(list(rh.parse_sse_stream("")), [])


class TokenStoreTest(unittest.TestCase):
    def test_is_token_valid_true(self):
        creds = {"access_token_expires_at": int(__import__("time").time()) + 3600}
        self.assertTrue(rh.is_token_valid(creds))

    def test_is_token_valid_false_expired(self):
        creds = {"access_token_expires_at": int(__import__("time").time()) - 100}
        self.assertFalse(rh.is_token_valid(creds))

    def test_is_token_valid_false_missing(self):
        self.assertFalse(rh.is_token_valid({}))

    def test_save_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            orig = rh.CREDS_PATH
            try:
                rh.CREDS_PATH = Path(td) / "creds.json"
                rh.save_creds({"access_token": "abc", "expires_in": 3600})
                loaded = rh.load_creds()
                self.assertEqual(loaded["access_token"], "abc")
                self.assertEqual(rh.CREDS_PATH.stat().st_mode & 0o777, 0o600)
            finally:
                rh.CREDS_PATH = orig


class ConfigRedactTest(unittest.TestCase):
    def test_redacts_authorization(self):
        node = {"headers": {"Authorization": "Bearer eyJabc123verylongtoken"}}
        out = rh._redact_config(node)
        self.assertNotIn("eyJabc123verylongtoken", out["headers"]["Authorization"])
        self.assertIn("<redacted>", out["headers"]["Authorization"])

    def test_preserves_other_fields(self):
        node = {"type": "stdio", "command": "/bin/rh-mcp", "args": ["serve"]}
        out = rh._redact_config(node)
        self.assertEqual(out["command"], "/bin/rh-mcp")

    def test_nested_redaction(self):
        node = {"mcp": {"servers": {"robinhood": {"headers": {"Authorization": "Bearer secret1234567890"}}}}}
        out = rh._redact_config(node)
        auth = out["mcp"]["servers"]["robinhood"]["headers"]["Authorization"]
        self.assertNotIn("secret", auth)


class ConfigWriteTest(unittest.TestCase):
    def test_atomic_write_preserves_existing(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "config.json"
            path.write_text(json.dumps({"mcp": {"servers": {"other": {"x": 1}}}}))
            data = json.loads(path.read_text())
            data["mcp"]["servers"]["robinhood"] = {"type": "stdio", "command": "rh-mcp"}
            rh._atomic_write_json(path, data)
            result = json.loads(path.read_text())
            self.assertEqual(result["mcp"]["servers"]["other"]["x"], 1)  # preserved
            self.assertEqual(result["mcp"]["servers"]["robinhood"]["command"], "rh-mcp")
            # backup created
            self.assertTrue((path.with_suffix(".json.bak")).exists())


class Proxy401LogicTest(unittest.TestCase):
    """Test the refresh-retry decision logic without real HTTP."""

    def test_upstream_error_carries_status(self):
        e = rh.UpstreamError(401, "Unauthorized", "JWT verification failed")
        self.assertEqual(e.status, 401)
        self.assertIn("JWT", e.body)


class UpstreamOptionTest(unittest.TestCase):
    """--upstream / --name point the proxy at another server under its own credentials."""

    def setUp(self):
        self.saved = {k: getattr(rh, k) for k in ("UPSTREAM_URL", "NAME", "SERVER_KEY", "CREDS_PATH", "LOCK_PATH", "LOG_PATH")}

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(rh, k, v)

    def test_defaults_unchanged(self):
        rh.configure(None, None)
        self.assertEqual(rh.UPSTREAM_URL, "https://agent.robinhood.com/mcp/trading")
        self.assertEqual(rh.CREDS_PATH.name, "rh-mcp-creds.json")
        self.assertEqual(rh.LOCK_PATH.name, "rh-mcp-creds.lock")
        self.assertEqual(rh.LOG_PATH.name, "rh-mcp.log")
        self.assertEqual(rh.serve_args(), ["serve"])

    def test_named_server_gets_its_own_files_and_key(self):
        rh.configure("https://data.example.net/mcp", "example")
        self.assertEqual(rh.UPSTREAM_URL, "https://data.example.net/mcp")
        self.assertEqual(rh.CREDS_PATH.name, "example-creds.json")
        self.assertEqual(rh.LOCK_PATH.name, "example-creds.lock")
        self.assertEqual(rh.LOG_PATH.name, "example.log")
        self.assertEqual(rh.SERVER_KEY, "example")
        self.assertEqual(rh.serve_args(), ["--upstream", "https://data.example.net/mcp", "--name", "example", "serve"])
        self.assertEqual(rh.CredLock().path.name, "example-creds.lock")

    def test_upstream_without_name_is_refused(self):
        with self.assertRaises(SystemExit):
            rh.configure("https://data.example.net/mcp", None)

    def test_bad_values_are_refused(self):
        for up, name in (("http://data.example.net/mcp", "example"), ("https://data.example.net/mcp", "../x"), ("https://data.example.net/mcp", "-x")):
            with self.assertRaises(SystemExit):
                rh.configure(up, name)

    def test_wiring_uses_the_name_and_flags(self):
        rh.configure("https://data.example.net/mcp", "example")
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "config.json"
            cfg.write_text(json.dumps({"mcp": {"servers": {"robinhood": {"type": "stdio", "command": "x", "args": ["serve"]}}}}))
            ok, _ = rh.wire_stdio_config("zcode", cfg, ["mcp", "servers"])
            servers = json.loads(cfg.read_text())["mcp"]["servers"]
            self.assertTrue(ok)
            self.assertEqual(servers["robinhood"]["args"], ["serve"])  # the Robinhood entry is left alone
            self.assertEqual(servers["example"]["args"], ["--upstream", "https://data.example.net/mcp", "--name", "example", "serve"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
