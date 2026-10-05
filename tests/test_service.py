"""In-process HTTP service tests (no network fixtures required)."""

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from app.service import make_server
from app.storage import SealedStore


class ServiceHarness:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        store_path = os.path.join(self.tmp.name, "sealed.json")
        self.httpd, _ = make_server("127.0.0.1", 0, SealedStore(store_path))
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}"

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.tmp.cleanup()

    def post(self, payload):
        req = urllib.request.Request(
            self.base + "/api/v1/analyze",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def get(self, path):
        try:
            with urllib.request.urlopen(self.base + path, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())


class TestService(unittest.TestCase):
    def setUp(self):
        self.h = ServiceHarness()

    def tearDown(self):
        self.h.stop()

    def test_health_and_404(self):
        s, b = self.h.get("/healthz")
        self.assertEqual(s, 200)
        self.assertEqual(b["status"], "ok")
        s, _ = self.h.get("/nope")
        self.assertEqual(s, 404)

    def test_full_lifecycle(self):
        payload = {
            "audit_id": "A-1", "nonterminals": ["S"],
            "productions": [{"id": 1, "lhs": "S", "rhs": ["a"]}],
            "start": "S", "tokens": ["a"],
        }
        s, b = self.h.post(payload)
        self.assertEqual(s, 200)
        self.assertEqual(b["seal_status"], "SEALED")
        self.assertEqual(b["result"]["verdict"], "UNIQUE_ACCEPTED")

        # replay
        s, b = self.h.post(payload)
        self.assertEqual(s, 200)
        self.assertEqual(b["seal_status"], "REPLAYED")

        # conflict
        bad = dict(payload, tokens=[])
        s, b = self.h.post(bad)
        self.assertEqual(s, 409)
        self.assertEqual(b["error"], "AUDIT_ID_CONFLICT")
        self.assertEqual(
            b["original_evidence"]["conclusion"]["verdict"], "UNIQUE_ACCEPTED")

    def test_malformed_new_id_is_400_not_500(self):
        s, b = self.h.post({"audit_id": "A-2", "nonterminals": "S"})
        self.assertEqual(s, 400)
        self.assertIn("error", b)
        # Nothing sealed.
        s, b = self.h.get("/api/v1/conclusion/A-2")
        self.assertEqual(s, 404)

    def test_rejected_verdict_is_still_sealed(self):
        payload = {
            "audit_id": "A-3", "nonterminals": ["S"],
            "productions": [{"id": 1, "lhs": "S", "rhs": ["a"]}],
            "start": "S", "tokens": ["z"],
        }
        s, b = self.h.post(payload)
        self.assertEqual(s, 200)
        self.assertEqual(b["result"]["verdict"], "REJECTED")
        self.assertEqual(b["result"]["rejection"]["reason"], "INPUT_NOT_ACCEPTED")
        s2, b2 = self.h.get("/api/v1/conclusion/A-3")
        self.assertEqual(s2, 200)
        self.assertEqual(b2["conclusion"]["verdict"], "REJECTED")

    def test_ambiguous_returns_two_trees(self):
        payload = {
            "audit_id": "A-4", "nonterminals": ["S"],
            "productions": [{"id": 1, "lhs": "S", "rhs": ["a"]},
                            {"id": 2, "lhs": "S", "rhs": ["a"]}],
            "start": "S", "tokens": ["a"],
        }
        s, b = self.h.post(payload)
        self.assertEqual(s, 200)
        self.assertEqual(b["result"]["verdict"], "AMBIGUOUS_ACCEPTED")
        self.assertEqual(b["result"]["production_sequences"],
                         {"first": [1], "second": [2]})


class SharedVolumeHarness:
    """Two arbiter HTTP instances initialized on one shared store file."""

    def __init__(self):
        import socket
        self.tmp = tempfile.TemporaryDirectory()
        self.store_path = os.path.join(self.tmp.name, "sealed.json")
        self.servers = []
        self.threads = []
        self.bases = []
        for _ in range(2):
            store = SealedStore(self.store_path)
            httpd, _ = make_server("127.0.0.1", 0, store)
            port = httpd.server_address[1]
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            self.servers.append(httpd)
            self.threads.append(thread)
            self.bases.append(f"http://127.0.0.1:{port}")

    def stop(self):
        for httpd in self.servers:
            httpd.shutdown()
            httpd.server_close()
        self.tmp.cleanup()


def _post(base, payload):
    req = urllib.request.Request(
        base + "/api/v1/analyze",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _get(base, path):
    with urllib.request.urlopen(base + path, timeout=5) as r:
        return r.status, json.loads(r.read())


class TestSharedVolumeConflict(unittest.TestCase):
    """Regression: duplicate seals over a shared file lose first evidence."""

    def setUp(self):
        self.h = SharedVolumeHarness()

    def tearDown(self):
        self.h.stop()

    def test_peer_conflict_keeps_first_evidence(self):
        base_a, base_b = self.h.bases
        first = {
            "audit_id": "shared-audit", "nonterminals": ["S"],
            "productions": [{"id": 1, "lhs": "S", "rhs": ["a"]}],
            "start": "S", "tokens": ["a"],
        }
        s, b = _post(base_a, first)
        self.assertEqual((s, b["seal_status"]), (200, "SEALED"))
        self.assertEqual(b["result"]["production_sequence"], [1])

        # Instance B was initialized before A sealed and never reloaded;
        # its semantically different submission must be refused.
        other = dict(first)
        other["productions"] = [{"id": 1, "lhs": "S", "rhs": ["b"]}]
        other["tokens"] = ["b"]
        s, b = _post(base_b, other)
        self.assertEqual(s, 409)
        self.assertEqual(b["error"], "AUDIT_ID_CONFLICT")
        self.assertEqual(
            b["original_evidence"]["conclusion"]["production_sequence"], [1])

        # Rereading by id from BOTH instances yields A's first evidence.
        for base in (base_a, base_b):
            s, b = _get(base, "/api/v1/conclusion/shared-audit")
            self.assertEqual(s, 200)
            conclusion = b["conclusion"]
            self.assertEqual(conclusion["verdict"], "UNIQUE_ACCEPTED")
            self.assertEqual(conclusion["tree"]["children"][0]["token"], "a")
            self.assertEqual(conclusion["production_sequence"], [1])

        # An equivalent retransmission via B replays A's evidence.
        s, b = _post(base_b, first)
        self.assertEqual((s, b["seal_status"]), (200, "REPLAYED"))
        self.assertEqual(b["result"]["tree"]["children"][0]["token"], "a")


if __name__ == "__main__":
    unittest.main()
