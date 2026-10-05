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
        self.httpd, self.store = make_server("127.0.0.1", 0, SealedStore(store_path))
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}"

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.store.close()
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
    """One arbiter HTTP instance, sharing a sealed.json path with peers."""

    def __init__(self, store_path):
        self.httpd, self.store = make_server("127.0.0.1", 0, SealedStore(store_path))
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}"

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.store.close()

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


class TestSharedVolumeConflict(unittest.TestCase):
    """Regression: two initialized arbiters sharing one sealed volume."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        store_path = os.path.join(self.tmp.name, "sealed.json")
        # Both finish initialization while the shared file is absent.
        self.a = SharedVolumeHarness(store_path)
        self.b = SharedVolumeHarness(store_path)

    def tearDown(self):
        self.a.stop()
        self.b.stop()
        self.tmp.cleanup()

    def test_peer_distinct_submission_conflicts_first_evidence_kept(self):
        payload_a = {
            "audit_id": "shared-audit", "nonterminals": ["S"],
            "productions": [{"id": 1, "lhs": "S", "rhs": ["a"]}],
            "start": "S", "tokens": ["a"],
        }
        payload_b = {
            "audit_id": "shared-audit", "nonterminals": ["S"],
            "productions": [{"id": 1, "lhs": "S", "rhs": ["b"]}],
            "start": "S", "tokens": ["b"],
        }

        s, body = self.a.post(payload_a)
        self.assertEqual(s, 200, body)
        self.assertEqual(body["seal_status"], "SEALED")
        self.assertEqual(body["result"]["verdict"], "UNIQUE_ACCEPTED")

        # B booted on the empty file; the distinct submission must be a
        # conflict rather than a second seal.
        s, body = self.b.post(payload_b)
        self.assertEqual(s, 409)
        self.assertEqual(body["error"], "AUDIT_ID_CONFLICT")
        orig = body["original_evidence"]["conclusion"]
        self.assertEqual(orig["verdict"], "UNIQUE_ACCEPTED")
        self.assertEqual(orig["production_sequence"], [1])
        self.assertEqual(orig["tree"]["children"][0]["token"], "a")

        # Re-reading through B (the stale instance) yields A's evidence,
        # never B's conclusion.
        s, body = self.b.get("/api/v1/conclusion/shared-audit")
        self.assertEqual(s, 200)
        reread = body["conclusion"]
        self.assertEqual(reread["verdict"], "UNIQUE_ACCEPTED")
        self.assertEqual(reread["tree"]["children"][0]["token"], "a")
        self.assertEqual(reread["production_sequence"], [1])

        # And through A as well.
        s, body = self.a.get("/api/v1/conclusion/shared-audit")
        self.assertEqual(s, 200)
        self.assertEqual(body["conclusion"]["tree"]["children"][0]["token"],
                         "a")


if __name__ == "__main__":
    unittest.main()
