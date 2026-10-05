"""Sealed-store tests: replay of equivalent input and id conflicts."""

import json
import os
import tempfile
import unittest

from app.storage import ConflictError, SealedStore, canonical_fingerprint


def payload_a():
    return {
        "audit_id": "audit-A",
        "start": "S",
        "nonterminals": ["S"],
        "productions": [{"id": 2, "lhs": "S", "rhs": ["a"]},
                        {"id": 1, "lhs": "S", "rhs": ["a", "b"]}],
        "tokens": ["a", "b"],
    }


class TestFingerprint(unittest.TestCase):
    def test_order_independent(self):
        p1 = payload_a()
        p2 = json.loads(json.dumps(p1))
        # Reorder declarations and productions (ids stay attached).
        p2["productions"] = list(reversed(p2["productions"]))
        self.assertEqual(canonical_fingerprint(p1)[0],
                         canonical_fingerprint(p2)[0])

    def test_token_order_significant(self):
        p1 = payload_a()
        p2 = json.loads(json.dumps(p1))
        p2["tokens"] = ["b", "a"]
        self.assertNotEqual(canonical_fingerprint(p1)[0],
                            canonical_fingerprint(p2)[0])

    def test_production_content_significant(self):
        p1 = payload_a()
        p2 = json.loads(json.dumps(p1))
        p2["productions"][0]["rhs"] = ["c"]
        self.assertNotEqual(canonical_fingerprint(p1)[0],
                            canonical_fingerprint(p2)[0])


class TestSealReplayConflict(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "sealed.json")
        self.store = SealedStore(self.path)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_seal_replay_conflict_keeps_original(self):
        calls = []

        def compute():
            calls.append(1)
            return {"verdict": "UNIQUE_ACCEPTED", "n": len(calls)}

        entry, status = self.store.submit("audit-A", payload_a(), compute)
        self.assertEqual(status, "SEALED")
        self.assertEqual(entry["conclusion"]["n"], 1)

        # Semantically equivalent retransmission (reordered productions).
        again = json.loads(json.dumps(payload_a()))
        again["productions"] = list(reversed(again["productions"]))
        replay, status2 = self.store.submit("audit-A", again, compute)
        self.assertEqual(status2, "REPLAYED")
        self.assertEqual(replay["conclusion"], entry["conclusion"])
        # The conclusion must not be recomputed on replay.
        self.assertEqual(len(calls), 1)

        # Different input under the same id -> conflict, original kept.
        diff = json.loads(json.dumps(payload_a()))
        diff["tokens"] = ["a"]
        with self.assertRaises(ConflictError) as ctx:
            self.store.submit("audit-A", diff, compute)
        self.assertEqual(ctx.exception.existing["conclusion"],
                         entry["conclusion"])

        replay2, status3 = self.store.submit("audit-A", again, compute)
        self.assertEqual(status3, "REPLAYED")
        self.assertEqual(replay2["conclusion"]["n"], 1)

    def test_persistence_across_instances(self):
        self.store.submit("audit-A", payload_a(),
                          lambda: {"verdict": "UNIQUE_ACCEPTED"})
        store2 = SealedStore(self.path)
        got = store2.get("audit-A")
        self.assertIsNotNone(got)
        self.assertEqual(got["conclusion"]["verdict"], "UNIQUE_ACCEPTED")


def payload_s(token):
    return {
        "audit_id": "shared-audit",
        "start": "S",
        "nonterminals": ["S"],
        "productions": [{"id": 1, "lhs": "S", "rhs": [token]}],
        "tokens": [token],
    }


class TestSharedVolumeInstances(unittest.TestCase):
    """Two instances sharing one file must not overwrite each other.

    Both stores finish initialization while the file is absent, exactly
    like a rolling deployment / accidental scale-out against the same
    empty sealed volume.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "sealed.json")
        # Both initialized before any evidence exists on disk.
        self.store_a = SealedStore(self.path)
        self.store_b = SealedStore(self.path)

    def tearDown(self):
        self.store_a.close()
        self.store_b.close()
        self.tmp.cleanup()

    def test_second_distinct_seal_conflicts_and_first_evidence_survives(self):
        # A seals S -> a / tokens [a].
        entry_a, status_a = self.store_a.submit(
            "shared-audit", payload_s("a"),
            lambda: {"verdict": "UNIQUE_ACCEPTED", "witness": "a"})
        self.assertEqual(status_a, "SEALED")

        # B never reloaded voluntarily; submit must detect A's seal via
        # the shared file and refuse to seal S -> b / tokens [b].
        with self.assertRaises(ConflictError) as ctx:
            self.store_b.submit(
                "shared-audit", payload_s("b"),
                lambda: {"verdict": "UNIQUE_ACCEPTED", "witness": "b"})
        self.assertEqual(
            ctx.exception.existing["conclusion"]["witness"], "a")

        # Re-reading the id from B (and a freshly opened third instance)
        # always yields A's first evidence.
        got_b = self.store_b.get("shared-audit")
        self.assertIsNotNone(got_b)
        self.assertEqual(got_b["conclusion"]["witness"], "a")
        store_c = SealedStore(self.path)
        got_c = store_c.get("shared-audit")
        self.assertEqual(got_c["conclusion"]["witness"], "a")
        store_c.close()

        # B retransmitting A's semantics replays instead of sealing.
        replay, status_r = self.store_b.submit(
            "shared-audit", payload_s("a"),
            lambda: self.fail("must not recompute on replay"))
        self.assertEqual(status_r, "REPLAYED")
        self.assertEqual(replay["conclusion"]["witness"], "a")

        # The shared file itself contains A's evidence, never B's.
        with open(self.path, "r", encoding="utf-8") as fh:
            on_disk = json.load(fh)
        self.assertEqual(
            on_disk["shared-audit"]["conclusion"]["witness"], "a")


if __name__ == "__main__":
    unittest.main()
