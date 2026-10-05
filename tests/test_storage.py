"""Sealed-store tests: replay of equivalent input and id conflicts."""

import json
import os
import tempfile
import threading
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


def payload_shared(kind):
    """S -> a / token a versus S -> b / token b (semantically different)."""
    return {
        "audit_id": "shared-audit",
        "start": "S",
        "nonterminals": ["S"],
        "productions": [{"id": 1, "lhs": "S", "rhs": [kind]}],
        "tokens": [kind],
    }


class TestSharedFileInstances(unittest.TestCase):
    """Two instances initialized together against an empty shared store.

    Models a rolling deploy / accidental scale-out where arbiter A and
    arbiter B both open the same sealed.json before any seal exists.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "sealed.json")
        # Both initialize while the file does not exist yet.
        self.store_a = SealedStore(self.path)
        self.store_b = SealedStore(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_second_distinct_submission_conflicts_and_keeps_first(self):
        entry_a, status_a = self.store_a.submit(
            "shared-audit", payload_shared("a"),
            lambda: {"verdict": "UNIQUE_ACCEPTED", "evidence": "A"},
        )
        self.assertEqual(status_a, "SEALED")
        self.assertEqual(entry_a["conclusion"]["evidence"], "A")

        # B never reloaded on its own; the shared-file re-check inside
        # submit must discover A's seal and refuse the different input.
        with self.assertRaises(ConflictError) as ctx:
            self.store_b.submit(
                "shared-audit", payload_shared("b"),
                lambda: {"verdict": "UNIQUE_ACCEPTED", "evidence": "B"},
            )
        self.assertEqual(ctx.exception.existing["conclusion"],
                         entry_a["conclusion"])

        # The first evidence stays readable from both instances and from
        # a freshly opened one; B's conclusion never replaces it.
        self.assertEqual(self.store_a.get("shared-audit")["conclusion"],
                         entry_a["conclusion"])
        self.assertEqual(self.store_b.get("shared-audit")["conclusion"],
                         entry_a["conclusion"])
        store_c = SealedStore(self.path)
        self.assertEqual(store_c.get("shared-audit")["conclusion"]["evidence"],
                         "A")

        # An equivalent retransmission via B still replays A's evidence.
        replay, status = self.store_b.submit(
            "shared-audit", payload_shared("a"),
            lambda: self.fail("replay must not recompute"))
        self.assertEqual(status, "REPLAYED")
        self.assertEqual(replay["conclusion"]["evidence"], "A")

    def test_racers_seal_simultaneously_only_first_evidence_survives(self):
        # Both instances race through submit while the other is blocked
        # inside compute; the file lock must serialize the decisions so
        # exactly one seals and the other conflicts, the loser seeing the
        # winner's (not its own) conclusion.
        def make_compute(label, gate):
            def compute():
                gate.wait(5)
                return {"verdict": "UNIQUE_ACCEPTED", "evidence": label}
            return compute

        gate_a = threading.Event()
        gate_b = threading.Event()
        results = {}

        def run(instance, label, gate):
            try:
                results[label] = instance.submit(
                    "shared-audit", payload_shared(label),
                    make_compute(label.upper(), gate))
            except ConflictError as exc:
                results[label] = exc

        ta = threading.Thread(target=run,
                              args=(self.store_a, "a", gate_a))
        tb = threading.Thread(target=run,
                              args=(self.store_b, "b", gate_b))
        ta.start()
        tb.start()
        # Release both computations at the same instant; submit then
        # contends for the file lock in an arbitrary order.
        gate_a.set()
        gate_b.set()
        ta.join(5)
        tb.join(5)
        self.assertFalse(ta.is_alive() or tb.is_alive(), "提交线程应已结束")

        statuses = sorted(
            v[1] if isinstance(v, tuple) else "CONFLICT"
            for v in results.values())
        self.assertEqual(statuses, ["CONFLICT", "SEALED"])

        sealed = next(v for v in results.values() if isinstance(v, tuple))
        winner = sealed[0]["conclusion"]["evidence"]
        self.assertIn(winner, ("A", "B"))
        conflict = next(v for v in results.values()
                        if isinstance(v, ConflictError))
        self.assertEqual(conflict.existing["conclusion"]["evidence"], winner)
        self.assertEqual(self.store_a.get("shared-audit")["conclusion"]["evidence"],
                         winner)
        self.assertEqual(self.store_b.get("shared-audit")["conclusion"]["evidence"],
                         winner)


if __name__ == "__main__":
    unittest.main()
