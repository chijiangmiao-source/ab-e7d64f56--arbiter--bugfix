"""Sealed-conclusion store keyed by stable audit identifiers.

Every well-formed submission is reduced to a canonical semantic
fingerprint.  Rules:

* a new audit id               -> the conclusion is computed, sealed and
                                  returned (``SEALED``);
* the same id, semantically
  equivalent retransmission    -> the sealed conclusion is replayed
                                  verbatim (``REPLAYED``);
* the same id, different input -> ``AUDIT_ID_CONFLICT``; the original
                                  evidence is retained untouched and
                                  reported back alongside the new
                                  fingerprint.

The store is a single JSON file replaced atomically.  Multiple arbiter
instances may share one file (rolling deployments, accidental scale-out);
the on-disk file is therefore authoritative.  Every check-and-seal
critical section takes an exclusive ``fcntl`` lock and re-reads the file
inside it, so an instance that booted against an empty/absent file still
observes evidence sealed concurrently by a peer -- the first sealed
conclusion for an audit id can never be silently overwritten.  Writes
merge the in-memory view with the freshly read peer entries.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Dict, Iterator, Optional, Tuple

try:
    import fcntl  # POSIX
except ImportError:  # pragma: no cover - non-POSIX fallback
    fcntl = None


class ConflictError(Exception):
    def __init__(self, detail: str, existing: dict, incoming_hash: str) -> None:
        super().__init__(detail)
        self.detail = detail
        self.existing = existing
        self.incoming_hash = incoming_hash


def canonical_fingerprint(payload: dict) -> Tuple[str, dict]:
    """Return ``(sha256_hex, canonical_object)`` for a submission.

    Only semantic content participates: declaration ordering is
    irrelevant; productions are keyed by their unique ids; the input
    token sequence order is significant.
    """
    productions = sorted(
        (
            {"id": int(p["id"]), "lhs": p["lhs"], "rhs": list(p["rhs"])}
            for p in payload["productions"]
        ),
        key=lambda p: p["id"],
    )
    canonical = {
        "start": payload["start"],
        "nonterminals": sorted(payload["nonterminals"]),
        "terminals": (
            sorted(payload["terminals"]) if payload.get("terminals") is not None else None
        ),
        "tokens": list(payload.get("tokens", [])),
        "productions": productions,
    }
    blob = json.dumps(
        canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest(), canonical


class SealedStore:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._entries: Dict[str, dict] = {}
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        # A separate lock file (never replaced) carries the fcntl lock
        # across the atomic rename of the data file.
        self._lock_path = os.path.abspath(path) + ".lock"
        self._lock_fh = open(self._lock_path, "a+b")
        self._entries = self._read_file()

    # ------------------------------------------------------------------
    # File-level primitives
    # ------------------------------------------------------------------
    def _read_file(self) -> Dict[str, dict]:
        """Read and validate the current on-disk store.

        A corrupt or truncated file (including a torn write observed by
        another process) is quarantined rather than destroyed.  When the
        file is temporarily unreadable the in-memory view is kept so
        that existing evidence is not lost.
        """
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return {}
        except (json.JSONDecodeError, OSError):
            try:
                qpath = self.path + ".corrupt." + datetime.now(timezone.utc).strftime(
                    "%Y%m%dT%H%M%SZ"
                )
                os.replace(self.path, qpath)
            except OSError:
                pass
            return {}
        if isinstance(data, dict):
            return data
        return {}

    @contextmanager
    def _file_lock(self, exclusive: bool) -> Iterator[None]:
        """Cross-process lock; re-entrant per thread.

        Combined with the in-process :data:`_lock` it serializes both
        threads of one instance and separate instances sharing the file.
        """
        self._lock.acquire()
        if fcntl is not None:
            flags = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            fcntl.flock(self._lock_fh.fileno(), flags)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(self._lock_fh.fileno(), fcntl.LOCK_UN)
            self._lock.release()

    def _persist_locked(self, entries: Dict[str, dict]) -> None:
        """Atomically replace the data file with ``entries``."""
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(entries, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)

    def _refresh_locked(self) -> Dict[str, dict]:
        """Re-read the shared file and merge it into the local view.

        Sealing is first-writer-wins, so on any id present in both
        views the on-disk entry takes precedence; locally known ids the
        file does not contain are kept (they belong to this instance
        and are about to be written back).
        """
        on_disk = self._read_file()
        merged = dict(self._entries)
        merged.update(on_disk)
        self._entries = merged
        return merged

    def close(self) -> None:
        """Release the cross-process lock handle."""
        self._lock_fh.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def get(self, audit_id: str) -> Optional[dict]:
        with self._file_lock(exclusive=False):
            entries = self._refresh_locked()
            entry = entries.get(audit_id)
            return json.loads(json.dumps(entry)) if entry else None

    def submit(
        self, audit_id: str, payload: dict, compute_conclusion
    ) -> Tuple[dict, str]:
        """Seal/replay a submission.

        ``compute_conclusion`` is called with no arguments only for a
        genuinely new id (visible to no sharing instance) and must
        return a JSON-serializable conclusion.  Returns
        ``(envelope, status)`` where status is ``SEALED`` or
        ``REPLAYED``; raises :class:`ConflictError` on id reuse with
        different semantics -- including reuse first observed through a
        peer instance's concurrent seal.
        """
        incoming_hash, canonical = canonical_fingerprint(payload)
        with self._file_lock(exclusive=True):
            # The file is authoritative: a peer may have sealed this id
            # after this instance last looked.
            entries = self._refresh_locked()
            existing = entries.get(audit_id)
            if existing is not None:
                if existing["request_hash"] == incoming_hash:
                    return json.loads(json.dumps(existing)), "REPLAYED"
                raise ConflictError(
                    f"审计标识 {audit_id!r} 已封存于 {existing['sealed_at']}，"
                    f"本次输入语义指纹 {incoming_hash[:12]} 与原证据 "
                    f"{existing['request_hash'][:12]} 不一致；原证据保留不变，"
                    "请使用新的审计标识提交，或重传语义等价的原始输入",
                    existing=json.loads(json.dumps(existing)),
                    incoming_hash=incoming_hash,
                )

            conclusion = compute_conclusion()
            entry = {
                "audit_id": audit_id,
                "request_hash": incoming_hash,
                "canonical_request": canonical,
                "sealed_at": datetime.now(timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z"),
                "conclusion": conclusion,
            }
            entries[audit_id] = entry
            self._persist_locked(entries)
            self._entries = entries
            return json.loads(json.dumps(entry)), "SEALED"
