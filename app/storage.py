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

The store is a single JSON file replaced atomically; a process-wide lock
serializes threads within one process, and an advisory ``flock`` on a
sibling lock file serializes arbiter *instances* sharing the same store
(rolling deploys, accidental scaling).  Every seal decision is made
inside that cross-process critical section against the bytes on disk:
the instance that completes the first seal owns the audit id forever,
while a peer working from a stale in-memory snapshot receives
``AUDIT_ID_CONFLICT`` instead of overwriting the first evidence.  Reads
also observe the shared file, so a peer can replay conclusions sealed by
another instance.  Sealed entries are immutable.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Dict, Iterator, Optional, Tuple


class ConflictError(Exception):
    def __init__(self, detail: str, existing: dict, incoming_hash: str) -> None:
        super().__init__(detail)
        self.detail = detail
        self.existing = existing
        self.incoming_hash = incoming_hash


class StoreIOError(Exception):
    """The shared store file cannot be read safely.

    Raised rather than overwriting potentially intact evidence when the
    on-disk file is unreadable or malformed.
    """


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
        self.lock_path = path + ".lock"
        self._lock = threading.Lock()
        self._entries: Dict[str, dict] = {}
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, dict):
                    self._entries = data
            except (json.JSONDecodeError, OSError):
                # Corrupt store: quarantine rather than destroy evidence.
                qpath = path + ".corrupt." + datetime.now(timezone.utc).strftime(
                    "%Y%m%dT%H%M%SZ"
                )
                try:
                    os.replace(path, qpath)
                except OSError:
                    # A peer may be quarantining concurrently; keep the
                    # empty in-memory snapshot without touching disk.
                    pass
                self._entries = {}

    # ------------------------------------------------------------------
    # Disk synchronization between processes sharing the same file.
    # ------------------------------------------------------------------
    @contextlib.contextmanager
    def _file_lock_unlocked(self) -> Iterator[None]:
        """Cross-process mutex for a read-check-write critical section.

        Must only be entered while holding ``self._lock``; that fixed
        lock order (thread lock -> file lock) prevents deadlock between
        threads.  ``flock`` is released on close and on process exit, so
        a crashed peer never strands the lock.
        """
        fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _read_disk_unlocked(self) -> Optional[dict]:
        """Return entries currently on disk (``None`` if the file is absent).

        Raises :class:`StoreIOError` when the file exists but is empty,
        malformed or otherwise unreadable: callers must not overwrite a
        shared file in that state, as it may still hold evidence.
        """
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return None
        except (json.JSONDecodeError, OSError) as exc:
            raise StoreIOError(
                f"共享封存文件 {self.path} 当前无法读取（{exc}）；"
                "为避免覆盖既有证据，本次封存中止，请人工核查该文件"
            ) from exc
        if not isinstance(data, dict):
            raise StoreIOError(
                f"共享封存文件 {self.path} 内容不是 JSON 对象；"
                "为避免覆盖既有证据，本次封存中止，请人工核查该文件"
            )
        return data

    def _reload_locked(self) -> Dict[str, dict]:
        """Refresh the in-memory snapshot from the shared file."""
        disk = self._read_disk_unlocked()
        self._entries = disk if disk is not None else {}
        return self._entries

    def _persist_locked(self) -> None:
        # A unique temp name per process/attempt is required: peers use
        # the same directory and must never interleave writes into one
        # shared temp file.  os.replace() is atomic on POSIX, so readers
        # (including peers) observe either the old or the new full file.
        tmp = f"{self.path}.tmp.{os.getpid()}.{uuid.uuid4().hex}"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._entries, fh, ensure_ascii=False, indent=2,
                          sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except OSError:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise

    @staticmethod
    def _verdict_for(audit_id: str, existing: dict, incoming_hash: str):
        """Return ``(envelope, 'REPLAYED')`` or raise a conflict."""
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

    def get(self, audit_id: str) -> Optional[dict]:
        with self._lock, self._file_lock_unlocked():
            try:
                disk = self._read_disk_unlocked()
            except StoreIOError:
                # Never destroy evidence on the read path: fall back to
                # the last good snapshot this process managed to load.
                disk = None
            if disk is not None:
                self._entries = disk
            entry = self._entries.get(audit_id)
            return json.loads(json.dumps(entry)) if entry else None

    def submit(
        self, audit_id: str, payload: dict, compute_conclusion
    ) -> Tuple[dict, str]:
        """Seal/replay a submission.

        ``compute_conclusion`` is called with no arguments only for a
        genuinely new id and must return a JSON-serializable conclusion.
        Returns ``(envelope, status)`` where status is ``SEALED`` or
        ``REPLAYED``; raises :class:`ConflictError` on id reuse with
        different semantics -- including reuse first sealed by a *peer
        process* sharing this file while the current instance held a
        stale empty snapshot.
        """
        incoming_hash, canonical = canonical_fingerprint(payload)

        # Fast path: a known id replays/conflicts straight from disk.
        with self._lock, self._file_lock_unlocked():
            existing = self._reload_locked().get(audit_id)
            if existing is not None:
                return self._verdict_for(audit_id, existing, incoming_hash)

        # Compute WITHOUT any lock (analysis is pure); a peer may seal
        # the same id during this window, so this is not yet a decision.
        conclusion = compute_conclusion()

        # Authoritative decision: inside the cross-process critical
        # section, re-read the shared file and only seal when the id is
        # still absent.  The first completed seal always wins; a peer
        # that reaches this point later replays or conflicts instead of
        # replacing the first evidence.
        with self._lock, self._file_lock_unlocked():
            existing = self._reload_locked().get(audit_id)
            if existing is not None:
                return self._verdict_for(audit_id, existing, incoming_hash)

            entry = {
                "audit_id": audit_id,
                "request_hash": incoming_hash,
                "canonical_request": canonical,
                "sealed_at": datetime.now(timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z"),
                "conclusion": conclusion,
            }
            self._entries[audit_id] = entry
            self._persist_locked()
            return json.loads(json.dumps(entry)), "SEALED"
