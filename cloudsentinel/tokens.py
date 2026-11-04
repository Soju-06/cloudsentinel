"""Hashed API-token store with rotation support.

The API historically accepted one shared token from ``--token``. That is fine
for a quick local run, but it cannot be rotated, and a leaked token means
editing a command line and restarting. This module adds a small file-backed
store:

* tokens are generated with :func:`secrets.token_urlsafe` (256 bits);
* only a salted SHA-256 fingerprint is written to disk, never the token;
* comparisons are constant-time (:mod:`hmac`);
* ``revoke`` takes effect on the next request, so rotation needs no restart:
  add a new token, switch clients over, revoke the old one;
* every token carries a role (``viewer`` / ``analyst`` / ``admin``) that
  scopes what the API allows; tokens created before Phase 20 default to
  ``analyst``, so re-issue one with ``--role admin`` for remote scans.

The file lives next to the database (``data/api_tokens.json``) and is written
atomically with the owner-only permission bit on POSIX systems.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .auth import normalize_role
from .paths import DATA_DIR

TOKEN_BYTES = 32
SALT_BYTES = 16
DEFAULT_TOKEN_PATH = Path(
    os.environ.get("CLOUDSENTINEL_TOKEN_FILE", DATA_DIR / "api_tokens.json")
)


def _safe_role(role: Any) -> str:
    try:
        return normalize_role(role, "analyst")
    except ValueError:
        return "analyst"


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


@dataclass
class TokenRecord:
    """One stored token: a label, a fingerprint and its lifecycle dates."""

    label: str
    digest: str
    created: str
    revoked: str | None = None
    last_used: str | None = None
    role: str = "analyst"

    @property
    def active(self) -> bool:
        return self.revoked is None

    def public(self) -> dict[str, object]:
        """Safe representation for listings: no digest, only a fingerprint."""
        return {
            "label": self.label,
            "fingerprint": self.digest[:8],
            "created": self.created,
            "revoked": self.revoked,
            "last_used": self.last_used,
            "active": self.active,
            "role": _safe_role(self.role),
        }


class TokenError(Exception):
    """Raised for invalid token-store operations (duplicate labels, etc.)."""


class TokenStore:
    """File-backed set of active API tokens."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path or DEFAULT_TOKEN_PATH)
        self._last_touch = 0.0
        self._store_mtime = None  # refreshed by the load/save below
        self._data = self._load()
        self._store_mtime = self._current_mtime()

    def _current_mtime(self) -> int | None:
        """File mtime (nanoseconds) used to detect changes by other processes."""
        try:
            return self.path.stat().st_mtime_ns
        except OSError:
            return None

    def _refresh_if_changed(self) -> None:
        """Pick up tokens added/revoked by another process (e.g. the CLI).

        The API keeps one long-lived ``TokenStore`` instance while the CLI
        creates and revokes tokens in short-lived ones on the same file. A
        cheap stat per verification keeps every store in sync, so rotation
        takes effect without restarting the server.
        """
        current = self._current_mtime()
        if current == self._store_mtime:
            return
        self._data = self._load()
        self._store_mtime = self._current_mtime()

    # ------------------------------------------------------------------ file

    def _load(self) -> dict:
        if not self.path.exists():
            return {"version": 1, "salt": secrets.token_hex(SALT_BYTES), "tokens": []}

        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise TokenError(f"cannot read token store {self.path}: {exc}") from exc

        if not isinstance(data, dict) or not isinstance(data.get("tokens"), list):
            raise TokenError(f"token store {self.path} is not a valid token file")

        # Older/hand-written files may lack a salt; add one before use.
        if not data.get("salt"):
            data["salt"] = secrets.token_hex(SALT_BYTES)
            self._data = data
            self._save()
        return data

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(self._data, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass  # Windows has no POSIX mode bits; skip silently.
        temporary.write_text(
            json.dumps(self._data, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, self.path)
        self._store_mtime = self._current_mtime()

    # --------------------------------------------------------------- helpers

    def _fingerprint(self, token: str) -> str:
        salted = f"{self._data['salt']}:{token}".encode("utf-8")
        return hashlib.sha256(salted).hexdigest()

    def _records(self) -> list[TokenRecord]:
        return [TokenRecord(**item) for item in self._data["tokens"]]

    def _write_records(self, records: list[TokenRecord]) -> None:
        self._data["tokens"] = [asdict(record) for record in records]
        self._save()

    # ------------------------------------------------------------------ api

    @property
    def exists(self) -> bool:
        return self.path.exists()

    def active_count(self) -> int:
        return sum(1 for record in self._records() if record.active)

    def add(
        self,
        label: str | None = None,
        token: str | None = None,
        role: str | None = None,
    ) -> tuple[str, TokenRecord]:
        """Create a token and return ``(plaintext, record)``; printed once."""
        records = self._records()
        name = (label or f"token-{len(records) + 1}").strip()
        if not name:
            raise TokenError("label must not be empty")
        if any(record.label == name for record in records):
            raise TokenError(f"label already exists: {name}")
        role = normalize_role(role, "analyst")

        plaintext = token or secrets.token_urlsafe(TOKEN_BYTES)
        if len(plaintext) < 16:
            raise TokenError("token must be at least 16 characters")

        record = TokenRecord(
            label=name,
            digest=self._fingerprint(plaintext),
            created=_now(),
            role=role,
        )
        records.append(record)
        self._write_records(records)
        return plaintext, record

    def revoke(self, selector: str) -> int:
        """Revoke by label (exact or prefix) or fingerprint prefix."""
        needle = selector.strip()
        if not needle:
            raise TokenError("selector must not be empty")

        records = self._records()
        revoked = 0
        for record in records:
            if not record.active:
                continue
            if (
                record.label == needle
                or record.label.startswith(needle)
                or record.digest.startswith(needle.lower())
            ):
                record.revoked = _now()
                revoked += 1

        if revoked:
            self._write_records(records)
        return revoked

    def verify(self, presented: str) -> bool:
        """Constant-time check against every active token."""
        return self.verify_record(presented) is not None

    def verify_record(self, presented: str) -> TokenRecord | None:
        """Constant-time check returning the matching token record (role)."""
        if not presented:
            return None
        self._refresh_if_changed()

        candidate = self._fingerprint(presented)
        matched_index: int | None = None
        records = self._records()
        for index, record in enumerate(records):
            if record.active:
                # Do not short-circuit: compare every active record.
                if hmac.compare_digest(candidate, record.digest):
                    matched_index = index

        if matched_index is None:
            return None
        self._touch(matched_index)
        return records[matched_index]

    def _touch(self, index: int) -> None:
        """Record ``last_used`` at most twice a minute to avoid disk churn."""
        import time

        now = time.monotonic()
        if now - self._last_touch < 30:
            return
        self._last_touch = now

        records = self._records()
        if 0 <= index < len(records) and records[index].active:
            records[index].last_used = _now()
            self._write_records(records)

    def listing(self) -> list[dict[str, object]]:
        return [record.public() for record in self._records()]
