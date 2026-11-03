"""Local user accounts for the Streamlit console.

The console has no external dependency to authenticate against, so Phase 20
adds a file-backed account store with the same shape as the API token store:

* passwords are hashed with PBKDF2-HMAC-SHA256 (200 000 iterations) and a
  random 16-byte salt — the plaintext password is never written anywhere;
* verification is constant-time (:mod:`hmac.compare_digest`);
* every account carries a role (``viewer`` / ``analyst`` / ``admin``).

If the store has no accounts the console stays open — consistent with the
``--token``/``--allow-scan`` opt-in philosophy — and shows a warning banner.
A public deployment should always define at least one account.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .auth import DEFAULT_ROLE, ROLES, normalize_role

PBKDF2_ITERATIONS = 200_000
SALT_BYTES = 16
NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$")
MIN_PASSWORD_LENGTH = 8


def default_accounts_path() -> Path:
    override = os.environ.get("CLOUDSENTINEL_USERS_FILE", "").strip()
    if override:
        return Path(override)
    from .paths import DATA_DIR

    return DATA_DIR / "console_users.json"


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


@dataclass
class AccountRecord:
    """One console account; only role and lifecycle metadata, never secrets."""

    username: str
    role: str
    created: str
    last_login: str | None = None

    def public(self) -> dict[str, object]:
        return {
            "username": self.username,
            "role": self.role,
            "created": self.created,
            "last_login": self.last_login,
        }


class AccountError(Exception):
    """Raised for invalid account-store operations."""


class AccountStore:
    """File-backed set of console users with PBKDF2 password hashes."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path or default_accounts_path())

    # ------------------------------------------------------------------ file

    def _load(self) -> list[dict]:
        if not self.path.exists():
            return []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AccountError(f"cannot read account store {self.path}: {exc}") from exc
        if isinstance(data, dict) and isinstance(data.get("accounts"), list):
            return data["accounts"]
        if isinstance(data, list):
            return data
        raise AccountError(f"account store {self.path} is not a valid account file")

    def _save(self, accounts: list[dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": 1, "accounts": accounts}
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass  # Windows has no POSIX mode bits; skip silently.
        os.replace(temporary, self.path)

    # ------------------------------------------------------------------ api

    @property
    def exists(self) -> bool:
        return self.path.exists()

    def count(self) -> int:
        return len([item for item in self._load() if item.get("username")])

    def add(
        self,
        username: str,
        password: str,
        role: str | None = None,
    ) -> AccountRecord:
        """Create an account and return its (public) record."""

        name = (username or "").strip()
        if not NAME_PATTERN.match(name):
            raise AccountError(
                "username must be 3-32 characters of letters, digits, '.', '_' or '-'"
            )
        if len(password or "") < MIN_PASSWORD_LENGTH:
            raise AccountError(
                f"password must be at least {MIN_PASSWORD_LENGTH} characters"
            )

        accounts = self._load()
        if any(item.get("username") == name for item in accounts):
            raise AccountError(f"account already exists: {name}")

        record = AccountRecord(
            username=name,
            role=normalize_role(role, DEFAULT_ROLE),
            created=_now(),
        )
        accounts.append({**asdict(record), **_hash(password)})
        self._save(accounts)
        return record

    def remove(self, username: str) -> bool:
        name = (username or "").strip()
        accounts = self._load()
        remaining = [item for item in accounts if item.get("username") != name]
        if len(remaining) == len(accounts):
            return False
        self._save(remaining)
        return True

    def set_role(self, username: str, role: Any) -> AccountRecord:
        name = (username or "").strip()
        normalized = normalize_role(role)
        accounts = self._load()
        for item in accounts:
            if item.get("username") == name:
                item["role"] = normalized
                self._save(accounts)
                return _public_item(item)
        raise AccountError(f"no account named {name!r}")

    def authenticate(self, username: str, password: str) -> AccountRecord | None:
        """Verify credentials; on success stamp ``last_login`` and return it."""

        if not password:
            return None
        name = (username or "").strip()
        accounts = self._load()

        match: dict | None = None
        for item in accounts:
            if item.get("username") == name:
                match = item
                break

        if match is not None and not _verify_hash(password, match):
            match = None
        if match is None:
            # Hash a throwaway input so unknown users cost the same time.
            _hash(password)
            return None

        match["role"] = normalize_role(match.get("role"), DEFAULT_ROLE)
        match["last_login"] = _now()
        self._save(accounts)
        return _public_item(match)

    def listing(self) -> list[dict[str, object]]:
        """Public records as dicts (matches TokenStore.listing)."""

        return [record.public() for record in
                (_public_item(item) for item in self._load())]


def _public_item(item: dict) -> AccountRecord:
    return AccountRecord(
        username=str(item.get("username")),
        role=normalize_role(item.get("role"), DEFAULT_ROLE),
        created=str(item.get("created") or _now()),
        last_login=item.get("last_login"),
    )


def _hash(password: str) -> dict[str, str]:
    salt = secrets.token_hex(SALT_BYTES)
    return {
        "hash": _pbkdf2(password, salt),
        "salt": salt,
        "iterations": PBKDF2_ITERATIONS,
    }


def _pbkdf2(password: str, salt: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations
    )
    return digest.hex()


def _verify_hash(password: str, item: dict) -> bool:
    if not isinstance(item, dict):
        return False
    stored, salt = item.get("hash"), item.get("salt")
    if not stored or not salt:
        return False
    try:
        iterations = int(item.get("iterations") or PBKDF2_ITERATIONS)
    except (TypeError, ValueError):
        return False
    computed = _pbkdf2(password, str(salt), iterations)
    return hmac.compare_digest(computed, str(stored))

