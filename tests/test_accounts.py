"""Console account store tests."""

from __future__ import annotations

import json

import pytest

from cloudsentinel.accounts import AccountError, AccountStore


@pytest.fixture
def store(tmp_path):
    return AccountStore(tmp_path / "users.json")


def test_add_hashes_password_and_never_stores_plaintext(store):
    record = store.add("analyst1", "S3cure-pass", "analyst")

    assert record.username == "analyst1"
    assert record.role == "analyst"
    listing = store.listing()
    assert listing[0]["username"] == "analyst1"
    assert "hash" not in listing[0]

    raw = json.loads(store.path.read_text(encoding="utf-8"))
    stored = raw["accounts"][0]
    assert "S3cure-pass" not in json.dumps(raw)
    assert stored["iterations"] >= 100_000
    assert len(stored["salt"]) == 32


def test_authenticate_accepts_correct_password_and_stamps_login(store):
    store.add("alice", "hunter42abc", "admin")
    store.add("bob", "hunter42xyz", "viewer")

    account = store.authenticate("alice", "hunter42abc")

    assert account is not None
    assert account.role == "admin"
    assert account.last_login

    again = store.authenticate("bob", "hunter42xyz")
    assert again is not None
    assert again.role == "viewer"


def test_authenticate_rejects_wrong_password_or_unknown_user(store):
    store.add("alice", "hunter42abc", "analyst")

    assert store.authenticate("alice", "hunter42abc!") is None
    assert store.authenticate("mallory", "hunter42abc") is None
    assert store.authenticate("alice", "") is None
    assert store.authenticate("", "hunter42abc") is None


def test_add_validates_username_password_and_duplicates(store):
    store.add("alice", "hunter42abc")

    with pytest.raises(AccountError):
        store.add("alice", "hunter42abc")
    with pytest.raises(AccountError):
        store.add("<bad>", "hunter42abc")
    with pytest.raises(AccountError):
        store.add("ab", "hunter42abc")
    with pytest.raises(AccountError):
        store.add("goodname", "short")


def test_set_role_updates_existing_account(store):
    store.add("alice", "hunter42abc", "viewer")

    record = store.set_role("alice", "Admin")
    assert record.role == "admin"

    with pytest.raises(AccountError):
        store.set_role("ghost", "admin")
    with pytest.raises(ValueError):
        store.set_role("alice", "root")


def test_remove_account(store):
    store.add("alice", "hunter42abc")

    assert store.remove("alice") is True
    assert store.remove("alice") is False
    assert store.count() == 0


def test_missing_store_is_empty_not_an_error(store):
    assert store.count() == 0
    assert store.listing() == []
    assert store.exists is False


def test_corrupt_store_raises_account_error(tmp_path):
    path = tmp_path / "users.json"
    path.write_text("{broken", encoding="utf-8")

    with pytest.raises(AccountError):
        AccountStore(path).count()
