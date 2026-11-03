"""Headless Streamlit console tests (AppTest)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from cloudsentinel.accounts import AccountStore
from cloudsentinel.auth import Principal
from cloudsentinel.db import AlertStore
from cloudsentinel.models import Alert
from cloudsentinel.severity import Severity


@pytest.fixture
def dashboard(tmp_path, monkeypatch):
    """Locate dashboard.py and redirect its database + user store to tmp_path.

    dashboard.py resolves paths from the environment at run time so the
    headless run is fully isolated from the developer's data directory.
    """

    monkeypatch.setenv("CLOUDSENTINEL_DB", str(tmp_path / "dash.db"))
    monkeypatch.setenv("CLOUDSENTINEL_USERS_FILE", str(tmp_path / "users.json"))
    return Path(__file__).resolve().parents[1] / "cloudsentinel" / "dashboard.py"


def _alert(entity="carol"):
    moment = datetime.now(timezone.utc) - timedelta(hours=2)
    return Alert(
        detector="brute_force",
        severity=Severity.CRITICAL,
        title="Repeated failed logins",
        description=f"Repeated failed logins for {entity}.",
        entity=entity,
        entity_type="user",
        event_count=5,
        first_seen=moment,
        last_seen=moment,
        evidence={"user": entity},
    )


def test_without_accounts_console_is_open(dashboard):
    at = AppTest.from_file(dashboard, default_timeout=90).run()

    assert not at.exception
    sidebar_values = [str(element.value) for element in at.sidebar.markdown]
    assert any("CONSOLE" in value and "OPEN" in value for value in sidebar_values)
    labels = [element.label for element in at.sidebar.button]
    assert any("RUN DETECTION SCAN" in label for label in labels)


def test_login_gate_blocks_unauthenticated_users(dashboard):
    AccountStore().add("alice", "sup3rsafe1", "admin")

    at = AppTest.from_file(dashboard, default_timeout=90).run()

    assert not at.exception
    assert "principal" not in at.session_state
    values = [str(element.value) for element in at.markdown] + [
        str(element.value) for element in at.sidebar.markdown
    ]
    assert any("ACCESS CONTROL" in value for value in values)
    assert not any("SECURITY OPERATIONS" in value for value in values)


def test_admin_session_renders_full_console(dashboard, tmp_path):
    AlertStore(tmp_path / "dash.db").init().upsert_many(
        [_alert()], suppression_minutes=0
    )
    AccountStore().add("alice", "sup3rsafe1", "admin")

    at = AppTest.from_file(dashboard, default_timeout=90)
    at.session_state["principal"] = Principal("alice", "admin", "account")
    at.run()

    assert not at.exception
    assert len(at.tabs) == 3
    labels = [element.label for element in at.sidebar.button]
    assert any("RUN DETECTION SCAN" in label for label in labels)
    rendered = [str(element.value) for element in at.markdown]
    assert any("TRIAGE CONSOLE" in value for value in rendered)


def test_viewer_session_is_read_only(dashboard, tmp_path):
    AlertStore(tmp_path / "dash.db").init().upsert_many(
        [_alert()], suppression_minutes=0
    )
    AccountStore().add("bob", "sup3rsafe1", "viewer")

    at = AppTest.from_file(dashboard, default_timeout=90)
    at.session_state["principal"] = Principal("bob", "viewer", "account")
    at.run()

    assert not at.exception
    assert len(at.tabs) == 3
    labels = [element.label for element in at.sidebar.button]
    assert not any("RUN DETECTION SCAN" in label for label in labels)
    rendered = [str(element.value) for element in at.markdown]
    assert not any("TRIAGE CONSOLE" in value for value in rendered)
    assert any("READ-ONLY SESSION" in value for value in rendered)


def test_analyst_session_can_triage_but_not_admin(dashboard, tmp_path):
    AlertStore(tmp_path / "dash.db").init().upsert_many(
        [_alert()], suppression_minutes=0
    )
    AccountStore().add("carol", "sup3rsafe1", "analyst")

    at = AppTest.from_file(dashboard, default_timeout=90)
    at.session_state["principal"] = Principal("carol", "analyst", "account")
    at.run()

    assert not at.exception
    labels = [element.label for element in at.sidebar.button]
    assert any("SIGN OUT" in label for label in labels)
    assert not any("RUN DETECTION SCAN" in label for label in labels)
    rendered = [str(element.value) for element in at.markdown]
    assert any("TRIAGE CONSOLE" in value for value in rendered)
