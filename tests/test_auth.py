"""Role and principal model tests."""

from __future__ import annotations

import pytest

from cloudsentinel.auth import (
    ADMIN,
    DEFAULT_ROLE,
    ROLES,
    TRIAGE,
    VIEW,
    Principal,
    capabilities_for,
    normalize_role,
    open_principal,
)


def test_normalize_role_accepts_canonical_and_casing():
    assert normalize_role("ADMIN") == "admin"
    assert normalize_role(" Analyst ") == "analyst"
    assert normalize_role(None) == DEFAULT_ROLE == "viewer"
    assert normalize_role("", default="admin") == "admin"


def test_normalize_role_rejects_unknown_roles():
    with pytest.raises(ValueError):
        normalize_role("superuser")


def test_capabilities_are_inherited_upwards():
    assert capabilities_for("viewer") == (VIEW,)
    assert capabilities_for("analyst") == (VIEW, TRIAGE)
    assert capabilities_for("admin") == (VIEW, TRIAGE, ADMIN)
    assert len(ROLES) == 3


def test_principal_can_checks_membership():
    viewer = Principal("phone", "viewer")
    analyst = Principal("analyst", "analyst")
    admin = Principal("bootstrap", "admin", source="bootstrap")

    assert viewer.can(VIEW) and not viewer.can(TRIAGE)
    assert analyst.can(TRIAGE) and not analyst.can(ADMIN)
    assert admin.can(ADMIN)
    assert admin.role == "admin"
    assert admin.to_dict() == {
        "name": "bootstrap",
        "role": "admin",
        "source": "bootstrap",
        "capabilities": [VIEW, TRIAGE, ADMIN],
    }


def test_open_principal_is_admin():
    guest = open_principal()

    assert guest.source == "open"
    assert guest.name == "guest"
    assert guest.can(ADMIN)