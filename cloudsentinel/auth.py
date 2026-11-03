"""Shared identity model: roles, capabilities and principals.

Phase 20 gives every caller an identity:

* API tokens carry a role (``viewer``, ``analyst`` or ``admin``);
* the Streamlit console is gated by local user accounts with the same roles;
* a principal is the authenticated view of either.

Open deployments (no bootstrap token, no token store, no console accounts)
keep the historic fully-trusted localhost behaviour: the anonymous principal
is ``admin`` so nothing breaks for a local lab, while anything that does
configure authentication inherits least-privilege defaults.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

ROLES = ("viewer", "analyst", "admin")
DEFAULT_ROLE = "viewer"

# Capability names used by the API and the console.
VIEW = "view"
TRIAGE = "triage"
ADMIN = "admin"

_RANK = {"viewer": 0, "analyst": 1, "admin": 2}
# What each role is allowed to do; a higher role inherits the rows above.
_CAPABILITIES: dict[str, tuple[str, ...]] = {
    "viewer": (VIEW,),
    "analyst": (VIEW, TRIAGE),
    "admin": (VIEW, TRIAGE, ADMIN),
}


def normalize_role(value: Any, default: str = DEFAULT_ROLE) -> str:
    """Map a user-supplied role onto the canonical lower-case name."""

    if value is None or (isinstance(value, str) and not value.strip()):
        value = default
    role = str(value).strip().lower()
    if role not in _RANK:
        raise ValueError(f"role must be one of {'|'.join(ROLES)}, got {role!r}")
    return role


def capabilities_for(role: Any) -> tuple[str, ...]:
    """Capabilities granted to *role* (including inherited ones)."""

    return _CAPABILITIES[normalize_role(role)]


@dataclass(frozen=True)
class Principal:
    """An authenticated caller: who it is and what it may do."""

    name: str
    role: str
    source: str = "token"  # token | account | open | bootstrap

    def __post_init__(self) -> None:
        object.__setattr__(self, "role", normalize_role(self.role))

    @property
    def capabilities(self) -> tuple[str, ...]:
        return capabilities_for(self.role)

    def can(self, capability: str) -> bool:
        return capability in self.capabilities

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "role": self.role,
            "source": self.source,
            "capabilities": list(self.capabilities),
        }


def open_principal() -> Principal:
    """Identity used when no authentication is configured at all.

    A deployment that never configured any credential is a trusted local lab,
    so the anonymous caller keeps full access (and the API banner keeps
    warning about it).
    """

    return Principal(name="guest", role="admin", source="open")
