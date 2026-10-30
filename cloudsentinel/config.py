"""Detector configuration with file overrides (TOML or JSON)."""

from __future__ import annotations

import json
import tomllib
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

from .paths import CONFIG_CANDIDATES
from .severity import Severity

DEFAULT_LOGIN_EVENTS = [
    "ConsoleLogin",
    "Login",
    "SignIn",
    "UserLogin",
    "Authenticate",
]

DEFAULT_PUBLIC_ACL_TOKENS = [
    "public-read",
    "allusers",
    "global/allusers",
]

DEFAULT_CRITICAL_ACL_TOKENS = [
    "public-read-write",
    "alluserswrite",
]

DEFAULT_AUTHENTICATED_ACL_TOKENS = [
    "authenticated-read",
    "authenticatedusers",
    "global/authenticatedusers",
]

DEFAULT_STORAGE_HINTS = [
    "bucket",
    "object",
    "storage",
    "blob",
    "container",
    "s3",
    "gcs",
    "azure",
    "acl",
]

DEFAULT_ADMIN_POLICY_HINTS = [
    "administratoraccess",
    "poweruseraccess",
]

# Ports whose exposure to the internet is treated as CRITICAL.
DEFAULT_SENSITIVE_PORTS = [
    22,
    23,
    1433,
    1521,
    3306,
    3389,
    5432,
    5900,
    6379,
    9200,
    9300,
    11211,
    27017,
]

# Root actions that change security posture escalate to CRITICAL.
DEFAULT_ROOT_CRITICAL_ACTIONS = [
    "createaccesskey",
    "createuser",
    "createrole",
    "createpolicy",
    "attachuserpolicy",
    "attachrolepolicy",
    "attachgrouppolicy",
    "putuserpolicy",
    "putrolepolicy",
    "putgrouppolicy",
    "deactivatemfadevice",
    "deletevirtualmfadevice",
    "deleteaccountpasswordpolicy",
    "updateaccountpasswordpolicy",
    "stoplogging",
    "deletetrail",
    "updatetrail",
    "putbucketpolicy",
    "putbucketacl",
]


@dataclass
class BruteForceConfig:
    enabled: bool = True
    threshold: int = 5
    window_minutes: int = 10
    critical_multiplier: int = 3
    compromise_window_minutes: int = 30
    detect_compromise: bool = True
    correlate_across_ips: bool = True
    group_by: str = "user_ip"  # user_ip | user | ip
    login_events: list[str] = field(default_factory=lambda: list(DEFAULT_LOGIN_EVENTS))

    def __post_init__(self) -> None:
        if self.group_by not in {"user_ip", "user", "ip"}:
            raise ValueError(
                f"brute_force.group_by must be user_ip|user|ip, got {self.group_by!r}"
            )
        if self.threshold < 1:
            raise ValueError("brute_force.threshold must be >= 1")
        if self.window_minutes < 1:
            raise ValueError("brute_force.window_minutes must be >= 1")


@dataclass
class PublicStorageConfig:
    enabled: bool = True
    public_acl_tokens: list[str] = field(
        default_factory=lambda: list(DEFAULT_PUBLIC_ACL_TOKENS)
    )
    critical_acl_tokens: list[str] = field(
        default_factory=lambda: list(DEFAULT_CRITICAL_ACL_TOKENS)
    )
    authenticated_acl_tokens: list[str] = field(
        default_factory=lambda: list(DEFAULT_AUTHENTICATED_ACL_TOKENS)
    )
    storage_hints: list[str] = field(default_factory=lambda: list(DEFAULT_STORAGE_HINTS))


@dataclass
class IAMConfig:
    enabled: bool = True
    admin_policy_hints: list[str] = field(
        default_factory=lambda: list(DEFAULT_ADMIN_POLICY_HINTS)
    )
    scan_inline_policies: bool = True


@dataclass
class MFAConfig:
    enabled: bool = True


@dataclass
class RootUsageConfig:
    enabled: bool = True
    critical_actions: list[str] = field(
        default_factory=lambda: list(DEFAULT_ROOT_CRITICAL_ACTIONS)
    )


@dataclass
class AccessKeyConfig:
    enabled: bool = True


@dataclass
class SecurityGroupConfig:
    enabled: bool = True
    sensitive_ports: list[int] = field(
        default_factory=lambda: list(DEFAULT_SENSITIVE_PORTS)
    )

    def __post_init__(self) -> None:
        self.sensitive_ports = [int(port) for port in self.sensitive_ports]
        for port in self.sensitive_ports:
            if not 0 <= port <= 65535:
                raise ValueError(
                    f"security_groups.sensitive_ports must be 0-65535, got {port}"
                )


@dataclass
class CloudTrailConfig:
    enabled: bool = True


@dataclass
class GeoIPConfig:
    """Location enrichment backend.

    ``event`` uses coordinates already present in the log (offline, default).
    ``maxmind`` uses a local GeoLite2 database, ``http`` calls a free lookup API.
    """

    backend: str = "event"  # event | maxmind | http
    maxmind_db_path: str | None = None
    http_timeout_seconds: float = 2.0
    cache: bool = True

    def __post_init__(self) -> None:
        if self.backend not in {"event", "maxmind", "http"}:
            raise ValueError(
                f"geoip.backend must be event|maxmind|http, got {self.backend!r}"
            )
        if self.backend == "maxmind" and not self.maxmind_db_path:
            raise ValueError("geoip.maxmind_db_path is required for the maxmind backend")


@dataclass
class ImpossibleTravelConfig:
    enabled: bool = True
    min_distance_km: float = 500.0
    max_travel_hours: float = 3.0
    critical_distance_km: float = 5000.0
    critical_travel_hours: float = 1.0
    login_events: list[str] = field(default_factory=lambda: list(DEFAULT_LOGIN_EVENTS))
    geoip: GeoIPConfig = field(default_factory=GeoIPConfig)

    def __post_init__(self) -> None:
        if self.min_distance_km <= 0:
            raise ValueError("impossible_travel.min_distance_km must be > 0")
        if self.max_travel_hours <= 0:
            raise ValueError("impossible_travel.max_travel_hours must be > 0")


@dataclass
class NotificationConfig:
    enabled: bool = False
    min_severity: str = "high"
    slack_webhook_url: str | None = None
    webhook_url: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_use_tls: bool = True
    email_from: str | None = None
    email_to: list[str] = field(default_factory=list)
    timeout_seconds: float = 5.0
    max_alerts: int = 20

    def __post_init__(self) -> None:
        self.min_severity = Severity.parse(self.min_severity).value


@dataclass
class Config:
    brute_force: BruteForceConfig = field(default_factory=BruteForceConfig)
    public_storage: PublicStorageConfig = field(default_factory=PublicStorageConfig)
    iam: IAMConfig = field(default_factory=IAMConfig)
    impossible_travel: ImpossibleTravelConfig = field(
        default_factory=ImpossibleTravelConfig
    )
    mfa: MFAConfig = field(default_factory=MFAConfig)
    root_usage: RootUsageConfig = field(default_factory=RootUsageConfig)
    access_keys: AccessKeyConfig = field(default_factory=AccessKeyConfig)
    security_groups: SecurityGroupConfig = field(default_factory=SecurityGroupConfig)
    cloudtrail: CloudTrailConfig = field(default_factory=CloudTrailConfig)
    notifications: NotificationConfig = field(default_factory=NotificationConfig)
    suppression_minutes: int = 60

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Config":
        """Load configuration from *path*, or auto-discover a project config."""

        if path is None:
            path = next((p for p in CONFIG_CANDIDATES if p.exists()), None)
        if path is None:
            return cls()
        path = Path(path)
        data = _read_config_file(path)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "Config":
        if not isinstance(data, dict):
            return cls()
        return cls(
            brute_force=_build(BruteForceConfig, data.get("brute_force")),
            public_storage=_build(PublicStorageConfig, data.get("public_storage")),
            iam=_build(IAMConfig, data.get("iam")),
            impossible_travel=_build(
                ImpossibleTravelConfig, data.get("impossible_travel")
            ),
            mfa=_build(MFAConfig, data.get("mfa")),
            root_usage=_build(RootUsageConfig, data.get("root_usage")),
            access_keys=_build(AccessKeyConfig, data.get("access_keys")),
            security_groups=_build(SecurityGroupConfig, data.get("security_groups")),
            cloudtrail=_build(CloudTrailConfig, data.get("cloudtrail")),
            notifications=_build(NotificationConfig, data.get("notifications")),
            suppression_minutes=int(data.get("suppression_minutes", 60)),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _build(cls: type, data: Any):
    if not isinstance(data, dict):
        return cls()
    allowed = {f.name for f in fields(cls)}
    values = {key: value for key, value in data.items() if key in allowed}
    if cls is ImpossibleTravelConfig and isinstance(values.get("geoip"), dict):
        values["geoip"] = _build(GeoIPConfig, values["geoip"])
    return cls(**values)


def _read_config_file(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".toml":
        return tomllib.loads(text)
    return json.loads(text or "{}")
