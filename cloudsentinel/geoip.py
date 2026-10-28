"""Location enrichment for audit events.

Three backends are supported:

* ``event`` (default) — read ``latitude``/``longitude``/``country``/``city``
  fields already present in the log. Fully offline.
* ``maxmind`` — look up IPs with a local GeoLite2/GeoIP2 database
  (``pip install geoip2``).
* ``http`` — call the free ipapi.co lookup service. Disabled by default
  because it sends IP addresses to a third party.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import urllib.request
from dataclasses import dataclass
from typing import Any

from .config import GeoIPConfig
from .utils import is_blank, walk_json

logger = logging.getLogger(__name__)

_EARTH_RADIUS_KM = 6371.0088


@dataclass(frozen=True)
class Location:
    latitude: float
    longitude: float
    country: str | None = None
    city: str | None = None

    @property
    def label(self) -> str:
        parts = [value for value in (self.city, self.country) if value]
        return ", ".join(parts) if parts else f"{self.latitude:.2f},{self.longitude:.2f}"


def haversine_km(origin: Location, destination: Location) -> float:
    """Great-circle distance between two coordinates."""

    lat1, lon1 = math.radians(origin.latitude), math.radians(origin.longitude)
    lat2, lon2 = math.radians(destination.latitude), math.radians(destination.longitude)
    dlat, dlon = lat2 - lat1, lon2 - lon1
    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    )
    return 2 * _EARTH_RADIUS_KM * math.asin(math.sqrt(a))


class GeoIPService:
    """Resolve event/IPs to coordinates with caching and graceful fallback."""

    def __init__(self, config: GeoIPConfig | None = None) -> None:
        self.config = config or GeoIPConfig()
        self._cache: dict[str, Location | None] = {}
        self._maxmind_reader: Any = None
        self._maxmind_failed = False

    def locate(
        self, ip: str | None, record: dict[str, Any] | None = None
    ) -> Location | None:
        explicit = location_from_record(record)
        if explicit is not None:
            return explicit

        if not ip or self.config.backend == "event":
            return None

        ip = str(ip).strip()
        if self.config.cache and ip in self._cache:
            return self._cache[ip]

        if self.config.backend == "maxmind":
            location = self._maxmind_lookup(ip)
        else:
            location = self._http_lookup(ip)

        if self.config.cache:
            self._cache[ip] = location
        return location

    # ------------------------------------------------------------- backends

    def _maxmind_lookup(self, ip: str) -> Location | None:
        if self._maxmind_failed:
            return None
        try:
            import geoip2.database  # type: ignore[import-not-found]
        except ImportError:
            self._maxmind_failed = True
            logger.warning(
                "geoip backend 'maxmind' requires `pip install geoip2`; skipping lookups"
            )
            return None

        try:
            if self._maxmind_reader is None:
                self._maxmind_reader = geoip2.database.Reader(
                    self.config.maxmind_db_path
                )
            response = self._maxmind_reader.city(ip)
        except Exception as exc:  # pragma: no cover - external database
            self._maxmind_failed = True
            logger.warning("MaxMind lookup failed: %s", exc)
            return None

        if response.location.latitude is None or response.location.longitude is None:
            return None
        return Location(
            latitude=float(response.location.latitude),
            longitude=float(response.location.longitude),
            country=getattr(response.country, "name", None),
            city=response.city.name,
        )

    def _http_lookup(self, ip: str) -> Location | None:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if not address.is_global:
            return None

        url = f"https://ipapi.co/{ip}/json/"
        request = urllib.request.Request(
            url, headers={"User-Agent": "CloudSentinel/0.2 geoip"}
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.config.http_timeout_seconds
            ) as response:
                payload = json.loads(response.read().decode("utf-8", "replace"))
        except Exception as exc:  # network failure must never break a scan
            logger.warning("GeoIP HTTP lookup failed for %s: %s", ip, exc)
            return None

        latitude = _coerce_float(payload.get("latitude"))
        longitude = _coerce_float(payload.get("longitude"))
        if latitude is None or longitude is None:
            return None
        return Location(
            latitude=latitude,
            longitude=longitude,
            country=payload.get("country_name") or payload.get("country_code"),
            city=payload.get("city"),
        )


def location_from_record(record: dict[str, Any] | None) -> Location | None:
    """Extract explicit coordinates from an event, including nested objects."""

    if not isinstance(record, dict):
        return None

    candidates: list[dict[str, Any]] = [
        {str(key).lower(): value for key, value in record.items()}
    ]
    for _, node in walk_json(record):
        if not isinstance(node, dict) or node is record:
            continue
        lowered = {str(key).lower(): value for key, value in node.items()}
        if any(key in lowered for key in ("latitude", "lat", "longitude", "lon", "lng")):
            candidates.append(lowered)

    for data in candidates:
        latitude = _first_float(data, ("latitude", "lat"))
        longitude = _first_float(data, ("longitude", "lon", "lng"))
        if latitude is None or longitude is None:
            continue
        if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
            continue
        return Location(
            latitude=latitude,
            longitude=longitude,
            country=_first_str(data, ("country", "country_name", "countrycode", "country_code")),
            city=_first_str(data, ("city", "city_name", "location_name")),
        )
    return None


def _first_float(data: dict[str, Any], keys: tuple[str, ...]) -> float | None:
    for key in keys:
        if key in data:
            value = _coerce_float(data[key])
            if value is not None:
                return value
    return None


def _first_str(data: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = data.get(key)
        if not is_blank(value):
            return str(value)
    return None


def _coerce_float(value: Any) -> float | None:
    if is_blank(value):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
