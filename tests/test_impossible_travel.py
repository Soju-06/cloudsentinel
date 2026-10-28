"""Impossible-travel and geolocation tests."""

from __future__ import annotations

from cloudsentinel.config import ImpossibleTravelConfig
from cloudsentinel.detectors import detect_impossible_travel
from cloudsentinel.geoip import Location, haversine_km, location_from_record
from cloudsentinel.severity import Severity

NEW_YORK = {"country": "United States", "city": "New York", "latitude": 40.7128, "longitude": -74.0060}
LONDON = {"country": "United Kingdom", "city": "London", "latitude": 51.5074, "longitude": -0.1278}
BOSTON = {"country": "United States", "city": "Boston", "latitude": 42.3601, "longitude": -71.0589}


def login(index: int, geo: dict, **overrides):
    row = {
        "offset": index,
        "event_name": "ConsoleLogin",
        "status": "success",
        **geo,
    }
    row.update(overrides)
    return row


def test_haversine_distance():
    distance = haversine_km(
        Location(40.7128, -74.0060), Location(51.5074, -0.1278)
    )
    assert 5500 < distance < 5650


def test_impossible_travel_detected(build_events):
    events = build_events([login(0, NEW_YORK), login(3600, LONDON)])

    alerts = detect_impossible_travel(events)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.detector == "impossible_travel"
    assert alert.severity == Severity.CRITICAL
    assert alert.entity == "alice"
    assert alert.evidence["distance_km"] > 5000
    assert alert.evidence["from"]["city"] == "New York"
    assert alert.evidence["to"]["city"] == "London"


def test_high_severity_for_slower_travel(build_events):
    events = build_events([login(0, NEW_YORK), login(2 * 3600, LONDON)])
    alerts = detect_impossible_travel(events)
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.HIGH


def test_enough_time_is_not_impossible(build_events):
    events = build_events([login(0, NEW_YORK), login(4 * 3600, LONDON)])
    assert detect_impossible_travel(events) == []


def test_short_distance_is_ignored(build_events):
    events = build_events([login(0, NEW_YORK), login(1800, BOSTON)])
    assert detect_impossible_travel(events) == []


def test_failed_logins_are_ignored(build_events):
    events = build_events(
        [
            login(0, NEW_YORK),
            login(3600, LONDON, status="failure", error_code="Failed authentication"),
        ]
    )
    assert detect_impossible_travel(events) == []


def test_non_login_events_are_ignored(build_events):
    events = build_events(
        [
            login(0, NEW_YORK, event_name="GetObject"),
            login(3600, LONDON, event_name="GetObject"),
        ]
    )
    assert detect_impossible_travel(events) == []


def test_missing_geo_data_is_ignored(build_events):
    events = build_events(
        [
            {"offset": 0, "event_name": "ConsoleLogin", "status": "success"},
            {"offset": 3600, "event_name": "ConsoleLogin", "status": "success"},
        ]
    )
    assert detect_impossible_travel(events) == []


def test_flat_lat_lon_keys(build_events):
    events = build_events(
        [
            {"offset": 0, "status": "success", "lat": 40.7128, "lon": -74.0060},
            {"offset": 3600, "status": "success", "lat": 51.5074, "lng": -0.1278},
        ]
    )
    alerts = detect_impossible_travel(events)
    assert len(alerts) == 1


def test_nested_location_object(build_events):
    events = build_events(
        [
            {
                "offset": 0,
                "status": "success",
                "request_parameters": {
                    "location": {"Latitude": 40.7128, "Longitude": -74.0060}
                },
            },
            {
                "offset": 3600,
                "status": "success",
                "request_parameters": {
                    "location": {"latitude": 51.5074, "longitude": -0.1278}
                },
            },
        ]
    )
    alerts = detect_impossible_travel(events)
    assert len(alerts) == 1


def test_config_threshold_override(build_events):
    events = build_events([login(0, NEW_YORK), login(3600, LONDON)])
    config = ImpossibleTravelConfig(min_distance_km=10_000)
    assert detect_impossible_travel(events, config) == []


def test_disabled_config(build_events):
    events = build_events([login(0, NEW_YORK), login(3600, LONDON)])
    assert detect_impossible_travel(events, ImpossibleTravelConfig(enabled=False)) == []


def test_empty_input():
    import pandas as pd

    assert detect_impossible_travel(pd.DataFrame()) == []


def test_location_from_record_variants():
    assert location_from_record({"latitude": 1.0, "longitude": 2.0}).latitude == 1.0
    assert location_from_record({"geo": {"lat": "3.5", "lon": "4.5"}}).longitude == 4.5
    assert location_from_record({"latitude": 999, "longitude": 2.0}) is None
    assert location_from_record({}) is None
    assert location_from_record(None) is None
