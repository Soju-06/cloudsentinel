"""Configuration loading tests."""

from __future__ import annotations

import json

import pytest

from cloudsentinel.config import BruteForceConfig, Config


def test_defaults():
    config = Config()

    assert config.brute_force.threshold == 5
    assert config.brute_force.window_minutes == 10
    assert config.suppression_minutes == 60
    assert config.public_storage.enabled is True
    assert config.mfa.enabled is True
    assert config.root_usage.enabled is True
    assert config.access_keys.enabled is True
    assert config.cloudtrail.enabled is True
    assert 22 in config.security_groups.sensitive_ports
    assert config.root_usage.critical_actions
    assert config.stream.window_minutes == 60
    assert config.stream.max_events == 20000


def test_from_dict_overrides():
    config = Config.from_dict(
        {"brute_force": {"threshold": 3, "window_minutes": 5}, "suppression_minutes": 15}
    )

    assert config.brute_force.threshold == 3
    assert config.brute_force.window_minutes == 5
    assert config.suppression_minutes == 15
    # Unspecified values fall back to defaults.
    assert config.brute_force.critical_multiplier == 3


def test_load_json(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps({"iam": {"enabled": False}, "suppression_minutes": 5}),
        encoding="utf-8",
    )

    config = Config.load(path)

    assert config.iam.enabled is False
    assert config.suppression_minutes == 5


def test_load_toml(tmp_path):
    path = tmp_path / "cloudsentinel.toml"
    path.write_text(
        '[brute_force]\nthreshold = 2\nwindow_minutes = 4\n', encoding="utf-8"
    )

    config = Config.load(path)

    assert config.brute_force.threshold == 2
    assert config.brute_force.window_minutes == 4


def test_roundtrip_to_dict():
    data = Config().to_dict()
    restored = Config.from_dict(data)

    assert restored.brute_force.threshold == 5
    assert restored.public_storage.storage_hints


def test_invalid_group_by_rejected():
    with pytest.raises(ValueError):
        BruteForceConfig(group_by="tenant")


def test_invalid_threshold_rejected():
    with pytest.raises(ValueError):
        BruteForceConfig(threshold=0)


def test_new_detector_sections_load_from_dict():
    config = Config.from_dict(
        {
            "mfa": {"enabled": False},
            "root_usage": {"critical_actions": ["GetCallerIdentity"]},
            "access_keys": {"enabled": False},
            "security_groups": {"sensitive_ports": [8080]},
            "cloudtrail": {"enabled": False},
        }
    )

    assert config.mfa.enabled is False
    assert config.root_usage.critical_actions == ["GetCallerIdentity"]
    assert config.access_keys.enabled is False
    assert config.security_groups.sensitive_ports == [8080]
    assert config.cloudtrail.enabled is False


def test_invalid_sensitive_port_rejected():
    from cloudsentinel.config import SecurityGroupConfig

    with pytest.raises(ValueError):
        SecurityGroupConfig(sensitive_ports=[70000])


def test_stream_section_loads_and_validates():
    from cloudsentinel.config import StreamConfig

    config = Config.from_dict({"stream": {"window_minutes": 15, "max_events": 500}})
    assert config.stream.window_minutes == 15
    assert config.stream.max_events == 500

    with pytest.raises(ValueError):
        StreamConfig(window_minutes=0)
    with pytest.raises(ValueError):
        StreamConfig(max_events=10)
    with pytest.raises(ValueError):
        StreamConfig(poll_seconds=0)
