"""Internet-exposed security-group detector tests."""

from __future__ import annotations

import pandas as pd

from cloudsentinel.config import SecurityGroupConfig
from cloudsentinel.detectors import detect_open_security_groups
from cloudsentinel.severity import Severity


def _ingress(build_events, rules, **overrides):
    row = {
        "event_source": "aws.ec2",
        "event_name": "AuthorizeSecurityGroupIngress",
        "user": "alice",
        "status": "success",
        "resource": "sg-0a1b2c3d",
        "request_parameters": {
            "groupId": "sg-0a1b2c3d",
            "ipPermissions": {"items": rules},
        },
    }
    row.update(overrides)
    return build_events([row])


def _rule(port, cidr="0.0.0.0/0", protocol="tcp", **extra):
    rule = {
        "ipProtocol": protocol,
        "fromPort": port,
        "toPort": port,
        "ipRanges": {"items": [{"cidrIp": cidr}]},
    }
    rule.update(extra)
    return rule


def test_ssh_open_to_the_world_is_critical(build_events):
    events = _ingress(build_events, [_rule(22)])

    alerts = detect_open_security_groups(events)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.detector == "security_group_open"
    assert alert.severity == Severity.CRITICAL
    assert alert.entity == "sg-0a1b2c3d"
    assert alert.entity_type == "security_group"
    assert "tcp/22 open to 0.0.0.0/0" in alert.description


def test_non_sensitive_port_is_high(build_events):
    events = _ingress(build_events, [_rule(80)])

    alerts = detect_open_security_groups(events)

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.HIGH


def test_all_traffic_is_critical(build_events):
    events = _ingress(
        build_events,
        [{"ipProtocol": "-1", "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}],
    )

    alerts = detect_open_security_groups(events)

    assert alerts[0].severity == Severity.CRITICAL
    assert "all traffic" in alerts[0].description


def test_ipv6_and_port_ranges(build_events):
    events = _ingress(
        build_events,
        [
            {
                "ipProtocol": "tcp",
                "fromPort": 8000,
                "toPort": 9500,
                "ipv6Ranges": {"items": [{"cidrIpv6": "::/0"}]},
            }
        ],
    )

    alerts = detect_open_security_groups(events)

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.CRITICAL  # 9200 falls inside the range
    assert "::/0" in alerts[0].description


def test_private_ranges_are_ignored(build_events):
    events = _ingress(build_events, [_rule(22, cidr="10.0.0.0/8")])
    assert detect_open_security_groups(events) == []


def test_flat_generic_parameters_are_supported(build_events):
    events = build_events(
        [
            {
                "event_source": "aws.ec2",
                "event_name": "AuthorizeSecurityGroupIngress",
                "user": "alice",
                "status": "success",
                "request_parameters": {
                    "group_id": "sg-flat",
                    "cidr_ip": "0.0.0.0/0",
                    "from_port": 3389,
                    "to_port": 3389,
                    "protocol": "tcp",
                },
            }
        ]
    )

    alerts = detect_open_security_groups(events)

    assert len(alerts) == 1
    assert alerts[0].entity == "sg-flat"
    assert alerts[0].severity == Severity.CRITICAL


def test_rules_aggregate_per_security_group(build_events):
    events = _ingress(
        build_events,
        [_rule(22), _rule(443)],
    )

    alerts = detect_open_security_groups(events)

    assert len(alerts) == 1
    assert alerts[0].event_count == 1
    assert len(alerts[0].evidence["open_rules"]) == 2
    assert alerts[0].severity == Severity.CRITICAL


def test_non_ingress_events_are_ignored(build_events):
    events = _ingress(
        build_events,
        [_rule(22)],
        event_name="DescribeSecurityGroups",
    )
    assert detect_open_security_groups(events) == []


def test_custom_sensitive_ports(build_events):
    events = _ingress(build_events, [_rule(80)])
    config = SecurityGroupConfig(sensitive_ports=[80])

    assert detect_open_security_groups(events, config)[0].severity == Severity.CRITICAL


def test_disabled_config_and_empty_input(build_events):
    events = _ingress(build_events, [_rule(22)])

    assert (
        detect_open_security_groups(events, SecurityGroupConfig(enabled=False)) == []
    )
    assert detect_open_security_groups(pd.DataFrame()) == []
