"""Tests for pydantic models mirroring Firegex DTOs."""

from __future__ import annotations

import base64

from firegex_mcp.models import (
    AppStatus,
    FirewallSettings,
    FwAction,
    FwMode,
    FwProto,
    FwTable,
    IpInterface,
    NfproxyProtocol,
    NfproxyService,
    NfregexService,
    PortHijackService,
    Protocol,
    PyFilterModel,
    RegexMode,
    RegexModel,
    RuleFormAdd,
    RuleInfo,
    RuleModel,
    ServiceStatus,
    StatusMessageModel,
    StatusModel,
)


def test_app_status_values() -> None:
    assert {e.value for e in AppStatus} == {"init", "run"}


def test_protocol_values() -> None:
    assert {e.value for e in Protocol} == {"tcp", "udp"}


def test_nfproxy_protocol_values() -> None:
    assert {e.value for e in NfproxyProtocol} == {"tcp", "http"}


def test_regex_mode_values() -> None:
    assert {e.value for e in RegexMode} == {"C", "S", "B"}


def test_service_status_values() -> None:
    assert {e.value for e in ServiceStatus} == {"active", "stop", "pause"}


def test_fw_action_values() -> None:
    assert {e.value for e in FwAction} == {"accept", "drop", "reject"}


def test_fw_mode_values() -> None:
    assert {e.value for e in FwMode} == {"in", "out", "forward"}


def test_fw_table_values() -> None:
    assert {e.value for e in FwTable} == {"filter", "mangle"}


def test_fw_proto_values() -> None:
    assert {e.value for e in FwProto} == {"tcp", "udp", "both", "any"}


def test_status_model_round_trip() -> None:
    s = StatusModel.model_validate({"status": "run", "loggined": True, "version": "1.2.3"})
    assert s.status == AppStatus.RUN
    assert s.loggined is True
    assert s.version == "1.2.3"


def test_status_message_round_trip() -> None:
    m = StatusMessageModel.model_validate({"status": "ok"})
    assert m.status == "ok"


def test_ip_interface_round_trip() -> None:
    i = IpInterface.model_validate({"name": "eth0", "addr": "10.0.0.1/24"})
    assert i.name == "eth0"
    assert i.addr == "10.0.0.1/24"


# ---------- per-module DTOs (Task 4) ----------


def test_nfregex_service_round_trip() -> None:
    s = NfregexService.model_validate(
        {
            "service_id": "abc",
            "status": "active",
            "port": 8080,
            "name": "vuln",
            "proto": "tcp",
            "ip_int": "0.0.0.0",
            "n_regex": 2,
            "n_packets": 5,
            "fail_open": False,
        }
    )
    assert s.port == 8080
    assert s.status == ServiceStatus.ACTIVE
    assert s.proto == Protocol.TCP


def test_nfproxy_service_round_trip() -> None:
    s = NfproxyService.model_validate(
        {
            "service_id": "abc",
            "status": "stop",
            "port": 80,
            "name": "http",
            "proto": "http",
            "ip_int": "::",
            "n_filters": 1,
            "edited_packets": 0,
            "blocked_packets": 0,
            "fail_open": True,
        }
    )
    assert s.proto == NfproxyProtocol.HTTP


def test_port_hijack_service_round_trip() -> None:
    s = PortHijackService.model_validate(
        {
            "service_id": "abc",
            "active": True,
            "public_port": 22,
            "proxy_port": 2222,
            "name": "ssh",
            "proto": "tcp",
            "ip_src": "0.0.0.0",
            "ip_dst": "127.0.0.1",
        }
    )
    assert s.public_port == 22
    assert s.proxy_port == 2222


def test_regex_model_decodes_base64() -> None:
    encoded = base64.b64encode(b"flag\\{[^}]+\\}").decode()
    r = RegexModel.model_validate(
        {
            "regex": encoded,
            "mode": "B",
            "id": 1,
            "service_id": "abc",
            "n_packets": 0,
            "is_case_sensitive": True,
            "active": True,
        }
    )
    assert r.regex == "flag\\{[^}]+\\}"
    assert r.mode == RegexMode.BOTH


def test_regex_model_passthrough_when_already_plain() -> None:
    # If a caller constructs RegexModel directly with plain text, accept it.
    r = RegexModel(
        regex="flag\\{[^}]+\\}",
        mode=RegexMode.BOTH,
        id=1,
        service_id="abc",
        n_packets=0,
        is_case_sensitive=True,
        active=True,
    )
    assert r.regex == "flag\\{[^}]+\\}"


def test_pyfilter_model_round_trip() -> None:
    f = PyFilterModel.model_validate(
        {
            "name": "block_flag",
            "service_id": "abc",
            "blocked_packets": 3,
            "edited_packets": 1,
            "active": True,
        }
    )
    assert f.name == "block_flag"
    assert f.blocked_packets == 3


def test_rule_model_round_trip() -> None:
    r = RuleModel.model_validate(
        {
            "active": True,
            "name": "drop-bad",
            "proto": "tcp",
            "table": "filter",
            "src": "10.0.0.0/8",
            "dst": "0.0.0.0/0",
            "port_src_from": 1,
            "port_src_to": 65535,
            "port_dst_from": 22,
            "port_dst_to": 22,
            "action": "drop",
            "mode": "in",
        }
    )
    assert r.action == FwAction.DROP
    assert r.mode == FwMode.IN


def test_rule_info_round_trip() -> None:
    info = RuleInfo.model_validate(
        {
            "rules": [],
            "policy": "accept",
            "enabled": True,
        }
    )
    assert info.policy == FwAction.ACCEPT


def test_rule_form_add_round_trip() -> None:
    form = RuleFormAdd(rules=[], policy=FwAction.DROP)
    assert form.policy == FwAction.DROP


def test_firewall_settings_round_trip() -> None:
    s = FirewallSettings.model_validate(
        {
            "keep_rules": True,
            "allow_loopback": True,
            "allow_established": True,
            "allow_icmp": True,
            "multicast_dns": False,
            "allow_upnp": False,
            "drop_invalid": True,
            "allow_dhcp": False,
        }
    )
    assert s.keep_rules is True
    assert s.allow_dhcp is False
