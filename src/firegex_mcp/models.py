"""Pydantic models matching Firegex REST DTOs.

Source of truth: firegex/backend/{utils/models.py, routers/*.py, modules/*/models.py}.
Firegex's API uses snake_case JSON, so no alias generator is needed.
"""

from __future__ import annotations

import base64
import binascii
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict

# ---------- enums ----------


class AppStatus(str, Enum):
    INIT = "init"
    RUN = "run"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"


class NfproxyProtocol(str, Enum):
    TCP = "tcp"
    HTTP = "http"


class RegexMode(str, Enum):
    CLIENT = "C"
    SERVER = "S"
    BOTH = "B"


class ServiceStatus(str, Enum):
    ACTIVE = "active"
    STOP = "stop"
    PAUSE = "pause"


class FwAction(str, Enum):
    ACCEPT = "accept"
    DROP = "drop"
    REJECT = "reject"


class FwMode(str, Enum):
    IN = "in"
    OUT = "out"
    FORWARD = "forward"


class FwTable(str, Enum):
    FILTER = "filter"
    MANGLE = "mangle"


class FwProto(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    BOTH = "both"
    ANY = "any"


# ---------- base ----------


class _Base(BaseModel):
    """Base model that allows both alias and field-name population."""

    model_config = ConfigDict(populate_by_name=True, use_enum_values=False)


# ---------- shared DTOs ----------


class StatusModel(_Base):
    status: AppStatus
    loggined: bool
    version: str


class StatusMessageModel(_Base):
    status: str


class IpInterface(_Base):
    name: str
    addr: str


# ---------- regex base64 helper ----------


def _b64decode_str(value: str) -> str:
    """Decode a base64-encoded UTF-8 string. Pass plain text through unchanged.

    Firegex stores regexes base64-encoded in JSON. Callers who construct
    RegexModel directly may pass plain text; we accept both so model_validate
    on raw API output and direct construction work the same way.
    """
    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return value


# ---------- nfregex ----------


class NfregexService(_Base):
    service_id: str
    status: ServiceStatus
    port: int
    name: str
    proto: Protocol
    ip_int: str
    n_regex: int = 0
    n_packets: int = 0
    fail_open: bool = False


class RegexModel(_Base):
    """Regex row. `regex` is exposed as plain text; on the wire it's base64."""

    regex: str
    mode: RegexMode
    id: int
    service_id: str
    n_packets: int = 0
    is_case_sensitive: bool
    active: bool

    @classmethod
    def model_validate(
        cls,
        obj: Any,
        *args: Any,
        **kwargs: Any,
    ) -> RegexModel:
        # Decode the regex field if it came from the API as base64.
        if isinstance(obj, dict) and "regex" in obj and isinstance(obj["regex"], str):
            obj = {**obj, "regex": _b64decode_str(obj["regex"])}
        return super().model_validate(obj, *args, **kwargs)


# ---------- nfproxy ----------


class NfproxyService(_Base):
    service_id: str
    status: ServiceStatus
    port: int
    name: str
    proto: NfproxyProtocol
    ip_int: str
    n_filters: int = 0
    edited_packets: int = 0
    blocked_packets: int = 0
    fail_open: bool = True


class PyFilterModel(_Base):
    name: str
    service_id: str
    blocked_packets: int = 0
    edited_packets: int = 0
    active: bool = True


# ---------- firewall ----------


class FirewallSettings(_Base):
    keep_rules: bool
    allow_loopback: bool
    allow_established: bool
    allow_icmp: bool
    multicast_dns: bool
    allow_upnp: bool
    drop_invalid: bool
    allow_dhcp: bool


class RuleModel(_Base):
    active: bool
    name: str
    proto: FwProto
    table: FwTable
    src: str
    dst: str
    port_src_from: int
    port_src_to: int
    port_dst_from: int
    port_dst_to: int
    action: FwAction
    mode: FwMode


class RuleInfo(_Base):
    rules: list[RuleModel]
    policy: FwAction
    enabled: bool


class RuleFormAdd(_Base):
    rules: list[RuleModel]
    policy: FwAction


# ---------- porthijack ----------


class PortHijackService(_Base):
    service_id: str
    active: bool
    public_port: int
    proxy_port: int
    name: str
    proto: Protocol
    ip_src: str
    ip_dst: str
