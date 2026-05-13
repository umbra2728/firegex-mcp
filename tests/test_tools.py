"""Integration tests for MCP tools.

We import the registered tool callables directly from FastMCP and exercise them
against a mocked Firegex HTTP API. The FastMCP tool registry stores tools in
`_tool_manager._tools`; each entry exposes the underlying coroutine as `.fn`.
"""

from __future__ import annotations

import base64
import pathlib
from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
import respx
from mcp.server.fastmcp import FastMCP

from firegex_mcp.client import FiregexClient
from firegex_mcp.config import FiregexSettings
from firegex_mcp.models import FwAction, FwMode, FwProto, FwTable, RuleModel


@pytest_asyncio.fixture
async def client() -> AsyncIterator[FiregexClient]:
    async with FiregexClient(FiregexSettings(password="p")) as c:
        yield c


def _mcp() -> FastMCP:
    return FastMCP("firegex-test")


def _tool_fn(mcp: FastMCP, name: str):  # type: ignore[no-untyped-def]
    return mcp._tool_manager._tools[name].fn


async def _logged_in(mock: respx.Router) -> None:
    mock.get("/api/status").mock(
        return_value=httpx.Response(
            200, json={"status": "run", "loggined": False, "version": "1.0"}
        )
    )
    mock.post("/api/login").mock(
        return_value=httpx.Response(200, json={"access_token": "T", "token_type": "bearer"})
    )


# ---------- system ----------


async def test_get_firegex_status_tool(client: FiregexClient) -> None:
    from firegex_mcp.tools.system import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "get_firegex_status")

    with respx.mock(base_url="http://localhost:4444") as mock:
        mock.get("/api/status").mock(
            return_value=httpx.Response(
                200, json={"status": "run", "loggined": False, "version": "1.0"}
            )
        )
        result = await fn()
        assert result.status.value == "run"
        assert result.version == "1.0"


async def test_set_password_tool(client: FiregexClient) -> None:
    from firegex_mcp.tools.system import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "set_password")

    with respx.mock(base_url="http://localhost:4444") as mock:
        route = mock.post("/api/set-password").mock(
            return_value=httpx.Response(200, json={"status": "ok", "access_token": "T"})
        )
        await fn(password="secret")
        assert route.called


async def test_list_interfaces_tool(client: FiregexClient) -> None:
    from firegex_mcp.tools.system import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "list_interfaces")

    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        mock.get("/api/interfaces").mock(
            return_value=httpx.Response(200, json=[{"name": "lo", "addr": "127.0.0.1"}])
        )
        ifs = await fn()
        assert ifs[0].name == "lo"


async def test_reset_firegex_tool_requires_explicit_flag(client: FiregexClient) -> None:
    from firegex_mcp.tools.system import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "reset_firegex")

    with pytest.raises(TypeError):
        await fn()


async def test_reset_firegex_tool_passes_delete(client: FiregexClient) -> None:
    from firegex_mcp.tools.system import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "reset_firegex")

    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        route = mock.post("/api/reset").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )
        await fn(delete=False)
        body = route.calls[0].request.read().decode()
        assert '"delete":false' in body


# ---------- nfregex ----------


async def test_nfregex_services_listed(client: FiregexClient) -> None:
    from firegex_mcp.tools.nfregex import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "list_nfregex_services")

    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        mock.get("/api/nfregex/services").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "service_id": "abc",
                        "status": "active",
                        "port": 8080,
                        "name": "vuln",
                        "proto": "tcp",
                        "ip_int": "0.0.0.0",
                        "n_regex": 0,
                        "n_packets": 0,
                        "fail_open": False,
                    }
                ],
            )
        )
        svcs = await fn()
        assert svcs[0].service_id == "abc"


async def test_add_regex_tool_encodes_b64(client: FiregexClient) -> None:
    from firegex_mcp.tools.nfregex import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "add_regex")

    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        route = mock.post("/api/nfregex/regexes").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )
        await fn(
            service_id="abc",
            regex="flag\\{.+\\}",
            mode="B",
            is_case_sensitive=True,
            active=True,
        )
        body = route.calls[0].request.read().decode()
        expected = base64.b64encode(b"flag\\{.+\\}").decode()
        assert f'"regex":"{expected}"' in body


async def test_list_regexes_decodes_b64_via_tool(client: FiregexClient) -> None:
    from firegex_mcp.tools.nfregex import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "list_regexes")

    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        encoded = base64.b64encode(b"x").decode()
        mock.get("/api/nfregex/services/abc/regexes").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "regex": encoded,
                        "mode": "C",
                        "id": 1,
                        "service_id": "abc",
                        "n_packets": 0,
                        "is_case_sensitive": False,
                        "active": True,
                    }
                ],
            )
        )
        rxs = await fn(service_id="abc")
        assert rxs[0].regex == "x"


async def test_get_nfregex_metrics_tool(client: FiregexClient) -> None:
    from firegex_mcp.tools.nfregex import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "get_nfregex_metrics")

    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        mock.get("/api/nfregex/metrics").mock(
            return_value=httpx.Response(200, text="firegex_blocked_packets{...} 7")
        )
        t = await fn()
        assert "firegex_blocked_packets" in t


# ---------- nfproxy ----------


async def test_nfproxy_services_listed(client: FiregexClient) -> None:
    from firegex_mcp.tools.nfproxy import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "list_nfproxy_services")

    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        mock.get("/api/nfproxy/services").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "service_id": "abc",
                        "status": "active",
                        "port": 80,
                        "name": "http",
                        "proto": "http",
                        "ip_int": "0.0.0.0",
                        "n_filters": 0,
                        "edited_packets": 0,
                        "blocked_packets": 0,
                        "fail_open": True,
                    }
                ],
            )
        )
        svcs = await fn()
        assert svcs[0].port == 80


async def test_set_pyfilter_code_tool(client: FiregexClient) -> None:
    from firegex_mcp.tools.nfproxy import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "set_pyfilter_code")

    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        route = mock.put("/api/nfproxy/services/abc/code").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )
        await fn(service_id="abc", code="print('x')")
        body = route.calls[0].request.read().decode()
        assert '"code":"print(\'x\')"' in body


async def test_set_pyfilter_code_from_file_tool(
    client: FiregexClient, tmp_path: pathlib.Path
) -> None:
    from firegex_mcp.tools.nfproxy import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "set_pyfilter_code_from_file")

    f = tmp_path / "filter.py"
    f.write_text("from firegex.nfproxy import pyfilter\n", encoding="utf-8")

    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        route = mock.put("/api/nfproxy/services/abc/code").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )
        await fn(service_id="abc", path=str(f))
        body = route.calls[0].request.read().decode()
        assert "from firegex.nfproxy" in body


async def test_set_pyfilter_code_from_file_missing(client: FiregexClient) -> None:
    from firegex_mcp.tools.nfproxy import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "set_pyfilter_code_from_file")
    with pytest.raises(FileNotFoundError):
        await fn(service_id="abc", path="/nonexistent/filter.py")


async def test_set_pyfilter_code_from_file_too_large(
    client: FiregexClient, tmp_path: pathlib.Path
) -> None:
    from firegex_mcp.tools.nfproxy import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "set_pyfilter_code_from_file")
    f = tmp_path / "big.py"
    f.write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(ValueError, match="too large"):
        await fn(service_id="abc", path=str(f))


async def test_pyfilter_enable_disable_tools(client: FiregexClient) -> None:
    from firegex_mcp.tools.nfproxy import register

    mcp = _mcp()
    register(mcp, client)
    en_fn = _tool_fn(mcp, "enable_pyfilter")
    dis_fn = _tool_fn(mcp, "disable_pyfilter")
    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        en = mock.post("/api/nfproxy/services/abc/pyfilters/f/enable").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )
        dis = mock.post("/api/nfproxy/services/abc/pyfilters/f/disable").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )
        await en_fn(service_id="abc", filter_name="f")
        await dis_fn(service_id="abc", filter_name="f")
        assert en.called and dis.called


# ---------- firewall ----------


async def test_list_firewall_rules_tool(client: FiregexClient) -> None:
    from firegex_mcp.tools.firewall import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "list_firewall_rules")
    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        mock.get("/api/firewall/rules").mock(
            return_value=httpx.Response(
                200, json={"rules": [], "policy": "drop", "enabled": False}
            )
        )
        info = await fn()
        assert info.policy.value == "drop"
        assert info.enabled is False


async def test_enable_disable_firewall_tools(client: FiregexClient) -> None:
    from firegex_mcp.tools.firewall import register

    mcp = _mcp()
    register(mcp, client)
    en_fn = _tool_fn(mcp, "enable_firewall")
    dis_fn = _tool_fn(mcp, "disable_firewall")
    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        en = mock.post("/api/firewall/enable").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )
        dis = mock.post("/api/firewall/disable").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )
        await en_fn()
        await dis_fn()
        assert en.called and dis.called


async def test_replace_firewall_rules_tool(client: FiregexClient) -> None:
    from firegex_mcp.tools.firewall import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "replace_firewall_rules")
    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        route = mock.post("/api/firewall/rules").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )
        rule = RuleModel(
            active=True,
            name="drop-all",
            proto=FwProto.ANY,
            table=FwTable.FILTER,
            src="0.0.0.0/0",
            dst="0.0.0.0/0",
            port_src_from=1,
            port_src_to=65535,
            port_dst_from=1,
            port_dst_to=65535,
            action=FwAction.DROP,
            mode=FwMode.IN,
        )
        await fn(policy=FwAction.ACCEPT, rules=[rule])
        body = route.calls[0].request.read().decode()
        assert '"policy":"accept"' in body
        assert '"name":"drop-all"' in body


async def test_set_firewall_settings_tool(client: FiregexClient) -> None:
    from firegex_mcp.tools.firewall import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "set_firewall_settings")
    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        route = mock.put("/api/firewall/settings").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )
        await fn(
            keep_rules=True,
            allow_loopback=True,
            allow_established=True,
            allow_icmp=True,
            multicast_dns=False,
            allow_upnp=False,
            drop_invalid=True,
            allow_dhcp=False,
        )
        body = route.calls[0].request.read().decode()
        assert '"keep_rules":true' in body
        assert '"allow_dhcp":false' in body


# ---------- porthijack ----------


async def test_phj_services_listed(client: FiregexClient) -> None:
    from firegex_mcp.tools.porthijack import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "list_phj_services")
    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        mock.get("/api/porthijack/services").mock(
            return_value=httpx.Response(
                200,
                json=[
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
                ],
            )
        )
        svcs = await fn()
        assert svcs[0].public_port == 22


async def test_add_phj_service_tool(client: FiregexClient) -> None:
    from firegex_mcp.tools.porthijack import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "add_phj_service")
    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        route = mock.post("/api/porthijack/services").mock(
            return_value=httpx.Response(200, json={"status": "ok", "service_id": "abc"})
        )
        await fn(
            name="ssh",
            public_port=22,
            proxy_port=2222,
            proto="tcp",
            ip_src="0.0.0.0",
            ip_dst="127.0.0.1",
        )
        body = route.calls[0].request.read().decode()
        assert '"public_port":22' in body
        assert '"ip_dst":"127.0.0.1"' in body


async def test_change_phj_destination_tool(client: FiregexClient) -> None:
    from firegex_mcp.tools.porthijack import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "change_phj_destination")
    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        route = mock.put("/api/porthijack/services/abc/change-destination").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )
        await fn(service_id="abc", ip_dst="10.0.0.5", proxy_port=4444)
        body = route.calls[0].request.read().decode()
        assert '"ip_dst":"10.0.0.5"' in body
        assert '"proxy_port":4444' in body


# ---------- wiring ----------


async def test_register_all_wires_all_modules(client: FiregexClient) -> None:
    from firegex_mcp.tools import register_all

    mcp = _mcp()
    register_all(mcp, client)
    names = set(mcp._tool_manager._tools.keys())
    # Spot-check one tool from each module.
    assert {
        "get_firegex_status",
        "list_nfregex_services",
        "list_nfproxy_services",
        "list_firewall_rules",
        "list_phj_services",
    }.issubset(names)
