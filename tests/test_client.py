"""Tests for FiregexClient HTTP layer, auth lifecycle, and per-module methods."""

from __future__ import annotations

import asyncio
import base64

import httpx
import pytest
import respx

from firegex_mcp.client import (
    FiregexAuthError,
    FiregexClient,
    FiregexConnectionError,
    FiregexError,
    FiregexNotFoundError,
    FiregexNotInitializedError,
    FiregexServerError,
    FiregexValidationError,
)
from firegex_mcp.config import FiregexSettings
from firegex_mcp.models import (
    FirewallSettings,
    FwAction,
    FwMode,
    FwProto,
    FwTable,
    IpInterface,
    NfproxyService,
    NfregexService,
    PortHijackService,
    PyFilterModel,
    RegexMode,
    RegexModel,
    RuleInfo,
    RuleModel,
)


def _settings() -> FiregexSettings:
    return FiregexSettings(password="p")


async def _logged_in(mock: respx.Router) -> None:
    mock.get("/api/status").mock(
        return_value=httpx.Response(
            200, json={"status": "run", "loggined": False, "version": "1.0"}
        )
    )
    mock.post("/api/login").mock(
        return_value=httpx.Response(200, json={"access_token": "T", "token_type": "bearer"})
    )


def _nfregex_service_json(sid: str = "abc") -> dict:
    return {
        "service_id": sid,
        "status": "active",
        "port": 8080,
        "name": "vuln",
        "proto": "tcp",
        "ip_int": "0.0.0.0",
        "n_regex": 0,
        "n_packets": 0,
        "fail_open": False,
    }


def _nfproxy_service_json(sid: str = "abc") -> dict:
    return {
        "service_id": sid,
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


def _phj_service_json(sid: str = "abc") -> dict:
    return {
        "service_id": sid,
        "active": True,
        "public_port": 22,
        "proxy_port": 2222,
        "name": "ssh",
        "proto": "tcp",
        "ip_src": "0.0.0.0",
        "ip_dst": "127.0.0.1",
    }


# ---------- exceptions ----------


def test_exception_hierarchy() -> None:
    for sub in (
        FiregexAuthError,
        FiregexConnectionError,
        FiregexNotFoundError,
        FiregexNotInitializedError,
        FiregexValidationError,
        FiregexServerError,
    ):
        assert issubclass(sub, FiregexError)


def test_exceptions_carry_messages() -> None:
    e = FiregexNotFoundError("Regex 42 not found.")
    assert str(e) == "Regex 42 not found."


# ---------- _request status mapping ----------


async def test_request_maps_401_to_auth_error() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/api/status").mock(
                return_value=httpx.Response(
                    200, json={"status": "run", "loggined": False, "version": "1.0"}
                )
            )
            mock.post("/api/login").mock(return_value=httpx.Response(401))
            with pytest.raises(FiregexAuthError) as exc:
                await client.get_status_authed()
            assert "Wrong password" in str(exc.value)


async def test_request_maps_404_to_not_found() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/x").mock(return_value=httpx.Response(404))
            with pytest.raises(FiregexNotFoundError):
                await client._request("GET", "/x", authed=False)


async def test_request_maps_400_to_validation_error_with_body() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.post("/x").mock(return_value=httpx.Response(400, text="bad regex"))
            with pytest.raises(FiregexValidationError) as exc:
                await client._request("POST", "/x", authed=False)
            assert "bad regex" in str(exc.value)


async def test_request_maps_500_to_server_error() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/x").mock(return_value=httpx.Response(500, text="boom"))
            with pytest.raises(FiregexServerError) as exc:
                await client._request("GET", "/x", authed=False)
            assert "500" in str(exc.value)
            assert "boom" in str(exc.value)


async def test_request_maps_connection_error() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/x").mock(side_effect=httpx.ConnectError("refused"))
            with pytest.raises(FiregexConnectionError) as exc:
                await client._request("GET", "/x", authed=False)
            assert "Cannot reach Firegex" in str(exc.value)


async def test_request_maps_timeout() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/x").mock(side_effect=httpx.TimeoutException("slow"))
            with pytest.raises(FiregexConnectionError) as exc:
                await client._request("GET", "/x", authed=False)
            assert "timed out" in str(exc.value).lower()


async def test_not_initialized_when_status_init() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/api/status").mock(
                return_value=httpx.Response(
                    200, json={"status": "init", "loggined": False, "version": "1.0"}
                )
            )
            with pytest.raises(FiregexNotInitializedError):
                await client.get_status_authed()


# ---------- auth lifecycle ----------


async def test_login_caches_token_and_attaches_bearer() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/api/status").mock(
                return_value=httpx.Response(
                    200, json={"status": "run", "loggined": False, "version": "1.0"}
                )
            )
            login = mock.post("/api/login").mock(
                return_value=httpx.Response(
                    200, json={"access_token": "TKN", "token_type": "bearer"}
                )
            )
            target = mock.get("/api/anywhere").mock(return_value=httpx.Response(200, json=[]))

            await client._request("GET", "/api/anywhere")
            assert login.call_count == 1
            assert target.calls[0].request.headers["Authorization"] == "Bearer TKN"

            await client._request("GET", "/api/anywhere")
            assert login.call_count == 1


async def test_login_form_sends_password_field() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/api/status").mock(
                return_value=httpx.Response(
                    200, json={"status": "run", "loggined": False, "version": "1.0"}
                )
            )
            login = mock.post("/api/login").mock(
                return_value=httpx.Response(
                    200, json={"access_token": "TKN", "token_type": "bearer"}
                )
            )
            mock.get("/api/anywhere").mock(return_value=httpx.Response(200, json=[]))

            await client._request("GET", "/api/anywhere")
            body = login.calls[0].request.read().decode()
            assert "password=p" in body
            assert "grant_type=password" in body


async def test_401_triggers_one_retry() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/api/status").mock(
                return_value=httpx.Response(
                    200, json={"status": "run", "loggined": False, "version": "1.0"}
                )
            )
            login = mock.post("/api/login").mock(
                return_value=httpx.Response(
                    200, json={"access_token": "TKN", "token_type": "bearer"}
                )
            )
            target = mock.get("/api/anywhere").mock(
                side_effect=[httpx.Response(401), httpx.Response(200, json=[])]
            )

            await client._request("GET", "/api/anywhere")
            assert login.call_count == 2
            assert target.call_count == 2


async def test_double_401_raises_auth_error() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/api/status").mock(
                return_value=httpx.Response(
                    200, json={"status": "run", "loggined": False, "version": "1.0"}
                )
            )
            mock.post("/api/login").mock(
                return_value=httpx.Response(
                    200, json={"access_token": "TKN", "token_type": "bearer"}
                )
            )
            mock.get("/api/anywhere").mock(return_value=httpx.Response(401))
            with pytest.raises(FiregexAuthError) as exc:
                await client._request("GET", "/api/anywhere")
            assert "after re-login" in str(exc.value)


async def test_concurrent_first_calls_share_one_login() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/api/status").mock(
                return_value=httpx.Response(
                    200, json={"status": "run", "loggined": False, "version": "1.0"}
                )
            )
            login = mock.post("/api/login").mock(
                return_value=httpx.Response(
                    200, json={"access_token": "TKN", "token_type": "bearer"}
                )
            )
            mock.get("/api/anywhere").mock(return_value=httpx.Response(200, json=[]))

            await asyncio.gather(*(client._request("GET", "/api/anywhere") for _ in range(5)))
            assert login.call_count == 1


async def test_public_paths_skip_login() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            status = mock.get("/api/status").mock(
                return_value=httpx.Response(
                    200, json={"status": "run", "loggined": False, "version": "1.0"}
                )
            )
            # No /api/login mock registered; if the client attempted to call it,
            # respx would raise "unmocked call" and the test would fail.
            await client.get_status()
            assert status.called


# ---------- system methods ----------


async def test_set_password() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            route = mock.post("/api/set-password").mock(
                return_value=httpx.Response(200, json={"status": "ok", "access_token": "T"})
            )
            result = await client.set_password("newpass")
            assert result == {"status": "ok", "access_token": "T"}
            body = route.calls[0].request.read().decode()
            assert '"password":"newpass"' in body


async def test_change_password() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            route = mock.post("/api/change-password").mock(
                return_value=httpx.Response(200, json={"status": "ok", "access_token": "T2"})
            )
            await client.change_password("new", expire=True)
            body = route.calls[0].request.read().decode()
            assert '"password":"new"' in body
            assert '"expire":true' in body
            assert client._token is None


async def test_change_password_keeps_token_when_no_expire() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            mock.post("/api/change-password").mock(
                return_value=httpx.Response(200, json={"status": "ok", "access_token": "T"})
            )
            await client.change_password("new", expire=False)
            assert client._token == "T"


async def test_list_interfaces() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            mock.get("/api/interfaces").mock(
                return_value=httpx.Response(200, json=[{"name": "eth0", "addr": "10.0.0.1"}])
            )
            ifs = await client.list_interfaces()
            assert ifs == [IpInterface(name="eth0", addr="10.0.0.1")]


async def test_reset_firegex() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            route = mock.post("/api/reset").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            await client.reset(delete=True)
            body = route.calls[0].request.read().decode()
            assert '"delete":true' in body


# ---------- nfregex ----------


async def test_list_nfregex_services() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            mock.get("/api/nfregex/services").mock(
                return_value=httpx.Response(200, json=[_nfregex_service_json()])
            )
            svcs = await client.list_nfregex_services()
            assert len(svcs) == 1
            assert isinstance(svcs[0], NfregexService)


async def test_get_nfregex_service() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            mock.get("/api/nfregex/services/abc").mock(
                return_value=httpx.Response(200, json=_nfregex_service_json())
            )
            s = await client.get_nfregex_service("abc")
            assert s.service_id == "abc"


async def test_add_nfregex_service() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            route = mock.post("/api/nfregex/services").mock(
                return_value=httpx.Response(200, json={"status": "ok", "service_id": "abc"})
            )
            r = await client.add_nfregex_service(
                name="vuln", port=8080, proto="tcp", ip_int="0.0.0.0", fail_open=False
            )
            assert r["service_id"] == "abc"
            body = route.calls[0].request.read().decode()
            assert '"port":8080' in body
            assert '"proto":"tcp"' in body


async def test_start_stop_delete_nfregex_service() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            r_start = mock.post("/api/nfregex/services/abc/start").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            r_stop = mock.post("/api/nfregex/services/abc/stop").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            r_del = mock.delete("/api/nfregex/services/abc").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            await client.start_nfregex_service("abc")
            await client.stop_nfregex_service("abc")
            await client.delete_nfregex_service("abc")
            assert r_start.called and r_stop.called and r_del.called


async def test_rename_nfregex_service() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            route = mock.put("/api/nfregex/services/abc/rename").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            await client.rename_nfregex_service("abc", "newname")
            body = route.calls[0].request.read().decode()
            assert '"name":"newname"' in body


async def test_update_nfregex_service_settings() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            route = mock.put("/api/nfregex/services/abc/settings").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            await client.update_nfregex_service_settings("abc", port=9090, fail_open=True)
            body = route.calls[0].request.read().decode()
            assert '"port":9090' in body
            assert '"fail_open":true' in body
            assert "proto" not in body


async def test_list_regexes_decodes_base64() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            encoded = base64.b64encode(b"flag\\{[^}]+\\}").decode()
            mock.get("/api/nfregex/services/abc/regexes").mock(
                return_value=httpx.Response(
                    200,
                    json=[
                        {
                            "regex": encoded,
                            "mode": "B",
                            "id": 1,
                            "service_id": "abc",
                            "n_packets": 0,
                            "is_case_sensitive": True,
                            "active": True,
                        }
                    ],
                )
            )
            rxs = await client.list_regexes("abc")
            assert len(rxs) == 1
            assert rxs[0].regex == "flag\\{[^}]+\\}"


async def test_add_regex_encodes_base64() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            route = mock.post("/api/nfregex/regexes").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            await client.add_regex(
                service_id="abc",
                regex="flag\\{[^}]+\\}",
                mode=RegexMode.BOTH,
                is_case_sensitive=True,
                active=True,
            )
            body = route.calls[0].request.read().decode()
            sent_b64 = base64.b64encode(b"flag\\{[^}]+\\}").decode()
            assert f'"regex":"{sent_b64}"' in body
            assert '"mode":"B"' in body


async def test_regex_enable_disable_delete() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            r_get = mock.get("/api/nfregex/regexes/7").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "regex": base64.b64encode(b"x").decode(),
                        "mode": "C",
                        "id": 7,
                        "service_id": "abc",
                        "n_packets": 0,
                        "is_case_sensitive": False,
                        "active": True,
                    },
                )
            )
            r_en = mock.post("/api/nfregex/regexes/7/enable").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            r_dis = mock.post("/api/nfregex/regexes/7/disable").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            r_del = mock.delete("/api/nfregex/regexes/7").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            got = await client.get_regex(7)
            assert isinstance(got, RegexModel) and got.id == 7
            await client.enable_regex(7)
            await client.disable_regex(7)
            await client.delete_regex(7)
            assert r_get.called and r_en.called and r_dis.called and r_del.called


async def test_nfregex_metrics_returns_text() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            mock.get("/api/nfregex/metrics").mock(
                return_value=httpx.Response(200, text="firegex_blocked_packets{...} 5")
            )
            t = await client.get_nfregex_metrics()
            assert "firegex_blocked_packets" in t


# ---------- nfproxy ----------


async def test_nfproxy_services_crud() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            mock.get("/api/nfproxy/services").mock(
                return_value=httpx.Response(200, json=[_nfproxy_service_json()])
            )
            mock.get("/api/nfproxy/services/abc").mock(
                return_value=httpx.Response(200, json=_nfproxy_service_json())
            )
            add = mock.post("/api/nfproxy/services").mock(
                return_value=httpx.Response(200, json={"status": "ok", "service_id": "abc"})
            )
            mock.post("/api/nfproxy/services/abc/start").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            mock.post("/api/nfproxy/services/abc/stop").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            mock.delete("/api/nfproxy/services/abc").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            rename = mock.put("/api/nfproxy/services/abc/rename").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            update = mock.put("/api/nfproxy/services/abc/settings").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )

            assert isinstance((await client.list_nfproxy_services())[0], NfproxyService)
            assert (await client.get_nfproxy_service("abc")).service_id == "abc"
            await client.add_nfproxy_service(
                name="http", port=80, proto="http", ip_int="0.0.0.0"
            )
            assert add.called
            await client.start_nfproxy_service("abc")
            await client.stop_nfproxy_service("abc")
            await client.delete_nfproxy_service("abc")
            await client.rename_nfproxy_service("abc", "n2")
            assert '"name":"n2"' in rename.calls[0].request.read().decode()
            await client.update_nfproxy_service_settings("abc", port=8080)
            assert '"port":8080' in update.calls[0].request.read().decode()


async def test_list_and_toggle_pyfilters() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            mock.get("/api/nfproxy/services/abc/pyfilters").mock(
                return_value=httpx.Response(
                    200,
                    json=[
                        {
                            "name": "drop_flag",
                            "service_id": "abc",
                            "blocked_packets": 0,
                            "edited_packets": 0,
                            "active": True,
                        }
                    ],
                )
            )
            en = mock.post(
                "/api/nfproxy/services/abc/pyfilters/drop_flag/enable"
            ).mock(return_value=httpx.Response(200, json={"status": "ok"}))
            dis = mock.post(
                "/api/nfproxy/services/abc/pyfilters/drop_flag/disable"
            ).mock(return_value=httpx.Response(200, json={"status": "ok"}))
            filters = await client.list_pyfilters("abc")
            assert filters[0].name == "drop_flag"
            assert isinstance(filters[0], PyFilterModel)
            await client.enable_pyfilter("abc", "drop_flag")
            await client.disable_pyfilter("abc", "drop_flag")
            assert en.called and dis.called


async def test_get_and_set_pyfilter_code() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            mock.get("/api/nfproxy/services/abc/code").mock(
                return_value=httpx.Response(200, text="@pyfilter\ndef f(): pass\n")
            )
            put = mock.put("/api/nfproxy/services/abc/code").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            code = await client.get_pyfilter_code("abc")
            assert "@pyfilter" in code
            await client.set_pyfilter_code("abc", "new code")
            body = put.calls[0].request.read().decode()
            assert '"code":"new code"' in body


# ---------- firewall ----------


async def test_firewall_settings_get_set() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            mock.get("/api/firewall/settings").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "keep_rules": True,
                        "allow_loopback": True,
                        "allow_established": True,
                        "allow_icmp": True,
                        "multicast_dns": False,
                        "allow_upnp": False,
                        "drop_invalid": True,
                        "allow_dhcp": False,
                    },
                )
            )
            put = mock.put("/api/firewall/settings").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            s = await client.get_firewall_settings()
            assert isinstance(s, FirewallSettings)
            assert s.keep_rules is True
            await client.set_firewall_settings(s)
            body = put.calls[0].request.read().decode()
            assert '"keep_rules":true' in body


async def test_firewall_enable_disable() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            en = mock.post("/api/firewall/enable").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            dis = mock.post("/api/firewall/disable").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            await client.enable_firewall()
            await client.disable_firewall()
            assert en.called and dis.called


async def test_list_firewall_rules() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            mock.get("/api/firewall/rules").mock(
                return_value=httpx.Response(
                    200, json={"rules": [], "policy": "accept", "enabled": True}
                )
            )
            info = await client.list_firewall_rules()
            assert isinstance(info, RuleInfo)
            assert info.policy == FwAction.ACCEPT


async def test_replace_firewall_rules() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            route = mock.post("/api/firewall/rules").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            rule = RuleModel(
                active=True,
                name="drop-bad",
                proto=FwProto.TCP,
                table=FwTable.FILTER,
                src="0.0.0.0/0",
                dst="10.0.0.1",
                port_src_from=1,
                port_src_to=65535,
                port_dst_from=22,
                port_dst_to=22,
                action=FwAction.DROP,
                mode=FwMode.IN,
            )
            await client.replace_firewall_rules(policy=FwAction.ACCEPT, rules=[rule])
            body = route.calls[0].request.read().decode()
            assert '"policy":"accept"' in body
            assert '"name":"drop-bad"' in body


# ---------- porthijack ----------


async def test_porthijack_services_crud() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            mock.get("/api/porthijack/services").mock(
                return_value=httpx.Response(200, json=[_phj_service_json()])
            )
            mock.get("/api/porthijack/services/abc").mock(
                return_value=httpx.Response(200, json=_phj_service_json())
            )
            add = mock.post("/api/porthijack/services").mock(
                return_value=httpx.Response(200, json={"status": "ok", "service_id": "abc"})
            )
            mock.post("/api/porthijack/services/abc/start").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            mock.post("/api/porthijack/services/abc/stop").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            mock.delete("/api/porthijack/services/abc").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            rename = mock.put("/api/porthijack/services/abc/rename").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )

            svcs = await client.list_phj_services()
            assert isinstance(svcs[0], PortHijackService)
            assert (await client.get_phj_service("abc")).service_id == "abc"
            await client.add_phj_service(
                name="ssh",
                public_port=22,
                proxy_port=2222,
                proto="tcp",
                ip_src="0.0.0.0",
                ip_dst="127.0.0.1",
            )
            assert add.called
            body = add.calls[0].request.read().decode()
            assert '"public_port":22' in body
            assert '"proxy_port":2222' in body
            await client.start_phj_service("abc")
            await client.stop_phj_service("abc")
            await client.delete_phj_service("abc")
            await client.rename_phj_service("abc", "n2")
            assert '"name":"n2"' in rename.calls[0].request.read().decode()


async def test_porthijack_change_destination() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            route = mock.put("/api/porthijack/services/abc/change-destination").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            await client.change_phj_destination("abc", ip_dst="127.0.0.2", proxy_port=3333)
            body = route.calls[0].request.read().decode()
            assert '"ip_dst":"127.0.0.2"' in body
            assert '"proxy_port":3333' in body
