"""Async HTTP client for Firegex's REST API."""

from __future__ import annotations

import asyncio
import base64
import logging
from types import TracebackType
from typing import Any

import httpx

from firegex_mcp.config import FiregexSettings
from firegex_mcp.models import (
    AppStatus,
    FirewallSettings,
    FwAction,
    IpInterface,
    NfproxyService,
    NfregexService,
    PortHijackService,
    PyFilterModel,
    RegexMode,
    RegexModel,
    RuleFormAdd,
    RuleInfo,
    RuleModel,
    StatusModel,
)

log = logging.getLogger(__name__)


# ---------- exceptions ----------


class FiregexError(Exception):
    """Base for all errors raised by FiregexClient."""


class FiregexConnectionError(FiregexError):
    """Network failure: cannot reach Firegex, or request timed out."""


class FiregexAuthError(FiregexError):
    """HTTP 401/403 or bad password during /api/login."""


class FiregexNotInitializedError(FiregexError):
    """Server responded with status='init' — call set_password first."""


class FiregexNotFoundError(FiregexError):
    """HTTP 404 — resource does not exist."""


class FiregexValidationError(FiregexError):
    """HTTP 4xx (other than 401/403/404) — Firegex rejected the request."""


class FiregexServerError(FiregexError):
    """HTTP 5xx — Firegex internal error."""


# ---------- client ----------


_PUBLIC_PATHS = frozenset({"/api/status", "/api/login", "/api/set-password"})


class FiregexClient:
    """Thin async client over Firegex's REST API.

    Use as an async context manager:
        async with FiregexClient(settings) as client:
            services = await client.list_nfregex_services()

    Auto-JWT lifecycle: the first protected request triggers
    /api/status + /api/login. A 401 on a protected path triggers exactly one
    re-login + retry; a second 401 raises FiregexAuthError.
    """

    def __init__(self, settings: FiregexSettings) -> None:
        self._settings = settings
        self._http: httpx.AsyncClient | None = None
        self._token: str | None = None
        self._auth_lock: asyncio.Lock = asyncio.Lock()

    async def __aenter__(self) -> FiregexClient:
        self._http = httpx.AsyncClient(
            base_url=str(self._settings.base_url).rstrip("/"),
            timeout=self._settings.timeout_seconds,
            verify=self._settings.verify_ssl,
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    # ---------- request helper ----------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        authed: bool = True,
        _retried: bool = False,
    ) -> httpx.Response:
        assert self._http is not None, "FiregexClient must be used as async context manager"
        headers: dict[str, str] = {}
        if authed and path not in _PUBLIC_PATHS:
            if self._token is None:
                await self._ensure_logged_in()
            headers["Authorization"] = f"Bearer {self._token}"
        try:
            response = await self._http.request(
                method, path, json=json, params=params, data=data, headers=headers
            )
        except httpx.TimeoutException as e:
            raise FiregexConnectionError(
                f"Request to {method} {path} timed out after "
                f"{self._settings.timeout_seconds}s."
            ) from e
        except httpx.ConnectError as e:
            raise FiregexConnectionError(
                f"Cannot reach Firegex at {self._settings.base_url}. "
                "Is the server running?"
            ) from e
        except httpx.HTTPError as e:
            raise FiregexConnectionError(f"HTTP error: {e}") from e

        if response.status_code == 401:
            if path == "/api/login":
                raise FiregexAuthError("Wrong password. Check FIREGEX_MCP_PASSWORD.")
            if not _retried and authed:
                log.warning("401 on %s %s — re-logging in", method, path)
                self._token = None
                await self._ensure_logged_in()
                return await self._request(
                    method,
                    path,
                    json=json,
                    params=params,
                    data=data,
                    authed=authed,
                    _retried=True,
                )
            raise FiregexAuthError("Could not validate credentials after re-login.")
        if response.status_code == 403:
            raise FiregexAuthError(f"Forbidden: {response.text}")
        if response.status_code == 404:
            raise FiregexNotFoundError(f"Resource not found: {method} {path}")
        if 400 <= response.status_code < 500:
            raise FiregexValidationError(
                f"Firegex rejected request ({response.status_code}): {response.text}"
            )
        if response.status_code >= 500:
            raise FiregexServerError(
                f"Firegex server error ({response.status_code}). Body: {response.text}"
            )
        return response

    # ---------- auth ----------

    async def _ensure_logged_in(self) -> None:
        async with self._auth_lock:
            if self._token is not None:
                return
            status = await self.get_status()
            if status.status == AppStatus.INIT:
                raise FiregexNotInitializedError(
                    "Firegex is uninitialized. Call set_password first."
                )
            r = await self._request(
                "POST",
                "/api/login",
                data={
                    "username": "firegex",
                    "password": self._settings.password,
                    "grant_type": "password",
                },
                authed=False,
            )
            self._token = r.json()["access_token"]
            log.info("Logged in to Firegex")

    async def get_status(self) -> StatusModel:
        r = await self._request("GET", "/api/status", authed=False)
        return StatusModel.model_validate(r.json())

    async def get_status_authed(self) -> StatusModel:
        """Force the auth lifecycle to run, then return the (now-authed) status."""
        await self._ensure_logged_in()
        return await self.get_status()

    # ---------- system ----------

    async def set_password(self, password: str) -> dict[str, Any]:
        r = await self._request(
            "POST", "/api/set-password", json={"password": password}, authed=False
        )
        return dict(r.json())

    async def change_password(self, password: str, expire: bool = True) -> dict[str, Any]:
        r = await self._request(
            "POST",
            "/api/change-password",
            json={"password": password, "expire": expire},
        )
        if expire:
            # Server rotated the JWT secret — our cached token is now invalid.
            self._token = None
        return dict(r.json())

    async def list_interfaces(self) -> list[IpInterface]:
        r = await self._request("GET", "/api/interfaces")
        return [IpInterface.model_validate(x) for x in r.json()]

    async def reset(self, delete: bool) -> dict[str, Any]:
        r = await self._request("POST", "/api/reset", json={"delete": delete})
        return dict(r.json())

    # ---------- nfregex: services ----------

    async def list_nfregex_services(self) -> list[NfregexService]:
        r = await self._request("GET", "/api/nfregex/services")
        return [NfregexService.model_validate(x) for x in r.json()]

    async def get_nfregex_service(self, service_id: str) -> NfregexService:
        r = await self._request("GET", f"/api/nfregex/services/{service_id}")
        return NfregexService.model_validate(r.json())

    async def add_nfregex_service(
        self,
        *,
        name: str,
        port: int,
        proto: str,
        ip_int: str,
        fail_open: bool = False,
    ) -> dict[str, Any]:
        r = await self._request(
            "POST",
            "/api/nfregex/services",
            json={
                "name": name,
                "port": port,
                "proto": proto,
                "ip_int": ip_int,
                "fail_open": fail_open,
            },
        )
        return dict(r.json())

    async def start_nfregex_service(self, service_id: str) -> dict[str, Any]:
        r = await self._request("POST", f"/api/nfregex/services/{service_id}/start")
        return dict(r.json())

    async def stop_nfregex_service(self, service_id: str) -> dict[str, Any]:
        r = await self._request("POST", f"/api/nfregex/services/{service_id}/stop")
        return dict(r.json())

    async def delete_nfregex_service(self, service_id: str) -> dict[str, Any]:
        r = await self._request("DELETE", f"/api/nfregex/services/{service_id}")
        return dict(r.json())

    async def rename_nfregex_service(self, service_id: str, name: str) -> dict[str, Any]:
        r = await self._request(
            "PUT", f"/api/nfregex/services/{service_id}/rename", json={"name": name}
        )
        return dict(r.json())

    async def update_nfregex_service_settings(
        self,
        service_id: str,
        *,
        port: int | None = None,
        proto: str | None = None,
        ip_int: str | None = None,
        fail_open: bool | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if port is not None:
            body["port"] = port
        if proto is not None:
            body["proto"] = proto
        if ip_int is not None:
            body["ip_int"] = ip_int
        if fail_open is not None:
            body["fail_open"] = fail_open
        r = await self._request(
            "PUT", f"/api/nfregex/services/{service_id}/settings", json=body
        )
        return dict(r.json())

    # ---------- nfregex: regexes ----------

    async def list_regexes(self, service_id: str) -> list[RegexModel]:
        r = await self._request("GET", f"/api/nfregex/services/{service_id}/regexes")
        return [RegexModel.model_validate(x) for x in r.json()]

    async def get_regex(self, regex_id: int) -> RegexModel:
        r = await self._request("GET", f"/api/nfregex/regexes/{regex_id}")
        return RegexModel.model_validate(r.json())

    async def add_regex(
        self,
        *,
        service_id: str,
        regex: str,
        mode: RegexMode | str,
        is_case_sensitive: bool,
        active: bool = True,
    ) -> dict[str, Any]:
        encoded = base64.b64encode(regex.encode("utf-8")).decode("ascii")
        r = await self._request(
            "POST",
            "/api/nfregex/regexes",
            json={
                "service_id": service_id,
                "regex": encoded,
                "mode": mode.value if isinstance(mode, RegexMode) else mode,
                "is_case_sensitive": is_case_sensitive,
                "active": active,
            },
        )
        return dict(r.json())

    async def enable_regex(self, regex_id: int) -> dict[str, Any]:
        r = await self._request("POST", f"/api/nfregex/regexes/{regex_id}/enable")
        return dict(r.json())

    async def disable_regex(self, regex_id: int) -> dict[str, Any]:
        r = await self._request("POST", f"/api/nfregex/regexes/{regex_id}/disable")
        return dict(r.json())

    async def delete_regex(self, regex_id: int) -> dict[str, Any]:
        r = await self._request("DELETE", f"/api/nfregex/regexes/{regex_id}")
        return dict(r.json())

    async def get_nfregex_metrics(self) -> str:
        r = await self._request("GET", "/api/nfregex/metrics")
        return r.text

    # ---------- nfproxy: services ----------

    async def list_nfproxy_services(self) -> list[NfproxyService]:
        r = await self._request("GET", "/api/nfproxy/services")
        return [NfproxyService.model_validate(x) for x in r.json()]

    async def get_nfproxy_service(self, service_id: str) -> NfproxyService:
        r = await self._request("GET", f"/api/nfproxy/services/{service_id}")
        return NfproxyService.model_validate(r.json())

    async def add_nfproxy_service(
        self,
        *,
        name: str,
        port: int,
        proto: str,
        ip_int: str,
        fail_open: bool = True,
    ) -> dict[str, Any]:
        r = await self._request(
            "POST",
            "/api/nfproxy/services",
            json={
                "name": name,
                "port": port,
                "proto": proto,
                "ip_int": ip_int,
                "fail_open": fail_open,
            },
        )
        return dict(r.json())

    async def start_nfproxy_service(self, service_id: str) -> dict[str, Any]:
        r = await self._request("POST", f"/api/nfproxy/services/{service_id}/start")
        return dict(r.json())

    async def stop_nfproxy_service(self, service_id: str) -> dict[str, Any]:
        r = await self._request("POST", f"/api/nfproxy/services/{service_id}/stop")
        return dict(r.json())

    async def delete_nfproxy_service(self, service_id: str) -> dict[str, Any]:
        r = await self._request("DELETE", f"/api/nfproxy/services/{service_id}")
        return dict(r.json())

    async def rename_nfproxy_service(self, service_id: str, name: str) -> dict[str, Any]:
        r = await self._request(
            "PUT", f"/api/nfproxy/services/{service_id}/rename", json={"name": name}
        )
        return dict(r.json())

    async def update_nfproxy_service_settings(
        self,
        service_id: str,
        *,
        port: int | None = None,
        ip_int: str | None = None,
        fail_open: bool | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if port is not None:
            body["port"] = port
        if ip_int is not None:
            body["ip_int"] = ip_int
        if fail_open is not None:
            body["fail_open"] = fail_open
        r = await self._request(
            "PUT", f"/api/nfproxy/services/{service_id}/settings", json=body
        )
        return dict(r.json())

    # ---------- nfproxy: pyfilters ----------

    async def list_pyfilters(self, service_id: str) -> list[PyFilterModel]:
        r = await self._request("GET", f"/api/nfproxy/services/{service_id}/pyfilters")
        return [PyFilterModel.model_validate(x) for x in r.json()]

    async def enable_pyfilter(self, service_id: str, filter_name: str) -> dict[str, Any]:
        r = await self._request(
            "POST", f"/api/nfproxy/services/{service_id}/pyfilters/{filter_name}/enable"
        )
        return dict(r.json())

    async def disable_pyfilter(self, service_id: str, filter_name: str) -> dict[str, Any]:
        r = await self._request(
            "POST", f"/api/nfproxy/services/{service_id}/pyfilters/{filter_name}/disable"
        )
        return dict(r.json())

    async def get_pyfilter_code(self, service_id: str) -> str:
        r = await self._request("GET", f"/api/nfproxy/services/{service_id}/code")
        return r.text

    async def set_pyfilter_code(self, service_id: str, code: str) -> dict[str, Any]:
        r = await self._request(
            "PUT", f"/api/nfproxy/services/{service_id}/code", json={"code": code}
        )
        return dict(r.json())

    # ---------- firewall ----------

    async def get_firewall_settings(self) -> FirewallSettings:
        r = await self._request("GET", "/api/firewall/settings")
        return FirewallSettings.model_validate(r.json())

    async def set_firewall_settings(self, settings: FirewallSettings) -> dict[str, Any]:
        r = await self._request(
            "PUT", "/api/firewall/settings", json=settings.model_dump(mode="json")
        )
        return dict(r.json())

    async def enable_firewall(self) -> dict[str, Any]:
        r = await self._request("POST", "/api/firewall/enable")
        return dict(r.json())

    async def disable_firewall(self) -> dict[str, Any]:
        r = await self._request("POST", "/api/firewall/disable")
        return dict(r.json())

    async def list_firewall_rules(self) -> RuleInfo:
        r = await self._request("GET", "/api/firewall/rules")
        return RuleInfo.model_validate(r.json())

    async def replace_firewall_rules(
        self, *, policy: FwAction, rules: list[RuleModel]
    ) -> dict[str, Any]:
        form = RuleFormAdd(rules=rules, policy=policy)
        r = await self._request(
            "POST", "/api/firewall/rules", json=form.model_dump(mode="json")
        )
        return dict(r.json())

    # ---------- porthijack ----------

    async def list_phj_services(self) -> list[PortHijackService]:
        r = await self._request("GET", "/api/porthijack/services")
        return [PortHijackService.model_validate(x) for x in r.json()]

    async def get_phj_service(self, service_id: str) -> PortHijackService:
        r = await self._request("GET", f"/api/porthijack/services/{service_id}")
        return PortHijackService.model_validate(r.json())

    async def add_phj_service(
        self,
        *,
        name: str,
        public_port: int,
        proxy_port: int,
        proto: str,
        ip_src: str,
        ip_dst: str,
    ) -> dict[str, Any]:
        r = await self._request(
            "POST",
            "/api/porthijack/services",
            json={
                "name": name,
                "public_port": public_port,
                "proxy_port": proxy_port,
                "proto": proto,
                "ip_src": ip_src,
                "ip_dst": ip_dst,
            },
        )
        return dict(r.json())

    async def start_phj_service(self, service_id: str) -> dict[str, Any]:
        r = await self._request("POST", f"/api/porthijack/services/{service_id}/start")
        return dict(r.json())

    async def stop_phj_service(self, service_id: str) -> dict[str, Any]:
        r = await self._request("POST", f"/api/porthijack/services/{service_id}/stop")
        return dict(r.json())

    async def delete_phj_service(self, service_id: str) -> dict[str, Any]:
        r = await self._request("DELETE", f"/api/porthijack/services/{service_id}")
        return dict(r.json())

    async def rename_phj_service(self, service_id: str, name: str) -> dict[str, Any]:
        r = await self._request(
            "PUT", f"/api/porthijack/services/{service_id}/rename", json={"name": name}
        )
        return dict(r.json())

    async def change_phj_destination(
        self, service_id: str, *, ip_dst: str, proxy_port: int
    ) -> dict[str, Any]:
        r = await self._request(
            "PUT",
            f"/api/porthijack/services/{service_id}/change-destination",
            json={"ip_dst": ip_dst, "proxy_port": proxy_port},
        )
        return dict(r.json())
