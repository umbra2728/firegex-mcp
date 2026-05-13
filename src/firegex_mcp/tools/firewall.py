"""MCP tools for Firegex firewall (nftables ruleset)."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from firegex_mcp.client import FiregexClient
from firegex_mcp.models import FirewallSettings, FwAction, RuleInfo, RuleModel


def register(mcp: FastMCP, client: FiregexClient) -> None:
    @mcp.tool()
    async def get_firewall_settings() -> FirewallSettings:
        """Read the firewall meta-settings (loopback, established, ICMP, mDNS, ...)."""
        return await client.get_firewall_settings()

    @mcp.tool()
    async def set_firewall_settings(
        keep_rules: bool,
        allow_loopback: bool,
        allow_established: bool,
        allow_icmp: bool,
        multicast_dns: bool,
        allow_upnp: bool,
        drop_invalid: bool,
        allow_dhcp: bool,
    ) -> dict[str, Any]:
        """Replace the firewall settings. All fields are required (no partial update)."""
        s = FirewallSettings(
            keep_rules=keep_rules,
            allow_loopback=allow_loopback,
            allow_established=allow_established,
            allow_icmp=allow_icmp,
            multicast_dns=multicast_dns,
            allow_upnp=allow_upnp,
            drop_invalid=drop_invalid,
            allow_dhcp=allow_dhcp,
        )
        return await client.set_firewall_settings(s)

    @mcp.tool()
    async def enable_firewall() -> dict[str, Any]:
        """Activate the nftables firewall ruleset."""
        return await client.enable_firewall()

    @mcp.tool()
    async def disable_firewall() -> dict[str, Any]:
        """Deactivate the nftables firewall ruleset (all rules unloaded)."""
        return await client.disable_firewall()

    @mcp.tool()
    async def list_firewall_rules() -> RuleInfo:
        """Return current rules, policy ('accept'/'drop'/'reject'), and enabled state."""
        return await client.list_firewall_rules()

    @mcp.tool()
    async def replace_firewall_rules(
        policy: FwAction,
        rules: list[RuleModel],
    ) -> dict[str, Any]:
        """Atomically replace the entire rule list.

        Firegex performs `DELETE FROM rules; INSERT ...` in one transaction —
        there is no per-rule CRUD. Read with `list_firewall_rules`, mutate, then
        write back.
        """
        return await client.replace_firewall_rules(policy=policy, rules=rules)
