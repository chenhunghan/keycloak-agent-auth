"""Admin-plane helpers.

Uses Keycloak's OIDC password grant to get an admin token, then calls
the extension's admin API to register a capability and approve pending
grants.

These operations are NOT part of the Agent Auth Protocol flow itself
they're the deployment-time setup a service operator does once (or when
capabilities change). Included here so the demo can be run from scratch.
"""

from __future__ import annotations

import json
from typing import Any, Literal, TypedDict

import requests


def get_admin_token(
    kc_base_url: str, realm: str, username: str, password: str
) -> str:
    resp = requests.post(
        f"{kc_base_url}/realms/{realm}/protocol/openid-connect/token",
        headers={"content-type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": username,
            "password": password,
        },
    )
    if not resp.ok:
        raise RuntimeError(f"admin token failed: {resp.status_code} {resp.text}")
    return resp.json()["access_token"]


class CapabilityDefinition(TypedDict, total=False):
    name: str
    description: str
    visibility: str  # "authenticated" | "public"
    requires_approval: bool
    location: str
    input: Any
    output: Any


def register_capability(
    kc_base_url: str,
    realm: str,
    admin_token: str,
    capability: CapabilityDefinition,
) -> Literal["created", "already_exists"]:
    url = f"{kc_base_url}/admin/realms/{realm}/agent-auth/capabilities"
    resp = requests.post(
        url,
        headers={
            "content-type": "application/json",
            "authorization": f"Bearer {admin_token}",
        },
        data=json.dumps(capability),
    )
    if resp.status_code == 409:
        return "already_exists"
    if not resp.ok:
        raise RuntimeError(
            f"register capability failed: {resp.status_code} {resp.text}"
        )
    return "created"


def approve_capability(
    kc_base_url: str,
    realm: str,
    admin_token: str,
    agent_id: str,
    capability: str,
) -> None:
    """Approves a pending capability grant on an agent.

    This is the admin-mediated approval path the extension uses when
    ``approval_methods=["admin"]`` or when the admin shortcut is
    preferred over device-flow. AAP 2.9 / 5.3.
    """
    url = (
        f"{kc_base_url}/admin/realms/{realm}"
        f"/agent-auth/agents/{agent_id}/capabilities/{capability}/approve"
    )
    resp = requests.post(
        url, headers={"authorization": f"Bearer {admin_token}"}
    )
    if not resp.ok:
        raise RuntimeError(f"approve failed: {resp.status_code} {resp.text}")
