"""End-to-end demo: walks both AAP journeys against a live Keycloak.

Mirrors AgentAuthFullJourneyE2E.java from the main test suite, from the
client side. Run with `python -m aap_demo.demo` after `docker compose up -d`
in this directory.
"""

from __future__ import annotations

import os
import secrets
import sys
from typing import Any

from .admin import approve_capability, get_admin_token, register_capability
from .agent import Agent
from .client import Client


KC_BASE = os.environ.get("KC_BASE", "http://localhost:28080")
REALM = os.environ.get("KC_REALM", "master")
ADMIN_USER = os.environ.get("KC_ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("KC_ADMIN_PASS", "admin")
RS_LOCATION = os.environ.get("RS_LOCATION", "http://resource-server:3000/exec/greet")

ISSUER = f"{KC_BASE}/realms/{REALM}/agent-auth"


def unique_suffix() -> str:
    return secrets.token_hex(4)


def autonomous_journey(admin_token: str) -> None:
    cap = f"greet_autonomous_{unique_suffix()}"
    print(f"\n=== autonomous journey (capability: {cap}) ===")

    print("1. admin registers capability (requires_approval=False)")
    register_capability(
        KC_BASE,
        REALM,
        admin_token,
        {
            "name": cap,
            "description": "Demo greet, auto-approved",
            "visibility": "authenticated",
            "requires_approval": False,
            "location": RS_LOCATION,
            "input": {"type": "object", "properties": {"name": {"type": "string"}}},
            "output": {"type": "object"},
        },
    )

    print("2. agent registers (mode=autonomous)")
    client = Client.create(ISSUER)
    reg = client.register_agent(
        {
            "name": "demo-autonomous-agent",
            "host_name": "demo-host",
            "mode": "autonomous",
            "capabilities": [cap],
            "reason": "Demo autonomous journey",
        }
    )
    print(f"   agent_id={reg['agent_id']}  status={reg['status']}")
    assert reg["status"] == "active", f"expected active, got {reg['status']}"

    print("3. execute via gateway")
    agent = Agent(client, reg["agent_id"])
    result: dict[str, Any] = agent.invoke_tool(cap, {"name": "autonomous"})
    greeting = result["data"]["greeting"]
    print(f'   backend returned: "{greeting}"')

    print("4. introspect")
    intro1 = client.introspect_agent()
    print(f"   active={intro1['active']}")
    assert intro1["active"] is True, "expected active=True"

    print("5. revoke")
    client.revoke_agent()

    print("6. post-revoke execute (expected: rejected)")
    post_exec = client.try_execute(cap, {"name": "autonomous"})
    print(f"   status={post_exec.status}")
    assert post_exec.status != 200, "expected execute to fail after revoke"

    print("7. post-revoke introspect (expected: active=False)")
    intro2 = client.introspect_agent()
    print(f"   active={intro2['active']}")
    assert intro2["active"] is False, "expected active=False"

    print("autonomous journey: OK")


def delegated_journey(admin_token: str) -> None:
    cap = f"greet_delegated_{unique_suffix()}"
    print(f"\n=== delegated journey (capability: {cap}) ===")

    print("1. admin registers capability (requires_approval=True)")
    register_capability(
        KC_BASE,
        REALM,
        admin_token,
        {
            "name": cap,
            "description": "Demo greet, approval required",
            "visibility": "authenticated",
            "requires_approval": True,
            "location": RS_LOCATION,
            "input": {"type": "object", "properties": {"name": {"type": "string"}}},
            "output": {"type": "object"},
        },
    )

    print("2. agent registers (mode=delegated) -> expect pending")
    client = Client.create(ISSUER)
    reg = client.register_agent(
        {
            "name": "demo-delegated-agent",
            "host_name": "demo-host",
            "mode": "delegated",
            "capabilities": [cap],
            "reason": "Demo delegated journey",
        }
    )
    print(f"   agent_id={reg['agent_id']}  status={reg['status']}")
    assert reg["status"] == "pending", f"expected pending, got {reg['status']}"

    print("3. admin approves grant")
    approve_capability(KC_BASE, REALM, admin_token, reg["agent_id"], cap)
    post_approve = client.get_agent_status()
    print(f"   agent status={post_approve}")
    assert post_approve == "active", f"expected active after approve, got {post_approve}"

    print("4. execute via gateway")
    agent = Agent(client, reg["agent_id"])
    result: dict[str, Any] = agent.invoke_tool(cap, {"name": "delegated"})
    greeting = result["data"]["greeting"]
    print(f'   backend returned: "{greeting}"')

    print("5. introspect")
    intro1 = client.introspect_agent()
    print(f"   active={intro1['active']}")
    assert intro1["active"] is True, "expected active=True"

    print("6. revoke")
    client.revoke_agent()

    print("7. post-revoke execute (expected: rejected)")
    post_exec = client.try_execute(cap, {"name": "delegated"})
    print(f"   status={post_exec.status}")
    assert post_exec.status != 200, "expected execute to fail after revoke"

    print("8. post-revoke introspect (expected: active=False)")
    intro2 = client.introspect_agent()
    print(f"   active={intro2['active']}")
    assert intro2["active"] is False, "expected active=False"

    print("delegated journey: OK")


def main() -> int:
    print(f"[demo] Keycloak: {ISSUER}")
    print(f"[demo] Resource Server (as seen by KC): {RS_LOCATION}")

    try:
        admin_token = get_admin_token(KC_BASE, REALM, ADMIN_USER, ADMIN_PASS)
        autonomous_journey(admin_token)
        delegated_journey(admin_token)
        print("\nAll journeys: OK")
        return 0
    except Exception as e:
        print(f"\n[demo] FAILED: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
