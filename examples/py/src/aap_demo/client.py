"""Client-side implementation of the Agent Auth Protocol.

Per AAP 1.5/1.6, the Client is "the process that holds a host identity
and exposes protocol tools to AI systems (MCP server, CLI, SDK). It
manages host and agent keys, talks to servers, and signs JWTs."

In this demo the Client:
  - generates an in-memory Ed25519 keypair (the Host identity)
  - generates a second Ed25519 keypair per Agent registered under it
  - mints host+jwt (4.2) for host-scoped ops (register, revoke, introspect)
  - mints agent+jwt (4.3) for /capability/execute (gateway mode)

A production Client would persist the host key (OS keychain, secrets
manager, disk with correct permissions) so the Host identity survives
restarts.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Optional, TypedDict

import jwt as pyjwt
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


@dataclass
class Ed25519KeyPair:
    public_key: Ed25519PublicKey
    private_key: Ed25519PrivateKey


class AgentRegistration(TypedDict, total=False):
    name: str
    host_name: str
    mode: str  # "delegated" | "autonomous"
    capabilities: list  # list[str | {"name": str, "constraints": ...}]
    reason: str


class AgentRegistrationResponse(TypedDict, total=False):
    agent_id: str
    status: str  # "pending" | "active" | "rejected"
    approval: dict
    agent_capability_grants: list


class IntrospectResponse(TypedDict, total=False):
    active: bool
    agent_id: str
    host_id: str
    mode: str
    expires_at: str
    agent_capability_grants: list


@dataclass
class ExecuteAttempt:
    status: int
    body: Any


def _generate_ed25519() -> Ed25519KeyPair:
    priv = Ed25519PrivateKey.generate()
    return Ed25519KeyPair(public_key=priv.public_key(), private_key=priv)


def _b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _public_jwk(key: Ed25519PublicKey) -> dict:
    raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64url_nopad(raw)}


def _thumbprint(key: Ed25519PublicKey) -> str:
    """RFC 7638 JWK thumbprint for an Ed25519 public key."""
    jwk = _public_jwk(key)
    # Canonical JSON: keys in lexicographic order, no whitespace.
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).digest()
    return _b64url_nopad(digest)


class Client:
    """The Client  a broker process.

    See module docstring for details. Mirrors the TypeScript
    ``examples/js/src/client.ts`` API surface.
    """

    def __init__(self, issuer_url: str, host_key: Ed25519KeyPair) -> None:
        self._issuer_url = issuer_url
        self._host_key = host_key
        self._agent_key: Optional[Ed25519KeyPair] = None
        self._agent_id: Optional[str] = None

    @classmethod
    def create(cls, issuer_url: str) -> "Client":
        return cls(issuer_url, _generate_ed25519())

    # ------------------------------------------------------------------
    # Public API (mirrors the TS surface).
    # ------------------------------------------------------------------

    def register_agent(self, req: AgentRegistration) -> AgentRegistrationResponse:
        """Register a new Agent under this Host. Returns the full response."""
        self._agent_key = _generate_ed25519()
        host_jwt = self._mint_host_jwt_for_registration()

        resp = requests.post(
            f"{self._issuer_url}/agent/register",
            headers={
                "content-type": "application/json",
                "authorization": f"Bearer {host_jwt}",
            },
            data=json.dumps(req),
        )
        if not resp.ok:
            raise RuntimeError(
                f"POST /agent/register failed: {resp.status_code} {resp.text}"
            )
        body: AgentRegistrationResponse = resp.json()
        self._agent_id = body["agent_id"]
        return body

    def get_agent_status(self) -> str:
        """GET /agent/status?agent_id=...  returns the current status."""
        if self._agent_id is None:
            raise RuntimeError("no agent registered")
        host_jwt = self._mint_host_jwt_for_op()
        resp = requests.get(
            f"{self._issuer_url}/agent/status",
            params={"agent_id": self._agent_id},
            headers={"authorization": f"Bearer {host_jwt}"},
        )
        if not resp.ok:
            raise RuntimeError(
                f"GET /agent/status failed: {resp.status_code} {resp.text}"
            )
        return resp.json()["status"]

    def execute_via_gateway(self, capability: str, args: Any) -> Any:
        """Execute a capability in gateway mode.

        Throws on non-2xx (for happy-path callers). Use ``try_execute`` to
        inspect a possibly-failing response (e.g. post-revocation).
        """
        attempt = self.try_execute(capability, args)
        if attempt.status < 200 or attempt.status >= 300:
            raise RuntimeError(
                f"POST /capability/execute failed: {attempt.status} "
                f"{json.dumps(attempt.body)}"
            )
        return attempt.body

    def try_execute(self, capability: str, args: Any) -> ExecuteAttempt:
        """Like ``execute_via_gateway`` but surfaces the status code instead of throwing."""
        if self._agent_key is None or self._agent_id is None:
            raise RuntimeError("no agent registered")
        execute_url = f"{self._issuer_url}/capability/execute"
        agent_jwt = self._mint_agent_jwt(execute_url)
        resp = requests.post(
            execute_url,
            headers={
                "content-type": "application/json",
                "authorization": f"Bearer {agent_jwt}",
            },
            data=json.dumps({"capability": capability, "arguments": args}),
        )
        text = resp.text
        try:
            body: Any = json.loads(text)
        except ValueError:
            body = text
        return ExecuteAttempt(status=resp.status_code, body=body)

    def introspect_agent(self) -> IntrospectResponse:
        """POST /agent/introspect  asks Keycloak to validate the current agent's JWT.

        Returns ``{"active": True, ...}`` or ``{"active": False}``.
        """
        if self._agent_key is None or self._agent_id is None:
            raise RuntimeError("no agent registered")
        agent_jwt = self._mint_agent_jwt(self._issuer_url)
        host_jwt = self._mint_host_jwt_for_op()
        resp = requests.post(
            f"{self._issuer_url}/agent/introspect",
            headers={
                "content-type": "application/json",
                "authorization": f"Bearer {host_jwt}",
            },
            data=json.dumps({"token": agent_jwt}),
        )
        if not resp.ok:
            raise RuntimeError(
                f"POST /agent/introspect failed: {resp.status_code} {resp.text}"
            )
        return resp.json()

    def revoke_agent(self) -> None:
        """POST /agent/revoke  permanently terminates the current agent."""
        if self._agent_id is None:
            raise RuntimeError("no agent registered")
        host_jwt = self._mint_host_jwt_for_op()
        resp = requests.post(
            f"{self._issuer_url}/agent/revoke",
            headers={
                "content-type": "application/json",
                "authorization": f"Bearer {host_jwt}",
            },
            data=json.dumps({"agent_id": self._agent_id}),
        )
        if not resp.ok:
            raise RuntimeError(
                f"POST /agent/revoke failed: {resp.status_code} {resp.text}"
            )

    @property
    def current_agent_id(self) -> Optional[str]:
        """Current agent_id (None until register_agent is called)."""
        return self._agent_id

    # ------------------------------------------------------------------
    # JWT minting.
    # ------------------------------------------------------------------

    def _mint_host_jwt_for_registration(self) -> str:
        """host+jwt for POST /agent/register  includes agent_public_key. (4.2)"""
        if self._agent_key is None:
            raise RuntimeError("agent key not prepared")
        host_pub = _public_jwk(self._host_key.public_key)
        agent_pub = _public_jwk(self._agent_key.public_key)
        iss = _thumbprint(self._host_key.public_key)
        now = int(time.time())
        payload = {
            "host_public_key": host_pub,
            "agent_public_key": agent_pub,
            "iss": iss,
            "aud": self._issuer_url,
            "iat": now,
            "exp": now + 60,
            "jti": f"h-{uuid.uuid4()}",
        }
        return pyjwt.encode(
            payload,
            self._host_key.private_key,
            algorithm="EdDSA",
            headers={"typ": "host+jwt"},
        )

    def _mint_host_jwt_for_op(self) -> str:
        """host+jwt for non-registration host ops (status, revoke, introspect). (4.2)"""
        host_pub = _public_jwk(self._host_key.public_key)
        iss = _thumbprint(self._host_key.public_key)
        now = int(time.time())
        payload = {
            "host_public_key": host_pub,
            "iss": iss,
            "aud": self._issuer_url,
            "iat": now,
            "exp": now + 60,
            "jti": f"h-{uuid.uuid4()}",
        }
        return pyjwt.encode(
            payload,
            self._host_key.private_key,
            algorithm="EdDSA",
            headers={"typ": "host+jwt"},
        )

    def _mint_agent_jwt(self, aud: str) -> str:
        """agent+jwt per 4.3."""
        if self._agent_key is None or self._agent_id is None:
            raise RuntimeError("agent key or id not set")
        iss = _thumbprint(self._host_key.public_key)
        now = int(time.time())
        payload = {
            "iss": iss,
            "sub": self._agent_id,
            "aud": aud,
            "iat": now,
            "exp": now + 60,
            "jti": f"a-{uuid.uuid4()}",
        }
        return pyjwt.encode(
            payload,
            self._agent_key.private_key,
            algorithm="EdDSA",
            headers={"typ": "agent+jwt"},
        )
