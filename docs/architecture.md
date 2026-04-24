# Architecture

This document maps the [Agent Auth Protocol v1.0-draft](https://agent-auth-protocol.com/specification/v1.0-draft) onto this Keycloak extension. It's aimed at someone who's read the spec once and wants to know how our code cuts it up, or someone who's read our code and wants to know where each piece lives in the spec.

The README gives the high-level picture; this doc is the deep reference.

## Contents

1. [Protocol actors](#protocol-actors)
2. [Spec data-flow diagram](#spec-data-flow-diagram)
3. [Canonical happy-path sequence](#canonical-happy-path-sequence)
4. [Extension internals](#extension-internals)
5. [Spec ↔ source file map](#spec--source-file-map)
6. [Deliberate deviations and choices](#deliberate-deviations-and-choices)

---

## Protocol actors

| Actor | Kind | Definition (verbatim quote, spec section) |
|-------|------|-------------------------------------------|
| **Agent** | service | "A runtime AI actor scoped to a specific conversation, task, or session, that calls external services." (§2.1) |
| **Client** | service | "The process that holds a host identity and exposes protocol tools to AI systems (MCP server, CLI, SDK). It manages host and agent keys, talks to servers, and signs JWTs." (§1.5) |
| **Host** | principal | "The persistent identity of the client environment where agents run... represented as a registered keypair plus metadata." (§2.7) |
| **Server** | service | "The service's authorization server. It manages discovery, host and agent registrations, approvals, capability grants, and JWT verification." (§1.5) |
| **Resource Server** | service | Implicit in §2.15 and §5.11. The service hosting a capability's business logic at `capability.location`. Validates agent JWTs locally or via introspection. |
| **User** | human | End user who approves delegated registrations and capability grants (§2.2.1, §2.9). |

Key property: **Client and Host are different things.** The client is the process (Claude Code CLI, a background worker, etc.); the host is the identity that client holds (one Ed25519 keypair + record on the server). Migrating a client install to a different machine but carrying the key = same host; reinstalling with a fresh key = different host.

## Spec data-flow diagram

```
  ┌──────────── Client environment (the host principal) ────────────┐
  │                                                                  │
  │    ┌─────────┐        protocol tools          ┌──────────┐       │
  │    │  Agent  │ ◀─────── (MCP / SDK) ─────────▶│  Client  │       │
  │    │  (LLM)  │                                 │ holds H  │       │
  │    └─────────┘                                 │ keypair, │       │
  │                                                 │ signs JWT│       │
  │                                                 └────┬─────┘       │
  └────────────────────────────────────────────────────── │ ────────────┘
                                                          │ HTTPS
                             ┌────────────────────────────┤
                             │                            │
                             │ host+jwt OR agent+jwt      │ agent+jwt
                             │ (server endpoints)         │ (direct-mode
                             ▼                            ▼  RS only)
        ┌────────────────────────────────────┐   ┌──────────────────────────┐
        │ Server (authz)                     │   │ Resource Server           │
        │                                    │   │   (capability.location)    │
        │  GET /.well-known/                 │   │                            │
        │       agent-configuration          │   │  POST <location>           │
        │  GET /capability/{list,describe}   │   │   Authorization:           │
        │  POST /agent/register              │   │     Bearer <agent+jwt>     │
        │       /agent/request-capability    │   │                            │
        │       /agent/{status,revoke,       │   │  runs business logic       │
        │        reactivate,rotate-key}      │   │                            │
        │       /host/{revoke,rotate-key}    │◀──┤ POST /agent/introspect     │
        │       /agent/introspect            │   │   { "token": "..." }       │
        │       /capability/execute          │   │   (server-to-server)       │
        │         (gateway mode —            │   │                            │
        │          proxies to                │   └──────────────────────────┘
        │          capability.location)      │
        └──────────────────┬─────────────────┘
                           │ approval flow
                           │  (device_authorization / CIBA / admin UI)
                           ▼
                       ┌────────┐
                       │  User  │
                       │ (human)│
                       └────────┘
```

The two capability-execution paths meet in the same picture:

- **Gateway** — client sends agent+jwt to `/capability/execute`; server validates, runs constraint checks, proxies to `<capability.location>`. The resource server never sees an agent+jwt directly.
- **Direct** — client sends agent+jwt to `<capability.location>` directly; the resource server calls `/agent/introspect` to validate.

Gateway is the simpler integration (resource server doesn't implement any auth); direct gives the resource server ownership of the auth decision and saves one hop.

## Canonical happy-path sequence

Delegated-mode registration → approval → execution → introspection → revocation. Numbers label the hops.

```
 [Agent]        [Client]               [Server]               [User]       [RS]
    │               │                      │                    │           │
    │─1. connect───▶│                      │                    │           │
    │               │                      │                    │           │
    │               │─2. GET /.well-known─▶│                    │           │
    │               │◀────discovery doc────│                    │           │
    │               │                      │                    │           │
    │               │─3. POST /agent/register [host+jwt]────────▶│           │
    │               │                      │ create host(pending│           │
    │               │                      │        or active), │           │
    │               │                      │ agent, grants      │           │
    │               │◀──4. approval object─│                    │           │
    │               │                      │                    │           │
    │               │                      │─5. approval prompt─▶│           │
    │               │                      │  (device / CIBA /  │           │
    │               │                      │   admin UI)        │           │
    │               │                      │◀──6. approved──────│           │
    │               │                      │                    │           │
    │               │─7. GET /agent/status─▶│                    │           │
    │               │◀─8. status=active────│                    │           │
    │               │                      │                    │           │
    │  — agent now usable —                │                    │           │
    │               │                      │                    │           │
    │◀─9. ok to work│                      │                    │           │
    │               │                      │                    │           │
    │10. execute_capability                │                    │           │
    │──────────────▶│                      │                    │           │
    │               │  — GATEWAY MODE —    │                    │           │
    │               │─11g. POST /capability/execute [agent+jwt]─▶│          │
    │               │                      │  introspect+       │           │
    │               │                      │  constraints+      │           │
    │               │                      │  proxy internally ─┼──────────▶│
    │               │                      │                    │  run      │
    │               │                      │◀───────────────────┼──────────┤
    │               │◀──12g. result────────│                    │           │
    │               │                      │                    │           │
    │               │  — DIRECT MODE —     │                    │           │
    │               │─11d. POST <location> [agent+jwt]──────────┼──────────▶│
    │               │                      │                    │           │
    │               │                      │◀─12d. POST /agent/introspect──┤
    │               │                      │──────────────────── ─ ─ ─ ─ ─▶│
    │               │◀────13d. result──────┼────────────────────┼──────────│
    │               │                      │                    │           │
    │◀──14. answer─│                      │                    │           │
    │               │                      │                    │           │
    │  — later, teardown —                 │                    │           │
    │               │─15. POST /agent/revoke [host+jwt]─────────▶│          │
    │               │◀──16. status=revoked─│                    │           │
    │               │                      │                    │           │
```

A few nuances worth calling out:

- **Host+jwt vs agent+jwt boundary.** Host+jwt signs *host-scoped* operations (register, status, revoke, reactivate, rotate-key). Agent+jwt signs *agent-scoped* operations (execute, introspect target). The spec requires `aud` on the agent+jwt to match the endpoint it's sent to — `/capability/execute` for gateway, `<capability.location>` for direct. That's enforced in `AgentAuthRealmResourceProvider.executeCapability` and mirrored by resource-server implementations.
- **Approval method selection.** Driven by what the server advertises in `/.well-known/agent-configuration` under `approval_methods`. Today we publish `["admin"]`, so step 5 is a human admin calling `/admin/.../agents/{id}/capabilities/{cap}/approve`; `device_authorization` and `ciba` are on the roadmap.
- **Async / streaming execution.** Gateway-mode `/capability/execute` can return `202 + status_url` for async or an SSE stream for streaming. Our `AgentAuthRealmResourceProvider.executeCapability` proxies all three response shapes; see `AgentAuthCapabilityExecuteIT` for the exercised contracts.

## Extension internals

```
  ┌──────────── Keycloak server (container) ──────────────────────────┐
  │                                                                    │
  │  ┌─── Keycloak core (pre-existing) ─────────────────────────────┐  │
  │  │   • Realms / users / sessions                                │  │
  │  │   • OIDC (admin-cli gets $TOKEN via password grant)          │  │
  │  │   • Admin UI / admin REST (/admin/realms/{r}/...)            │  │
  │  │   • Event framework (AdminEvent audit log)                   │  │
  │  │   • JPA persistence unit (H2 in dev, Postgres in prod)       │  │
  │  └──────────────────────────────────────────────────────────────┘  │
  │                                                                    │
  │  ┌─── This extension (keycloak-agent-auth JAR) ─────────────────┐  │
  │  │                                                              │  │
  │  │   WellKnownProvider SPI                                      │  │
  │  │     └─ AgentAuthWellKnownProvider                            │  │
  │  │         publishes /.well-known/agent-configuration           │  │
  │  │         with modes, approval_methods=["admin"],              │  │
  │  │         endpoints map, default_location                      │  │
  │  │                                                              │  │
  │  │   RealmResourceProvider SPI                                  │  │
  │  │     └─ AgentAuthRealmResourceProvider                        │  │
  │  │         /agent/register, /agent/introspect,                  │  │
  │  │         /agent/status, /agent/revoke, /agent/reactivate,     │  │
  │  │         /agent/rotate-key, /host/revoke, /host/rotate-key,   │  │
  │  │         /agent/request-capability,                           │  │
  │  │         /capability/{list,describe,execute},                 │  │
  │  │         /agent/{id}/capabilities/{cap}/status, /health       │  │
  │  │                                                              │  │
  │  │   AdminRealmResourceProvider SPI (reuses KC admin auth)      │  │
  │  │     └─ AgentAuthAdminResourceProvider                        │  │
  │  │         capability CRUD,                                     │  │
  │  │         agent approve/reject/expire,                         │  │
  │  │         host pre-register + GET                              │  │
  │  │                                                              │  │
  │  │   Storage SPI (AgentAuthStorage)                             │  │
  │  │     ├─ JpaStorage  (default, order=100)                      │  │
  │  │     │    └─ JpaEntityProvider + Liquibase changelog →        │  │
  │  │     │       AGENT_AUTH_{HOST,AGENT,CAPABILITY,ROTATED_HOST}  │  │
  │  │     └─ InMemoryStorage (tests)                               │  │
  │  │        override via kc.spi.agent-auth-storage.provider=...   │  │
  │  │                                                              │  │
  │  │   Support classes                                            │  │
  │  │     ├─ JwksCache (5-min TTL, kid-miss rate-limited)          │  │
  │  │     ├─ ConstraintValidator (max/min/in/not_in/exact)         │  │
  │  │     └─ AgentAuthDiscoveryCacheFilter                         │  │
  │  └──────────────────────────────────────────────────────────────┘  │
  └────────────────────────────────────────────────────────────────────┘

  External to the extension (you plug these in):
    • Client software    — your host process, any language
    • Agent runtime      — your LLM / app, any runtime
    • Resource server    — your product backend, any language
                           (register its URL as capability.location)
    • Keycloak admin user — the human who approves delegated grants
                           via the admin API until CIBA / device-flow land
```

The three SPIs (WellKnownProvider, RealmResourceProvider, AdminRealmResourceProvider) are the only extension points Keycloak itself defines; everything else the extension does is either SPI registration boilerplate or ordinary Java code that those three invoke.

### Storage layering

`AgentAuthStorage` is the single interface through which every endpoint reaches state. Two implementations ship:

- `JpaStorage` — default, order=100. Writes land in Keycloak's main persistence unit via `JpaEntityProvider`. One Liquibase changelog (`META-INF/agent-auth-changelog.xml`) creates the four tables. The entity shape is deliberately coarse: four tagged columns (`ID`, `STATUS`, `CREATED_AT`, `UPDATED_AT`) plus a `PAYLOAD TEXT` holding the full record as JSON. Adding optional fields to a record (name/description/metadata) is a zero-migration change — they ride along in `PAYLOAD`.
- `InMemoryStorage` — order=0, used by tests that don't care about persistence. The existing IT suite uses it; `BasePostgresE2E` switches to JPA+Postgres for cross-restart tests.

Providers are selected with `kc.spi.agent-auth-storage.provider=<jpa|in-memory>`.

### JWT verification

Two keyed verification paths:

- **Inline key** — the host+jwt or the registered agent record contains a JWK. Signature verification reads the key directly.
- **JWKS URL** — `host_jwks_url` or `agent_jwks_url` is registered; `JwksCache` fetches and caches. 5-minute TTL; a `kid` miss triggers one refetch per URL per 10 seconds.

Both paths converge in the same verification logic; the choice is per-identity, fixed at registration time, and mutually exclusive for the same identity.

### Constraint enforcement

`ConstraintValidator` enforces `max` / `min` / `in` / `not_in` / exact-scalar constraints declared on a grant. Evaluation happens in two places:

- Gateway mode (`/capability/execute`) — before proxying, Keycloak checks arguments and returns `403 constraint_violated` with a `violations[]` array.
- Introspection-assisted direct mode — resource servers POST `{token, capability, arguments}` to `/agent/introspect`; if constraints fail, the introspection response carries a `violations` field, and the resource server is expected to reject.

## Spec ↔ source file map

| Spec section / concept | Implementation |
|------------------------|----------------|
| §5.1 Discovery | `AgentAuthWellKnownProvider` + `AgentAuthWellKnownProviderFactory` |
| §5.2 / §5.2.1 Capability list / describe | `AgentAuthRealmResourceProvider.listCapabilities` / `.describeCapability` |
| §5.3 Agent registration | `AgentAuthRealmResourceProvider.registerAgent` |
| §5.4 Request capability | `AgentAuthRealmResourceProvider.requestCapability` |
| §5.5 Status | `AgentAuthRealmResourceProvider.getAgentStatus` and `.getGrantStatus` |
| §5.6 Reactivate | `AgentAuthRealmResourceProvider.reactivateAgent` |
| §5.7 / §5.10 Revoke agent / host | `AgentAuthRealmResourceProvider.revokeAgent` / `.revokeHost` |
| §5.8 / §5.9 Key rotation | `AgentAuthRealmResourceProvider.rotateAgentKey` / `.rotateHostKey` |
| §5.11 Execute (gateway) | `AgentAuthRealmResourceProvider.executeCapability` |
| §5.12 Introspect | `AgentAuthRealmResourceProvider.introspect` |
| §4.5 JWT verification | inline in the above, shared helpers |
| §2.13 Constraints | `ConstraintValidator`, `ConstraintViolation` |
| §2.8 Pre-registration | `AgentAuthAdminResourceProvider.preRegisterHost` / `.getHost` |
| Admin capability CRUD | `AgentAuthAdminResourceProvider.registerCapability` / `.updateCapability` / `.deleteCapability` |
| Admin grant approve / reject / expire | `AgentAuthAdminResourceProvider.approveCapability` / `.rejectAgent` / `.expireAgent` |
| Storage | `storage/AgentAuthStorage` + `storage/jpa/*` + `storage/InMemoryStorage` |
| Liquibase schema | `META-INF/agent-auth-changelog.xml` |

Tests mirror the endpoint boundaries: one `*IT.java` per spec section in `src/test/java/.../agentauth/`, plus `AgentAuthFullJourneyE2E` and `AgentAuthRestartSurvivalE2E` for cross-endpoint invariants.

## Deliberate deviations and choices

The spec is intentionally implementation-agnostic in several places. Here's where we picked and why.

| Spec concept | What we did | Why |
|--------------|-------------|-----|
| `approval_methods` | `["admin"]` only | Device flow + CIBA are on the roadmap. Today a Keycloak admin approves via `POST /admin/.../agents/{id}/capabilities/{cap}/approve`. |
| Host state on dynamic registration | `active` (spec prescribes `pending`) | Pre-existing simplification to keep the initial implementation compact; pre-registration now gives admins a hook to gate this properly. Revisit alongside device-flow. |
| Pre-registration endpoint shape | `POST /admin/.../agent-auth/hosts` with inline JWK | Spec explicitly defers this to "server's dashboard, admin API, or any other server-specific mechanism" (§2.8). We matched the shape of the existing admin API. |
| `user_id` linking on hosts | not implemented | Waits on the user-approval flow. Today all hosts are unlinked. |
| `jwks_uri` in discovery | omitted | Extension doesn't sign server responses — nothing to publish. Host/agent JWKS support is separate and fully implemented. |
| Autonomous-agent `claimed` transition on host link | not implemented | Waits on user linking. |
| JWKS HTTPS enforcement | stricter than spec (HTTPS required except for localhost and container-test hostnames) | Avoid accidentally fetching JWKS over cleartext in production. Dev/test exceptions are scoped narrowly. |
| Storage SPI | shipped (`AgentAuthStorage`) with JPA default | So persistence survives container restarts and scales across replicas without forcing any consumer onto a specific backend. |

If you hit one of these and need different behavior, open an issue — most of them are "waits on a sibling feature" rather than deliberate exclusion.
