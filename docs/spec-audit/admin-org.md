# AAP v1.0-draft Audit — Realm + Org Admin Control Plane

> **Source of truth:** https://agent-auth-protocol.com/specification/v1.0-draft
> **Audited:** 2026-04-28
> **Scope:** `/admin/realms/{realm}/agent-auth/...`
> **Framing:** Admin endpoints are extensions per §5.1; the audit checks that they produce spec-conformant Host/Agent/Grant/Capability records and §2 state transitions. README-documented deviations (capability registry, multi-tenant scoping via Keycloak Organizations, agent-environments self-serve) are noted but stay out of the action plan.

## Endpoints in scope

| Method | Path | Spec touched | Impl |
|--------|------|--------------|------|
| POST | `capabilities` | §2.12, §2.14, §5.1 | `AgentAuthAdminResourceProvider.java:56-120` |
| PUT | `capabilities/{name}` | §2.12 | `AgentAuthAdminResourceProvider.java:122-170` |
| DELETE | `capabilities/{name}` | §5.1 | `AgentAuthAdminResourceProvider.java:172-187` |
| POST | `hosts` | §2.7, §2.8, §3.1, §4.1 | `AgentAuthAdminResourceProvider.java:604-727` |
| GET | `hosts/{id}` | §3.1 | `AgentAuthAdminResourceProvider.java:729-740` |
| POST | `hosts/{id}/link` | §2.9, §2.10, §3.1, §3.2 | `AgentAuthAdminResourceProvider.java:850-926` |
| DELETE | `hosts/{id}/link` | §2.9 | `AgentAuthAdminResourceProvider.java:933-965` |
| GET | `agents/{id}` | §3.2, §3.3 | `AgentAuthAdminResourceProvider.java:742-768` |
| GET | `agents/{id}/grants` | §3.3 | `AgentAuthAdminResourceProvider.java:776-788` |
| POST | `agents/{id}/capabilities/{cap}/approve` | §2.3, §3.3, §3.3.1, §5.1 | `AgentAuthAdminResourceProvider.java:402-587` |
| POST | `agents/{id}/expire` | §2.3, §2.4 | `AgentAuthAdminResourceProvider.java:189-241` |
| POST | `agents/{id}/reject` | §2.3, §3.3 | `AgentAuthAdminResourceProvider.java:340-400` |
| POST | `pending-agents/cleanup` | §7.1 | `AgentAuthAdminResourceProvider.java:819-844` + `PendingAgentCleanup.java` |
| POST | `agents/{id}/backdate-clocks` | test-only | `AgentAuthAdminResourceProvider.java:265-323` |
| POST | `organizations/{orgId}/capabilities` | §2.12, README ext | `AgentAuthAdminResourceProvider.java:1417-1469` |
| GET | `organizations/{orgId}/capabilities` | extension | `AgentAuthAdminResourceProvider.java:1476-1492` |
| PUT | `organizations/{orgId}/capabilities/{name}` | §2.12 | `AgentAuthAdminResourceProvider.java:1500-1538` |
| DELETE | `organizations/{orgId}/capabilities/{name}` | extension | `AgentAuthAdminResourceProvider.java:1544-1565` |
| POST | `organizations/{orgId}/hosts` | §2.7, §2.8, §3.1, §4.1 | `AgentAuthAdminResourceProvider.java:990-1095` |
| POST | `organizations/{orgId}/agent-environments` | §2.7, §2.8, §3.1, §4.1 | `AgentAuthAdminResourceProvider.java:1127-1278` |
| GET | `organizations/{orgId}/agent-environments` | extension | `AgentAuthAdminResourceProvider.java:1286-1327` |
| DELETE | `organizations/{orgId}/agent-environments/{clientId}` | §2.6 | `AgentAuthAdminResourceProvider.java:1339-1402` |

## Cross-cutting: data-model conformance

| Entity | §3 ref | Required fields per spec | Impl entity / writer | Verdict |
|--------|--------|--------------------------|----------------------|---------|
| Capability (extension; not in §3) | §2.12 | `name`, `description` REQUIRED; `location` optional spec-side, REQUIRED admin-side (documented) | `CapabilityEntity.java:16-60` (typed columns); validators at `AgentAuthAdminResourceProvider.java:1683-1721` | CONFORMANT |
| Host | §3.1 | `id`, `status`, `created_at`, `updated_at` REQUIRED; `public_key` or `jwks_url`; `name`, `user_id`, `default_capabilities`, `activated_at`, `last_used_at` optional | `HostEntity.java:25-75`; admin writers at `:635-722`, `:1066-1080`, `:1234-1246` (`host_id` = JWK thumbprint per §4.1) | CONFORMANT |
| Agent | §3.2 | `id`, `host_id`, `status`, `mode`, `created_at`, `updated_at` REQUIRED; `user_id`, `public_key`/`jwks_url` optional | `AgentEntity.java:33-119`; admin paths only mutate (status/grants/user_id/timestamps) | CONFORMANT |
| Agent Capability Grant | §3.3 | `capability`, `status` REQUIRED (∈ {active, pending, denied}); `constraints`, `granted_by`, `denied_by`, `reason`, `expires_at` optional | `AgentGrantEntity.java:34-60` + nested in `AgentEntity.AGENT_GRANTS`; approve at `:512-530`, deny-cascade at `:500-510`, `:386-394` | V2: missing `denied_by` on auto-deny / reject-cascade |

## Cross-cutting: state-transition conformance

| Admin action | Spec transition | Impl evidence | Verdict |
|--------------|-----------------|---------------|---------|
| Approve grant: pending → active | §3.3 | `:512-530` flip status, snapshot description/input/output, stamp `granted_by`, promote `requested_constraints → constraints` (§2.13 no-widen) | CONFORMANT |
| Approve grant: pending → denied (insufficient_authority) | §3.3 / §5.1 | `:500-510` | V2 (no `denied_by`) |
| Approve cascades: pending agent → active when no remaining pending grants | §2.3 | `:532-543` | CONFORMANT |
| Approve cascades: pending host → active + add cap to `default_capabilities` | §2.11, §3.1 (TOFU) | `:559-582` | CONFORMANT |
| Approve cascades: delegated agent inherits host `user_id` | §3.2 | `:548-552` | CONFORMANT |
| Expire: active → expired (idempotent on expired; 409 otherwise) | §2.3, §2.4 | `:212-222` | CONFORMANT |
| Reject: pending → rejected; pending grants cascade → denied | §2.3, §3.3 | `:354-396` | V2 (no `denied_by` on cascade) |
| Link host: bind user, ban multi-user, autonomous → claimed (§2.10), delegated → inherit user_id (§3.2) | §2.9, §2.10, §3.2 | `:881-922` | CONFORMANT (host status not flipped — U1) |
| Unlink host: revoke all delegated agents; host id retained | §2.9 | `:946-961` | CONFORMANT |
| Delete agent-environment: cascade host + non-terminal agents → revoked | §2.6, §2.10 (terminal preserved) | `:1364-1396` | CONFORMANT |
| Pending cleanup: deletes (not revokes) pending agents past server-defined threshold | §7.1 | `PendingAgentCleanup.java:27, 41-54`; admin trigger `:822-844` | CONFORMANT |

## Per-endpoint findings

### Realm admin: POST `/capabilities` — `:56-120`

Validators at `:1683-1721` enforce §2.12 fields (`description` required `:1684-1690`; `location` required + URL-shape `:1691-1707, 1731-1768`; `input`/`output` MUST be JSON objects `:1708-1719`). Realm-scoped writes reject `organization_id` body (`:93-100`) so org-tenancy can't be back-doored. `manage-realm` gate at `:967-971`. 409 on duplicate (`:113`).

- **D1 (documented).** `location` REQUIRED at admin time even though §2.12 makes it optional with §2.15 `default_location` fallback (README:182).
- **D2 (documented).** Name regex `[a-zA-Z0-9_]+` is broader than §2.14's `[a-z0-9_]+` SHOULD (README:180).
- No violations.

### Realm admin: PUT `/capabilities/{name}` — `:122-170`

Same shape validators as POST (`:154-157`); 404 envelope (`:135-140`); rejects `organization_id` body (`:145-152`); path `name` wins over body (`:165`). Inherits D1/D2. No violations.

### Realm admin: DELETE `/capabilities/{name}` — `:172-187`

404 envelope (`:177-182`); existing grants intentionally NOT scrubbed — runtime fails closed at execute/introspect time, GET decorates with `inoperative:true` (`:799-811`) — preserving §3.3 audit trail while §2.12 enforcement happens elsewhere. 204 on success. No violations.

### Realm admin: POST `/hosts` — `:604-727`

Pre-registration produces a §3.1-shaped record (`:635-640`) with `host_id` = JWK thumbprint (`parseEd25519HostKeyThumbprint:1812-1840`); rejects non-Ed25519 with `unsupported_algorithm` (`:1824-1830`). The `AAP-ADMIN-001` branch logic (`:651-722`) closes a former hole — admin-created hosts no longer land `status=active` without an owning user. Branches: `client_id` → SA-as-host owner + active; `user_id` → realm user + active; neither → `pending` (dynamic-registration path `/verify/approve` will link+activate). 409 on duplicate (`:629-633`).

- **D1 (documented).** `client_id` (SA-as-host) and `user_id` direct-bind are extension features (README:101). Resulting record satisfies §3.1.
- No violations.

### Realm admin: GET `/hosts/{id}` — `:729-740`

Returns §3.1 shape; 404 envelope; `manage-realm` gate. No violations.

### Realm admin: POST `/hosts/{id}/link` — `:850-926`

Single-user invariant (`:881-887` 409 host_already_linked). Cascade: autonomous + non-terminal → `claimed`, grants revoked, attribute to user (`:901-915`, §2.10); delegated → inherit `user_id` (`:916-921`, §3.2); claimed/revoked/rejected preserved (`:899-901`). User must exist in realm (`:875-879`).

- **U1 (undocumented gap).** Linking writes `user_id` and `updated_at` but does not flip `pending → active` for an unowned pending host (branch (c) of `preRegisterHost`). The grant-approval path at `:559-582` does flip pending → active. Internally consistent (§2.11 lets a `pending` host register agents that themselves stay pending), but the host state machine should be either (a) flipped here for symmetry, or (b) explicitly documented as grant-driven activation. No spec violation today.
- No violations.

### Realm admin: DELETE `/hosts/{id}/link` — `:933-965`

§2.9: revokes all non-terminal delegated agents (`:951-957`); autonomous already terminal (`claimed`); host retains `host_id` across unlink/relink (`:958` only removes `user_id`). 204 No Content. No violations.

### Realm admin: GET `/agents/{id}` — `:742-768`

Returns §3.2 + §3.3 shape; `decorateGrantsWithInoperative` (`:799-811`) flags grants whose capability is gone — read-time only, never mutates storage (preserves §3.3 audit trail). No violations.

### Realm admin: GET `/agents/{id}/grants` — `:776-788`

Reads from `AGENT_AUTH_AGENT_GRANT` secondary index; same `inoperative` decoration. No violations.

### Realm admin: POST `/agents/{id}/capabilities/{cap}/approve` — `:402-587`

The richest endpoint. Idempotent on `active` (`:454-456`); rejects non-pending grants 409 (`:457-462`); blocks approval on terminal agents (`claimed/revoked/rejected`) per §2.6/§2.10 (`:424-431`); requires linked host for delegated approval (`:469-487`, AAP-ADMIN-001) — closes "unowned authority" hole. Entitlement gate (`:497-510`) mirrors `/verify/approve`: when org/role gate fails, flips to `denied(reason=insufficient_authority)` instead of activating.

On success: snapshot description/input/output from registry (`:514-520`); stamp `granted_by` = approving admin id (`:521`, §3.3.1); promote `requested_constraints → constraints` per §2.13 no-widen (`:526-530`); cascade pending agent → active when no remaining pending grants (`:532-543`); cascade pending host → active + add cap to `default_capabilities` (`:559-582`, §2.11/§3.1 TOFU); stamp delegated agent's `user_id` from host (`:548-552`).

- **V2 (P2 SPEC VIOLATION).** Auto-deny path at `:500-510` writes `status=denied` and `reason=insufficient_authority` but does not stamp `denied_by`. §3.3 lists `denied_by` as the analogue of `granted_by` ("user or system actor who denied"). Same gap on `rejectAgent` cascade at `:386-394`.

### Realm admin: POST `/agents/{id}/expire` — `:189-241`

`active → expired` only; idempotent on expired; 409 otherwise (`:212-222`, §2.3). `absolute_lifetime_elapsed` flag toggle (`:223-226`) feeds §2.5 reactivation guard. Test-only `escalate_capability` writes a synthetic `escalated_cap` grant (`:227-237`), not a privilege escalator. No violations.

### Realm admin: POST `/agents/{id}/reject` — `:340-400`

`pending → rejected` only; idempotent on rejected; 409 otherwise (`:354-362`, §2.3). Cascades pending grants to `denied` with reason (`:386-395`); discards `requested_constraints` and `status_url` (no widening per §2.13). 

- **V2 (P2 — same as approve).** Cascade-denied grants lack `denied_by`. Mirrors the auto-deny gap above.

### Realm admin: POST `/pending-agents/cleanup` — `:819-844`

§7.1: pending agents are *deleted* (not revoked) — `storage.deletePendingAgentsOlderThan`. Server-defined threshold default 24h (`PendingAgentCleanup.java:27`); hourly scheduler + admin trigger (`PendingAgentCleanup.java:41-54`). Returns `{removed, removed_agents, removed_hosts, threshold_seconds}` (README:110). Orphan pending hosts also reaped — extension to §7.1, documented. No violations.

### Realm admin: POST `/agents/{id}/backdate-clocks` — `:265-323` (test-only)

**P0 sanity check passes.** Endpoint returns 404 unless `System.getProperty("agent-auth.test-mode") == "true"` (`:271-273`). Production Dockerfile and docker-compose stack do not set the property; integration tests pass it via Testcontainers JVM args. `manage-realm` still required (`:270`). Body knobs only mutate timestamp/lifetime fields, never `status` (`:291-318`). Admin event emitted (`:321`). No production exposure.

### Org admin: POST `/organizations/{orgId}/capabilities` — `:1417-1469`

`organization_id` derived from path; body cannot override (`:1458-1459`). Auth gate `requireOrgAdmin` (`:1576-1629`): realm-admin override OR `manage-organization` role + member of target org. 501 envelope when Organizations feature disabled (`orgsEnabledOrError:1642-1660`, README:201). Same shape validators as realm-scoped POST. Inherits D1/D2 from realm-scoped POST. No violations.

### Org admin: GET `/organizations/{orgId}/capabilities` — `:1476-1492`

Strict `organization_id` equality filter (`:1487`); never leaks NULL-org or other-org caps. No violations.

### Org admin: PUT `/organizations/{orgId}/capabilities/{name}` — `:1500-1538`

Cross-org PUT returns 404 (`:1517-1521`, README:114) — caller can't sneak edits across tenants. Path-derived `organization_id` and path `name` always win (`:1531-1533`). No violations.

### Org admin: DELETE `/organizations/{orgId}/capabilities/{name}` — `:1544-1565`

Cross-org DELETE returns 404 (`:1554-1559`); 204 on success. No violations.

### Org admin: POST `/organizations/{orgId}/hosts` — `:990-1095`

Org-scoped SA-as-host: `client_id` REQUIRED (`:1014-1020`). Resolves SA user; checks `serviceAccountsEnabled` (`:1029-1044`); requires SA already a member of the path's org (`:1056-1064`, `sa_not_in_org` 400) — without this an org admin could bind a host to any client's SA. Stores §3.1 record with `status=active` since SA is the owning user from the start (`:1066-1080`). Public key MUST be Ed25519 (same `parseEd25519HostKeyThumbprint`). 409 on duplicate. No violations.

### Org admin: POST `/organizations/{orgId}/agent-environments` — `:1127-1278`

Combined client provisioning + host pre-registration. Lockdown (`:1190-1206`): `publicClient=false`, no standard/implicit/direct-grant flows, no redirect URIs, `serviceAccountsEnabled=true` only — workload can only mint client_credentials tokens for its SA. Tagged `agent_auth_managed=true` + `agent_auth_organization_id=<orgId>`. 50-clients/org cap (`MAX_MANAGED_CLIENTS_PER_ORG:1104`, 429 quota_exceeded `:1165-1175`). `client_secret` returned exactly once (`:1257-1258`); audit event omits secret (`:1248-1254`). Host record (`:1234-1246`) satisfies §3.1; `host_id` = JWK thumbprint. Best-effort rollback on partial failure (`:1267-1273`). No violations.

### Org admin: GET `/organizations/{orgId}/agent-environments` — `:1286-1327`

Filters by both managed tag and org tag (`:1299-1301`). Resolves bound host by `service_account_client_id` (`:1315-1321`); never returns `client_secret`. No violations.

### Org admin: DELETE `/organizations/{orgId}/agent-environments/{clientId}` — `:1339-1402`

Returns 404 for unmanaged or other-org clients (`:1351-1358`) — no leakage of unrelated client existence. Explicit cascade revokes host + non-terminal agents (`:1364-1396`) before client removal — doesn't rely solely on `UserRemovedEvent`. Terminal-state agents preserved per §2.10 (`:1380-1387`). The `AgentAuthUserEventListenerProviderFactory` listener (`:79-99`) is a safety net. No violations.

## Action plan (prioritized)

| # | Priority | Title | Endpoint | Spec § | Impl ref | Fix sketch |
|---|----------|-------|----------|--------|----------|------------|
| 1 | P2 | Stamp `denied_by` on admin-denied / reject-cascade grants | `agents/{id}/capabilities/{cap}/approve` (auto-deny branch) and `agents/{id}/reject` (pending-grant cascade) | §3.3 | `:500-510, 386-394` | Add `targetGrant.put("denied_by", approverUserId())` in both branches; `denied_by` is the §3.3 analogue of `granted_by` and is currently unset. |
| 2 | P3 | Document or implement host activation on link | `hosts/{id}/link` POST | §2.11, §3.1 | `:889-892` | Either flip `pending → active` at link time for symmetry with the grant-approval path at `:559-582`, or document that host activation is grant-driven. Internally consistent today; no spec violation. |

> README-documented deviations (capability name regex; `location` REQUIRED at admin time; gateway audience profile; agent-environments self-serve; JWKS HTTPS strictness; pending-host orphan sweep extension to §7.1) are intentionally out of the action plan.

## Methodology notes

- **Spec subsections fetched** (verbatim via WebFetch): §1.4, §2.3-§2.15, §3 intro, §3.1-§3.3.1, §4.1, §5.1, §5.13.
- **Files read:** `AgentAuthAdminResourceProvider.java` (1-1868), `AgentAuthAdminResourceProviderFactory.java`, `PendingAgentCleanup.java`, `AgentAuthUserEventListenerProviderFactory.java`, JPA entities (`CapabilityEntity`, `HostEntity`, `AgentEntity`, `AgentGrantEntity`, `RotatedHostEntity`), `README.md`.
- **Verification gaps:**
  - The `agent-auth.test-mode` flag was checked via the `System.getProperty` gate only. The Dockerfile (multi-stage; README:281-287) and `docker compose up` stack do not set the property, so production exposure is gated by inspection — operators who set it deliberately would expose `backdate-clocks`.
  - The `verify/deny` realm-side counterpart was out of scope. V2 (`denied_by`) likely applies there too — flag for the `/verify/*` audit.
  - Spec is silent on the wire shape of admin-side responses; the audit only checks that returned records satisfy §3 fields and that error envelopes match §5.13.
