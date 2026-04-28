# AAP v1.0-draft Audit — Agent & Host Lifecycle

> **Source of truth:** https://agent-auth-protocol.com/specification/v1.0-draft
> **Audited:** 2026-04-28
> **Scope:** register, status, reactivate, revoke, rotate-key (agent + host), request-capability, per-grant status

## Endpoints in scope

| Method | Path | Spec § | Impl |
|--------|------|--------|------|
| POST | `/realms/{realm}/agent-auth/agent/register` | §5.3 | `AgentAuthRealmResourceProvider.java:149-639` |
| GET  | `/realms/{realm}/agent-auth/agent/status` | §5.5 | `AgentAuthRealmResourceProvider.java:1037-1133` |
| POST | `/realms/{realm}/agent-auth/agent/reactivate` | §5.6 | `AgentAuthRealmResourceProvider.java:1338-1473` |
| POST | `/realms/{realm}/agent-auth/agent/revoke` | §5.7 | `AgentAuthRealmResourceProvider.java:1258-1336` |
| POST | `/realms/{realm}/agent-auth/agent/rotate-key` | §5.8 | `AgentAuthRealmResourceProvider.java:1135-1256` |
| POST | `/realms/{realm}/agent-auth/agent/request-capability` | §5.4 | `AgentAuthRealmResourceProvider.java:1965-2227` |
| POST | `/realms/{realm}/agent-auth/host/revoke` | §5.10 | `AgentAuthRealmResourceProvider.java:1475-1539` |
| POST | `/realms/{realm}/agent-auth/host/rotate-key` | §5.9 | `AgentAuthRealmResourceProvider.java:1541-1653` |
| GET  | `/realms/{realm}/agent-auth/agent/{agentId}/capabilities/{capabilityName}/status` | (extension) | `AgentAuthRealmResourceProvider.java:2660-2727` |

Shared helpers: `HostJwtVerifier.java` (§4.5.1), `AgentJwtVerifier.java` (§4.5), `LifecycleClock.java` (§§2.3-2.5), `JwksCache.java` (§4.1), storage layer under `storage/` and `storage/jpa/`.

---

## Per-endpoint findings

### POST /agent/register

**Spec:** §5.3, §2.1, §2.2, §2.8, §2.11, §3.2, §4.5.1
**Impl:** `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:149-639`
**Summary:** 14 conformant • 3 documented deviations • 2 undocumented deviations • 2 violations

#### Conformance matrix

| # | Spec requirement | Spec § | Impl evidence (file:line) | Verdict |
|---|------------------|--------|---------------------------|---------|
| 1 | Host JWT required, `typ=host+jwt` | §4.5.1 | `:158-180` | CONFORMANT |
| 2 | `jti`, `iat`, `exp`, `aud`, `iss` MUST be present | §4.2, §4.5.1 | `:184-225` | CONFORMANT |
| 3 | `jti` replay rejected within JWT lifetime | §4.6 | `:190-193` (delegates to `isJtiReplay` `:3875-3887`) | CONFORMANT |
| 4 | `aud` MUST equal server's issuer URL | §4.2 | `:217-225` | CONFORMANT |
| 5 | `iss` MUST equal SHA-256 thumbprint of host signing key | §4.2, §4.5.1 step 4 | `:310-317` | CONFORMANT |
| 6 | Host pubkey via inline `host_public_key` OR `host_jwks_url` (mutually exclusive) | §4.2 | `:227-257` | DEVIATION (D1, mutual exclusion is impl choice) |
| 7 | `agent_public_key` or `agent_jwks_url` MUST be present | §4.2, §5.3 | `:259-289` | CONFORMANT |
| 8 | Required body field `name` | §5.3 | `:331-336` | CONFORMANT |
| 9 | `mode` defaults to `delegated`, accepts `autonomous` | §2.2 | `:339-351` | CONFORMANT |
| 10 | Unknown caps → `400 invalid_capabilities` listing names | §5.3, §5.13 | `:415-418`, `:503-506` | CONFORMANT |
| 11 | New host → `pending` per §2.8 dynamic-registration | §2.8, §2.11 | `:611-615` | CONFORMANT |
| 12 | Pending host → agent `pending` and all grants `pending` (§2.11) | §2.11 | `:432-433`, `:567-569` | CONFORMANT |
| 13 | Auto-approve when host is linked AND caps in defaults (§5.3 / §3.1 TOFU) | §5.3 | `:431-446` | CONFORMANT |
| 14 | Idempotent retry on existing-pending agent (same key/host) | §5.3 | `:531-548` | CONFORMANT |
| 15 | Existing terminal/active agent → `409 agent_exists` | §5.3 | `:534-547` | CONFORMANT |
| 16 | Response: `agent_id`, `host_id`, `name`, `mode`, `status`, `agent_capability_grants` | §5.3 | `:572-602`, `sanitizeAgentResponse` `:3735-3776` | CONFORMANT |
| 17 | `approval` object only when `status=pending` | §5.3, §7.1 | `:589-602` | CONFORMANT |
| 18 | `delegated` agent under linked host inherits `user_id` | §3.2 | `:626-628` | CONFORMANT |
| 19 | Revoked/rejected host → 403 | §2.11 | `:507-516` | CONFORMANT |
| 20 | Per-grant active grants surface `description`/`input`/`output` | §5.3 | `:445-452` | CONFORMANT |
| 21 | Pending grants are compact `{capability, status}` | §5.3 | `:442-444`, `sanitizeGrantsForResponse` `:3762-3776` | CONFORMANT |

#### Documented intentional deviations
- **D1.** Inline-key vs JWKS-URL hosts are mutually exclusive on a single registration (`:230-235`). README:232 documents: "Inline and JWKS URL are mutually exclusive per identity, and `agent_kid` is required when `agent_jwks_url` is used." Spec §4.2 lists both fields without explicit exclusion; this is a tightening, not a violation.
- **D2.** JWKS URLs must be HTTPS (except localhost / container hosts). README:236 documents: "JWKS fetches require HTTPS, except for localhost and container-test hostnames... — intentionally stricter than the spec's URL-fetching guidance." Enforced inside `JwksCache.fetchJwks` (not on this endpoint directly but on the JWKS-resolution path).
- **D3.** Autonomous registrations on unknown hosts return `400 host_pre_registration_required` (`:554-562`). README:101-103 documents the admin pre-registration / `client_id` path; this guard surfaces the spec-implied "no approval flow for autonomous-on-pending-host" rule (§2.11 forbids activating an agent under a pending host).

#### Undocumented intentional deviations (likely doc gap)
- **U1.** SA-host (host pre-registered with `service_account_client_id`) blocks `mode=delegated` with `400 invalid_mode_for_sa_host` (`:521-528`). The rationale comment is good (no human consent channel for an SA), but the README mentions the `agent-environments` provisioning flow without spelling out this guard. Note in README so admins know to set `mode=autonomous` for SA-bound clients.
- **U2.** When the entitlement gate strips a cap from an autonomous registration the cap is appended to `invalid_capabilities` and the whole registration fails with `400 invalid_capabilities` (`:493-505`). This is reasonable, but `invalid_capabilities` per §5.13 conventionally means "unknown name". Document the dual semantics, or split the response into `invalid_capabilities` (unknown) vs `forbidden_capabilities` (entitlement-denied).

#### Violations (action required)

- **V1. Auto-deny grants are emitted with `status=denied` and an internal `reason` instead of being treated as a request-time error**
  - **Spec:** §5.3 — registration response carries grants with `status` of `"active"` or `"pending"`; §3.3 — `Agent Capability Grant.status` enum is `active | pending | denied`, but a denied grant is the result of approval, not an admin pre-flag.
  - **Impl:** `:425, :434, :439-441` — when `auto_deny=true` on the cap, the registration succeeds and emits `{capability, status: "denied", reason: "Capability has auto_deny enabled"}` while `requiresApproval` is forced to `false` (`:434`).
  - **Why violation:** `auto_deny` is an extension flag (admin write side). Emitting a denied grant on the registration response means the agent is created `active` even though one of the requested caps was rejected, with no way for the spec-defined client to discover that the resulting grant is unusable. The §5.3 contract is "active or pending" for the agent state; once a cap is policy-rejected the request behaves like an invalid cap and should follow the §5.3 / §5.13 `invalid_capabilities` shape (or a new extension error code documented in README).
  - **Suggested fix:** Surface auto-denied caps the same way unknown caps are surfaced — append the name to `invalid_capabilities` (or a sibling `denied_capabilities`) and return `400` with the offending names so the client sees the rejection at request time. If the current behavior is intentional, document `auto_deny` and the `denied` grant shape in README.

- **V2. Internal storage fields leak through registration response**
  - **Spec:** §3.2 / §5.3 — protocol fields are `id`, `name`, `host_id`, `user_id?`, `public_key?`, `jwks_url?`, `status`, `mode`, `last_used_at?`, `activated_at?`, `expires_at?`, `created_at`, `updated_at`, `agent_capability_grants[]` and (when pending) `approval`.
  - **Impl:** `sanitizeAgentResponse` `:3735-3776` does a shallow copy of `agentData` and only strips `requested_constraints`/`status_url` from grants. Other internal keys persisted on the agent map (e.g. `agent_key_thumbprint` `:575`, `agent_public_key` blob `:576`, `session_ttl_reset_at` `:1437`, `max_lifetime_reset_at` `:1438`, `absolute_lifetime_elapsed`, `revocation_reason`, `rejection_reason`, `agent_kid`, `user_code`) are returned verbatim when they happen to be set.
  - **Why violation:** §3.2 enumerates protocol agent fields; admin/extension keys are not in that list. `agent_public_key` and `agent_kid` are merely re-exposed (the client already has them), but `user_code` (spec §7.1 *user-facing* code on the approval object — but stored under `agentData.user_code` for the registration that minted it) and internal reset timestamps are leaked into the wire. Aligns with the `describe` whitelist violation in `discovery-catalog.md` V1.
  - **Suggested fix:** Replace the shallow copy in `sanitizeAgentResponse` with an explicit projection of §3.2 fields, then add `agent_capability_grants` and `approval` (if pending). Strip `agent_key_thumbprint`, `session_ttl_reset_at`, `max_lifetime_reset_at`, `absolute_lifetime_elapsed`, `user_code`, `agent_kid`, `agent_public_key` blob from the response shape.

---

### GET /agent/status

**Spec:** §5.5, §3.2, §4.5.1
**Impl:** `AgentAuthRealmResourceProvider.java:1037-1133`
**Summary:** 11 conformant • 0 documented deviations • 0 undocumented deviations • 1 violation (shared with V2)

#### Conformance matrix

| # | Spec requirement | Spec § | Impl evidence | Verdict |
|---|------------------|--------|---------------|---------|
| 1 | Host JWT auth via §4.5.1 pipeline | §5.5, §4.5.1 | `:1044-1050` (shared `HostJwtVerifier.verify`) | CONFORMANT |
| 2 | `agent_id` query parameter required → `400 invalid_request` | §5.5 | `:1075-1078`, `:1100-1103` | CONFORMANT |
| 3 | Unknown agent → `404 agent_not_found` | §5.5 | `:1105-1109` | CONFORMANT |
| 4 | Cross-host agent → `403` Host mismatch | §5.5 | `:1111-1114` | CONFORMANT |
| 5 | Revoked host → `403 host_revoked` ahead of jti consumption (so the same JWT used to revoke can still poll status) | §2.11 | `:1062-1067` + `Options.forAgentStatus()` defers replay | CONFORMANT |
| 6 | Lifecycle clocks evaluated lazily on read | §§2.3-2.5 | `:1116-1125`, `LifecycleClock.applyExpiry` | CONFORMANT |
| 7 | Returns full §3.2 agent record + grants | §5.5, §3.2 | `:1127` `sanitizeAgentResponse` | CONFORMANT |
| 8 | Active grants include `description`, `input`, `output`; denied grants show `reason` | §5.5 | grant persisted at `:445-452`, retained through sanitize | CONFORMANT |
| 9 | Lazy expiry transitions persist | §2.3 | `:1119-1125` writes back on transition | CONFORMANT |
| 10 | Rotated host key on JWT → `401 invalid_jwt` | §5.9 safety | `:1056-1060` | CONFORMANT |
| 11 | jti replay enforced after host-status check | §4.6 | `:1094-1098` | CONFORMANT |

#### Documented intentional deviations
None.

#### Undocumented intentional deviations
None.

#### Violations (action required)

- **V3. Status response leaks internal/admin keys** — same shape leak as V2. See V2's spec / fix; the `sanitizeAgentResponse` call at `:1127` is the same code path.

---

### POST /agent/reactivate

**Spec:** §5.6, §2.4, §2.5
**Impl:** `AgentAuthRealmResourceProvider.java:1338-1473`
**Summary:** 12 conformant • 0 documented deviations • 1 undocumented deviation • 1 violation

#### Conformance matrix

| # | Spec requirement | Spec § | Impl evidence | Verdict |
|---|------------------|--------|---------------|---------|
| 1 | Host JWT auth via §4.5.1 | §5.6 | `:1346-1352` | CONFORMANT |
| 2 | `agent_id` body field required | §5.6 | `:1362-1365` | CONFORMANT |
| 3 | Unknown agent → 404, cross-host → 403, host pending/revoked → 403 | §5.6 | `:1369-1394` | CONFORMANT |
| 4 | Revoked agent → `403 agent_revoked` | §2.6 | `:1396-1399` | CONFORMANT |
| 5 | Rejected agent → `403 agent_rejected` | §2.3 | `:1401-1403` | CONFORMANT |
| 6 | Claimed agent → `403 agent_claimed` (terminal, §2.10) | §2.10 | `:1405-1407` | CONFORMANT |
| 7 | Pending agent → 403 (no-op, must finish original approval) | §2.5 | `:1409-1411` | CONFORMANT |
| 8 | Active agent → no-op success returning current status | §5.6 | `:1414-1416` | CONFORMANT |
| 9 | Absolute lifetime elapsed → flip to `revoked`, return `403 absolute_lifetime_exceeded` | §2.4, §5.6 | `:1421-1433` (uses `LifecycleClock.evaluate`, not `applyExpiry`, which preserves the original timestamps for the absolute clock) | CONFORMANT |
| 10 | Reset session TTL + max lifetime; record new `activated_at` | §5.6 | `:1437-1441` | CONFORMANT |
| 11 | Capabilities decay to host defaults (TOFU auto-grant logic) | §2.5, §5.6 | `:1443-1444` `buildReactivationGrants` `:4147-4201` | CONFORMANT |
| 12 | Status flips to `active` or `pending` based on whether any default needs approval | §5.6 | `:1446-1462` | CONFORMANT |

#### Documented intentional deviations
None.

#### Undocumented intentional deviations (likely doc gap)
- **U1.** Reactivation always uses the host's stored `default_capability_grants` snapshot (`:4148-4198`) rather than recomputing what the host's *current* default capabilities are. If an admin trims `default_capabilities` on the host between expiry and reactivation, the trimmed cap still re-grants because it's in the registration-time snapshot. The spec wording is "host's current default capabilities" — this is a divergence from a strict reading. Likely intentional (TOFU semantics) but not noted.

#### Violations (action required)

- **V4. Reactivation does not run the entitlement gate over the rebuilt grant set**
  - **Spec:** §2.5 — "Capabilities decay to baseline: any previously escalated capabilities are removed and MUST be requested again." §5.6 — "follow the same auto-approval logic as registration."
  - **Impl:** `buildReactivationGrants` `:4147-4201` rebuilds grants from the host's `default_capability_grants` snapshot but does NOT consult `userEntitlementAllows` against the host's current owner. Registration (`:487-501`) and request-capability (`:2081-2085`) both run the gate.
  - **Why violation:** A delegated agent under a linked host whose owner's role/org membership changed between registration and reactivation can re-acquire a cap they no longer satisfy because the gate is skipped. Spec §5.6 binds reactivation to "the same auto-approval logic as registration" — so the auth model should be in lock-step.
  - **Suggested fix:** In `buildReactivationGrants` (or in `reactivateAgent` after the call), filter the rebuilt grants through `loadUserEntitlement(resolveEffectiveUserId(agentData, hostData))` + `userEntitlementAllows(registeredCap, entitlement)`; demote grants that fail the gate to `denied(insufficient_authority)` or strip them entirely (consistent with the entitlement filter at execute/introspect).

---

### POST /agent/revoke

**Spec:** §5.7, §2.6
**Impl:** `AgentAuthRealmResourceProvider.java:1258-1336`
**Summary:** 9 conformant • 0 deviations • 0 violations

| # | Spec requirement | Spec § | Impl evidence | Verdict |
|---|------------------|--------|---------------|---------|
| 1 | Host JWT auth via §4.5.1 | §5.7 | `:1266-1272` | CONFORMANT |
| 2 | `agent_id` body required → `400 invalid_request` | §5.7 | `:1282-1285` | CONFORMANT |
| 3 | Unknown agent → 404; cross-host → 403; pending/revoked host → 403 | §5.7, §2.11 | `:1289-1315` | CONFORMANT |
| 4 | Idempotent on already-revoked agent | §5.7 | `:1317-1322` | CONFORMANT |
| 5 | Response `{agent_id, status: "revoked"}` exactly | §5.7 | `:1330` | CONFORMANT |
| 6 | Permanent (status=revoked persisted) | §2.6 | `:1324-1328` | CONFORMANT |
| 7 | Optional `reason` stored as `revocation_reason` (extension) | — | `:1325-1327` | CONFORMANT (ext.) |

---

### POST /agent/rotate-key

**Spec:** §5.8, §4.1
**Impl:** `AgentAuthRealmResourceProvider.java:1135-1256`
**Summary:** 10 conformant • 0 documented deviations • 1 undocumented deviation • 1 violation

#### Conformance matrix

| # | Spec requirement | Spec § | Impl evidence | Verdict |
|---|------------------|--------|---------------|---------|
| 1 | Host JWT auth via §4.5.1 | §5.8 | `:1143-1149` | CONFORMANT |
| 2 | `agent_id` and `public_key` body fields required | §5.8 | `:1159-1164` | CONFORMANT |
| 3 | `public_key` MUST be a JWK object | §5.8, §4.1 | `:1167-1183` | CONFORMANT |
| 4 | Ed25519 only | §4.1 | `:1185-1190` | CONFORMANT |
| 5 | Unknown agent → 404 | §5.8 | `:1192-1196` | CONFORMANT |
| 6 | Cross-host → 403 | §5.8 | `:1198-1201` | CONFORMANT |
| 7 | Unknown / pending / revoked host → 401/403 | §4.5.1, §2.11 | `:1203-1221` | CONFORMANT |
| 8 | Terminal agent (revoked/rejected/claimed) → 403 | §2.6, §2.10 | `:1224-1228` | CONFORMANT |
| 9 | Pending or expired agent → 403 (rotation only valid on active) | §5.8 | `:1233-1242` | CONFORMANT |
| 10 | New key replaces old immediately, response `{agent_id, status: "active"}` | §5.8 | `:1244-1250` | CONFORMANT |

#### Documented intentional deviations
None.

#### Undocumented intentional deviations (likely doc gap)
- **U1.** When the agent record carries an `agent_jwks_url`, this endpoint silently overwrites the inline `agent_public_key` field but leaves `agent_jwks_url` and `agent_kid` in place. After rotation the verifier will pick whichever is set; the JWKS URL still wins (`AgentJwtVerifier.resolveAgentPublicKey` `:277-301` favors `agent_jwks_url` when present). README says JWKS-based identities rotate through their JWKS endpoint. The impl should reject `rotate-key` on JWKS-based agents (or clear the JWKS URL) — silent precedence is surprising. Document or guard.

#### Violations (action required)

- **V5. Rotation accepts the same key as the current key**
  - **Spec:** §5.8 — "The old key stops working immediately." Implies the new key is distinct; §4.1 keypairs section ("private key MUST never be sent to the server" — operationally the rotation only matters if the key changes).
  - **Impl:** `:1244-1246` writes the new `agent_public_key` and recomputes thumbprint without comparing to the existing stored value. A `rotate-key` call replaying the current public key reports success and burns no state.
  - **Why violation:** Although §5.8 doesn't word a literal MUST about uniqueness, the operational invariant that "old key stops working" cannot hold if the new key equals the old. A no-op rotation can mask a failed/stalled rotation in incident response — the operator gets a 200 but the compromised key still authenticates. The host-key path (`rotateHostKey`) has the same gap (`:1631-1634` writes without comparison, see V6 below).
  - **Suggested fix:** Compute `newAgentKey.computeThumbprint().toString()` before persisting and compare against the stored `agent_key_thumbprint` (or to the JWKS-resolved current key); reject equality with `400 invalid_request "new key must differ from current key"`. Mirror in `rotateHostKey`.

---

### POST /agent/request-capability

**Spec:** §5.4, §3.3, §2.13
**Impl:** `AgentAuthRealmResourceProvider.java:1965-2227`
**Summary:** 13 conformant • 1 documented deviation • 1 undocumented deviation • 1 violation

#### Conformance matrix

| # | Spec requirement | Spec § | Impl evidence | Verdict |
|---|------------------|--------|---------------|---------|
| 1 | Agent JWT auth via §4.5 (full pipeline) | §5.4, §4.5 | `:1981-1986` | CONFORMANT |
| 2 | Verifier rejects non-active agent and non-active host | §4.5 | `AgentJwtVerifier.java:172-211` | CONFORMANT |
| 3 | `capabilities[]` body required, non-empty | §5.4 | `:1994-2010` | CONFORMANT |
| 4 | Each cap may be string or `{name, constraints}` object | §5.4 | `:2037-2067` | CONFORMANT |
| 5 | Unknown caps surface `400 invalid_capabilities` listing names | §5.4, §5.13 | `:2076-2079`, `:2156-2161` | CONFORMANT |
| 6 | Already-active grant for cap → keep existing, do not re-prompt | §5.4 | `:2092-2106` | CONFORMANT |
| 7 | TOFU auto-grant for caps in host defaults | §5.3, §5.4 | `:2116-2118` | CONFORMANT |
| 8 | Pending grants stash `requested_constraints` so approval restores scope | §2.13 | `:2128-2135`, `sanitizeGrantsForResponse` `:3762-3776` | CONFORMANT |
| 9 | Active grants surface `description`, `input`, `output`, `granted_by`, `constraints` | §5.4 | `:2136-2148` | CONFORMANT |
| 10 | Response shape: `agent_id`, `agent_capability_grants` (only newly requested) | §5.4 | `:2184-2189` | CONFORMANT |
| 11 | Approval object only when `requiresApproval` | §5.4 | `:2190-2215` | CONFORMANT |
| 12 | Reuses existing pending approval blob if present (avoids extending the original window) | §7.1, §7.2 | `:2199-2213` | CONFORMANT |
| 13 | Agent `expires_at` extended on request (TTL renewal) | §2.4 | `:2216-2218` | CONFORMANT |
| 14 | All caps already active → `409 already_granted` | §5.4 | `:2163-2168` | (extension — see U1) |
| 15 | Entitlement gate stripped caps for autonomous-or-linked-host agents | §3.1 multi-tenant extension | `:2026-2035`, `:2081-2085` | CONFORMANT (extension) |

#### Documented intentional deviations
- **D1.** `409 already_granted` (`:2163-2168`) when every requested cap is already active — spec §5.4 doesn't specify this case explicitly. Treating an empty new-grant set as a 409 keeps clients honest about checking before re-requesting. Worth noting in README, but matches sane idempotency.

#### Undocumented intentional deviations (likely doc gap)
- **U1.** When *some* requested caps are already active and *some* are new, the response includes the existing active grants in `agent_capability_grants` (`:2104-2106` add the existing grant into `newGrants`) alongside the new ones. The §5.4 prose says: "Returns only requested grants, not full agent state." That is satisfied — but emitting the existing-active row in a §5.4 response could surprise clients that diff against §5.3's response. Either documented behavior is fine; consider a README bullet under `request-capability`.

#### Violations (action required)

- **V6. `partial-success` shape returns 400 even when at least one cap is valid and approvable**
  - **Spec:** §5.4 / §5.13 — `invalid_capabilities` with the `invalid_capabilities[]` array signals unknown names. The auto-deny / entitlement-stripped paths in `request-capability` also funnel into `invalidCaps` (`:2077, :2083`).
  - **Impl:** `:2156-2161` — if `invalidCaps` is non-empty (even with one entry), the entire request returns 400 and any caps that *would* have been processed are abandoned. There is no "partial success" path.
  - **Why violation:** If a client requests `[ok_cap, denied_by_role_cap]`, both are dropped. The spec wording "the server should validate the capabilities array" leaves this open, but the operational consequence is that a client can't progressively narrow its request — a single failing cap blocks the rest. Combined with V1 (auto_deny silently emits a denied grant), the dual semantics are confusing.
  - **Suggested fix:** Either (a) split `invalid_capabilities` into a 207-style partial response (`{granted: [...], denied: [...]}`) — would require spec extension — or (b) at minimum, distinguish "unknown name" from "entitlement denied" so a client can act differently. Easiest concrete fix: add a `denied_capabilities[]` array sibling to `invalid_capabilities` in the 400 body so the client knows which caps to drop versus rename.

---

### POST /host/revoke

**Spec:** §5.10
**Impl:** `AgentAuthRealmResourceProvider.java:1475-1539`
**Summary:** 7 conformant • 0 deviations • 0 violations

| # | Spec requirement | Spec § | Impl evidence | Verdict |
|---|------------------|--------|---------------|---------|
| 1 | Host JWT auth via §4.5.1 | §5.10 | `:1483-1489` | CONFORMANT |
| 2 | No body required | §5.10 | endpoint ignores body | CONFORMANT |
| 3 | Idempotent on already-revoked host (`agents_revoked: 0`) | §5.10 | `:1499-1508` | CONFORMANT |
| 4 | Unknown host → 404 | (impl choice) | `:1510-1514` | CONFORMANT |
| 5 | Cascade: every agent under host → revoked (skip already-revoked) | §5.10 | `:1521-1528` | CONFORMANT |
| 6 | Response `{host_id, status:"revoked", agents_revoked:n}` exact shape | §5.10 | `:1530-1532` | CONFORMANT |
| 7 | Rotated key on JWT → 401 | §5.9 safety | `:1493-1497` | CONFORMANT |

---

### POST /host/rotate-key

**Spec:** §5.9
**Impl:** `AgentAuthRealmResourceProvider.java:1541-1653`
**Summary:** 11 conformant • 1 documented deviation • 0 undocumented deviations • 1 violation

#### Conformance matrix

| # | Spec requirement | Spec § | Impl evidence | Verdict |
|---|------------------|--------|---------------|---------|
| 1 | Host JWT signed with the current (pre-rotation) key | §5.9 | `:1549-1555` | CONFORMANT |
| 2 | Rejects rotated keys (history check) | §5.9 | `:1560-1567` | CONFORMANT |
| 3 | Unknown host → 404 (must mutate existing record only) | §5.9 | `:1570-1578` | CONFORMANT |
| 4 | Revoked host → `403 host_revoked`; non-active → `409 invalid_state` | §2.11, §5.9 | `:1580-1592` | CONFORMANT |
| 5 | `public_key` body field required, JWK object | §5.9, §4.1 | `:1594-1605` | CONFORMANT |
| 6 | Ed25519 only | §4.1 | `:1617-1622` | CONFORMANT |
| 7 | Update host record's `public_key` and `host_id` to new thumbprint | §5.9 | `:1631-1632` | CONFORMANT |
| 8 | Record old→new mapping in rotation history; remove old row | §5.9 | `:1634-1636` | CONFORMANT |
| 9 | Cascade `host_id` rewrite to all agents under the host | §5.9 ("agent records … remain bound to the host record") | `:1638-1641` | CONFORMANT |
| 10 | Response `{host_id, status: "active"}` exact shape | §5.9 | `:1646` | CONFORMANT |
| 11 | JWKS-fallback iss rebind allowed only on this endpoint via `Options.forRotateHostKey()` | §5.9 (inline-key only) | `:1552`, `HostJwtVerifier.java:283-285` | CONFORMANT |

#### Documented intentional deviations
- **D1.** README:238 documents: "Inline-key identities rotate through the explicit endpoints; JWKS-based identities rotate by publishing the new key at the JWKS URL." Spec §5.9 says "for inline key hosts only"; this matches the spec but the impl doesn't actively *forbid* a JWKS-served host calling here. The verifier locates the host via JWKS fallback, then `rotateHostKey` mutates the inline `public_key` field — which conflicts with the JWKS-served model. Worth a guard, but README's guidance is enough to call this a documented behavior.

#### Violations (action required)

- **V7. Rotation accepts the same key as the current key (host-side)**
  - **Spec:** §5.9 — "The old key stops working immediately." "Future host JWTs must be signed with the new key."
  - **Impl:** `:1624-1635` computes `newIss` and writes it without comparing against the pre-rotation `iss`/stored host PK. A self-rotation to the same key burns no state and reports success.
  - **Why violation:** Same operational rationale as V5 (agent rotate). After a "rotation" returning 200, an operator may believe the prior key is retired; if `newKey == oldKey`, it isn't.
  - **Suggested fix:** Add `if (newIss.equals(oldIss)) return 400 invalid_request "new key must differ from current key"` immediately after computing `newIss` (`:1624`). For the JWKS-fallback path, compare against `verified.iss()` (the verified pre-rotation thumbprint).

---

### GET /agent/{agentId}/capabilities/{capabilityName}/status

**Spec:** *Extension — no spec section.* Documented in README:61 as "Poll a pending grant while it awaits approval." Spec §5.5 is the comprehensive status endpoint.
**Impl:** `AgentAuthRealmResourceProvider.java:2660-2727`
**Summary:** Compatibility check vs §5.5: no conflict.

#### Behavior

- Auth: host JWT, full §4.5.1 pipeline (`:2674-2680`).
- Responds `{agent_id, capability, status, reason?}` (`:2708-2715`).
- 404 `capability_not_granted` when grant not found (`:2719-2721`).
- Cross-host: 403 (`:2697-2700`).

#### Findings

- **No conflict with §5.5.** The endpoint is a strict subset of the data §5.5 already returns; it does not introduce a state transition, replay window, or new shape on protocol-defined endpoints. Polling semantics piggyback on host JWT auth — pending agents cannot mint an `agent+jwt`, so the host that registered them is correctly the principal here.
- **Nit:** The docstring `:2668-2673` correctly cites §5.5. Adding a `Cache-Control: no-store` header (the response is per-grant state and consumed at high cadence by polling clients) would prevent any intermediary from caching a stale `pending` after the approval lands. Not a violation.

---

## Action plan (prioritized)

P0 = MUST violation in core flow • P1 = SHOULD violation or MUST in edge case • P2 = nit / future-proofing

| # | Priority | Title | Endpoint | Spec § | Impl ref | Fix sketch |
|---|----------|-------|----------|--------|----------|------------|
| 1 | P0 | Reject `auto_deny` caps at request time instead of returning a denied grant | `POST /agent/register` (V1) | §5.3, §3.3 | `:425-441, :503-506` | When `registeredCap.auto_deny == true`, append the cap name to a `denied_capabilities[]` (or push it into `invalid_capabilities`) and return `400` instead of stamping `status=denied` on the grant. Document `auto_deny` extension in README either way. |
| 2 | P0 | Reject self-rotation that re-uses the current key | `POST /agent/rotate-key` (V5), `POST /host/rotate-key` (V7) | §5.8, §5.9 | `:1244-1246, :1624-1635` | Compute the new key thumbprint, compare to the stored `agent_key_thumbprint` (resp. pre-rotation host iss), return `400 invalid_request "new key must differ from current key"` on equality. |
| 3 | P0 | Re-run entitlement gate on reactivation grants | `POST /agent/reactivate` (V4) | §5.6, §2.5 | `:1443-1444, :4147-4201` | After `buildReactivationGrants`, intersect the rebuilt grant set with `userEntitlementAllows(cap, loadUserEntitlement(resolveEffectiveUserId(agentData, hostData)))`; demote failing grants to `denied(insufficient_authority)` or strip them. Mirror the gate logic from `:487-501`. |
| 4 | P1 | Project agent-response fields to the §3.2 protocol set | `POST /agent/register` (V2), `GET /agent/status` (V3), `POST /agent/reactivate` | §3.2, §5.3, §5.5, §5.6 | `sanitizeAgentResponse` `:3735-3776` | Replace shallow copy with explicit projection of the §3.2 fields plus `agent_capability_grants` and `approval`. Strip `agent_key_thumbprint`, `*_reset_at`, `absolute_lifetime_elapsed`, `user_code`, `agent_kid`, internal `approval.issued_at_ms` from the wire. |
| 5 | P1 | Distinguish entitlement-denied from unknown caps in `request-capability` 400 body | `POST /agent/request-capability` (V6) | §5.4, §5.13 | `:2076-2085, :2156-2161` | Track the two failure reasons in separate lists (`unknown_capabilities`, `denied_capabilities`); return `400 invalid_capabilities` with both arrays present so callers can reason about each cap individually. |
| 6 | P2 | Document SA-host blocks `mode=delegated` | `POST /agent/register` (U1) | §2.8 | `:521-528` | Add a README bullet under `agent-environments` clarifying that SA-bound hosts MUST register agents with `mode=autonomous`. |
| 7 | P2 | Document or guard JWKS-served agents calling `rotate-key` | `POST /agent/rotate-key` (U1) | §5.8 | `:1244` | Either reject the call when `agent_jwks_url` is set on the agent record (`return 400 jwks_rotation_required`) or document precedence in README under "Identity and keys". |
| 8 | P2 | Document/guard JWKS-served hosts calling `host/rotate-key` | `POST /host/rotate-key` (D1) | §5.9 | `:1546-1646` | Reject when host has `host_jwks_url` set (`return 400 jwks_rotation_required`) so JWKS-served hosts can't accidentally land an inline `public_key`. README:238 already documents the intent; a guard makes it enforceable. |
| 9 | P2 | Document `409 already_granted` and partial existing-grant echo | `POST /agent/request-capability` (D1, U1) | §5.4 | `:2104-2106, :2163-2168` | Add a README bullet under `agent/request-capability` describing both behaviors so clients aren't surprised. |
| 10 | P2 | Add `Cache-Control: no-store` to per-grant status | `GET /agent/{id}/capabilities/{name}/status` | (extension) | `:2715` | Add the header to the 200 path so polling clients never see a stale `pending` from a CDN/proxy. |
| 11 | P2 | Reactivation uses snapshot rather than live host defaults | `POST /agent/reactivate` (U1) | §5.6 | `:4147-4201` | Either rebuild from `hostData.default_capabilities` directly (live) or document the snapshot semantics in README under "Identity and keys" / "Auto-grant". |

---

## Methodology notes

- **Spec subsections fetched:** §1.4, §2.1-2.11, §3-§3.3.1, §4.1-§4.6, §5.3-§5.10, §5.13, §7.1-§7.2.
- **Files read:** `AgentAuthRealmResourceProvider.java` (`:1-639, :1037-1473, :1541-1653, :1900-2227, :2660-2727, :3700-3776, :3800-4368`), `HostJwtVerifier.java` (full), `AgentJwtVerifier.java` (full), `LifecycleClock.java` (full), `JwksCache.java` (resolution path), `storage/AgentAuthStorage.java`, `storage/jpa/AgentEntity.java`, `README.md` (full), `docs/spec-audit/discovery-catalog.md` (sanitize/projection convention reused in V2/V3 fix sketch).
- **Verification gaps:**
  - §3.3 per-grant `expires_at` is read for execute/introspect (`isEffectiveActiveGrant` `:3864-3873`); the lifecycle endpoints don't write it, so the §3.3 surface beyond `status` was not stress-tested.
  - §4.5.1 step 3 (JWKS-fallback "fetch by `kid`, thumbprint matches `iss`") confirmed in `HostJwtVerifier.java:182-190`; the iss-rebind path is correctly contained to `rotate-host-key` via `Options.forRotateHostKey()`.
  - §4.6 jti replay: `isJtiReplay` `:3875-3887` ties cache TTL to JWT `exp` (min 60 s) via Keycloak `singleUseObjects` — verified by inspection only.
