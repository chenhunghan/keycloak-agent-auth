# AAP v1.0-draft Audit — Execution & Introspection

> **Source of truth:** https://agent-auth-protocol.com/specification/v1.0-draft
> **Audited:** 2026-04-28
> **Scope:** `/capability/execute`, `/agent/introspect`, shared constraint engine + agent-JWT verifier

## Endpoints in scope

| Method | Path | Spec § | Impl |
|--------|------|--------|------|
| POST | `/realms/{realm}/agent-auth/capability/execute` | §5.11, §2.15, §4.5 | `AgentAuthRealmResourceProvider.java:2230-2658` |
| POST | `/realms/{realm}/agent-auth/agent/introspect` | §5.12, §4.5 | `AgentAuthRealmResourceProvider.java:642-1035` |

Shared helpers: `AgentJwtVerifier.java`, `ConstraintValidator.java`, `LifecycleClock.java`, `JwksCache.java`.

`AgentJwtVerifier` is the centralised pipeline but is currently wired only to the catalog endpoints; execute and introspect both open-code their own chains (self-flagged at `:2312-2316` and `:841-845` as deferred migration).

## Cross-cutting: Agent JWT verification chain

§4.5 implies: typ → iss/sub → aud → host → agent → status → signature → exp/iat/jti → caps intersect → constraints. §4.6 places replay after signature.

| # | Requirement | Verifier | execute | introspect | Verdict |
|---|-------------|----------|---------|------------|---------|
| 1 | `typ=agent+jwt` | `:108-111` | `:2256-2261` (401) | `:723-725` (`active:false`) | CONFORMANT |
| 2 | `jti`/`iat`/`exp`; not future/expired | `:120-135` | `:2264-2289` | `:727-780` | CONFORMANT (30 s skew) |
| 3 | aud match | `:137-140` | `:2478-2483` | `:790-833` (multi-grant) | INTENDED DEVIATION (D1, U7) |
| 4 | `iss` identifies parent host | `:145-203` (exact + JWKS rotation) | `:2298-2321` (exact only) | `:836-849` (exact only) | UNDOC. DEVIATION (U1) |
| 5 | Lifecycle-clock + reject non-active agent | `:155-178` (BEFORE sig) | `:2356-2393` (AFTER sig) | `:732-754` (BEFORE sig) | execute: **V1** |
| 6 | Reject non-active host | `:185-212` | `:2323-2335` (per-state codes) | `:851-854` (`active:false` per §5.12) | CONFORMANT |
| 7 | Verify signature | `:214-241` | `:2337-2344` | `:756-765` | CONFORMANT |
| 8 | Replay after sig | `:243-245` | `:2350-2354` | `:856-862` | CONFORMANT (see V1) |
| 9 | JWT `capabilities` claim intersect | n/a | `:2418-2426` (403) | `:797-806, :871-874` | CONFORMANT |
| 10 | Constraint check | n/a | `:2499-2524` (403, `violations[]`) | `:921-1029` (extension `violations[]`) | CONFORMANT (see V4) |

## Cross-cutting: Constraint operators (§2.13)

Single implementation in `ConstraintValidator.java`; both endpoints call it. Spec defines four operators plus exact-value match; impl supports exactly that set and rejects others with `IllegalArgumentException` mapped to `400 unknown_constraint_operator` (`AgentAuthRealmResourceProvider.java:4220-4227`).

| Operator | Spec | Impl (file:line) | Verdict |
|----------|------|------------------|---------|
| `max` | numeric `value <= max` | `ConstraintValidator.java:107-110` — both args must be `Number`; double-compare; missing/non-numeric → violation | CONFORMANT |
| `min` | numeric `value >= min` | `:110-112` — symmetric | CONFORMANT |
| `in` | value ∈ list | `:113-116` — opValue must be `List`; null → violation; uses Java `List#contains` | CONFORMANT |
| `not_in` | value ∉ list | `:116-119` — opValue must be `List`; null actual → passes (absent ≡ "not in") | CONFORMANT |
| exact-value | structural equality, any JSON type | `:43-54, :63-95` — Jackson `valueToTree` round-trip; numeric-by-decimal-value (`500 == 500.0`); arrays/objects compared structurally | CONFORMANT |

Edge cases: `in: []` violates everything (vacuously); `not_in: []` admits everything; missing argument + `in` violates; missing + `not_in` passes; missing + exact violates with `actual:null`; unknown operator → `IllegalArgumentException` → `400` at execute, but **swallowed at introspect** (V4).

## Per-endpoint findings

### POST /capability/execute

**Spec:** §5.11, §2.15, §4.5
**Impl:** `AgentAuthRealmResourceProvider.java:2230-2658`
**Summary:** Hand-rolled JWT verification, grant resolution against `agent_capability_grants`, constraint check, then HTTP proxy to `capability.location`. Sync responses are buffered; SSE / chunked-transfer responses pass through via `StreamingOutput` with `Cache-Control: no-cache`. The gateway never synthesizes §5.11 sync/async/SSE shapes — the upstream owns them (D2).

#### Conformance matrix

| # | Requirement | § | Impl | Verdict |
|---|-------------|---|------|---------|
| E1 | typ + iss/sub/jti/iat/exp + skew 30 s | §4.3, §4.5 | `:2256-2303` | CONFORMANT |
| E2 | aud = resolved location | §4.3, §2.15 | `:2473-2483` | INTENDED DEVIATION (D1) |
| E3 | Reject non-active host (per-state codes) | §2.11 | `:2323-2335` via `hostMustBeActive` (`:3826-3856`) | CONFORMANT |
| E4 | Lifecycle-clock + agent-status reject (`agent_revoked`/`pending`/`expired`/`rejected`/`claimed`) | §2.3-2.5 | `:2356-2393` | shape OK; **ordering wrong (V1)** |
| E5 | Signature verify; replay after sig | §4.5/§4.6 | `:2337-2354` | CONFORMANT (see V1) |
| E6 | `400 invalid_request` on missing/invalid `capability`; `400` on non-object `arguments` | §5.11/§5.13 | `:2395-2433` | CONFORMANT (`name` alias, U3) |
| E7 | JWT `capabilities` claim intersect | §4.3 | `:2418-2426` → `403 capability_not_granted` | CONFORMANT |
| E8 | Effective grant (active AND not past `expires_at`); `404 capability_not_found`; `403 capability_not_granted` | §3.3, §5.11 | `:2435-2467` via `isEffectiveActiveGrant` (`:3864-3873`) | CONFORMANT |
| E9 | `403 constraint_violated` w/ `violations[]` `{field,constraint,actual}` | §2.13, §5.11 | `:2499-2524` | CONFORMANT |
| E10 | Sync `{data}` / 202 `{status, status_url}` / SSE `done` | §5.11 | `:2581-2631` (pass-through; never synthesized) | INTENDED DEVIATION (D2) |
| E11 | `{error, message[, …]}` envelope per §5.13; `WWW-Authenticate: AgentAuth discovery=…` | §5.13/§5.14 | every error path; `:2238-2245` | CONFORMANT |

#### Documented intentional deviations
- **D1.** **Gateway-mode aud accept.** Spec §2.15/§4.3 says `aud` is the resolved location and the agent posts directly to that URL. This impl runs in gateway mode by default — the agent posts to Keycloak's `/capability/execute` while the JWT carries `aud = capability.location` (or the discovery `default_location` for locationless caps). Operators wanting strict-spec route agents directly to `capability.location`. Documented in README ~138 ("Gateway audience semantics are an extension profile"); intentional, not actioned.
- **D2.** **Pass-through response shape.** §5.11 mandates four mutually-exclusive sync/async/SSE shapes. The gateway forwards upstream bytes verbatim with the upstream's status/content-type (`:2625-2631`). README line 135 documents this: "admin-registered resource servers MUST return spec-conformant `/capability/execute` shapes". Contract is shifted to the resource server. Intentional, not actioned.

#### Undocumented intentional deviations
- **U1.** **Exact `iss == host_id` match — no JWKS-rotation fallback.** `AgentJwtVerifier:194-203` accepts an iss whose thumbprint matches any key currently published at the host's `host_jwks_url`. Execute (`:2317-2321`) and introspect (`:847-849`) only do exact match. Self-flagged in code as deferred (Audit E-F6). Effect: a JWKS host that rotates its key cannot use the new key against execute/introspect until the migration to `AgentJwtVerifier` lands. Strict §4.5 reading is satisfied by exact match (it's not a violation), but the impl is internally inconsistent.
- **U3.** **`name` alias for `capability`.** `:2395-2405` accepts either field. Permissive; spec-strict clients always win. Not advertised.
- **U4.** **Refresh `expires_at` on every successful execute.** `:2526-2528` writes `last_used_at` and a 3600 s `expires_at`. §2.4 lets the server choose session-TTL semantics; flagged for completeness.

#### Violations (action required)

- **V1.** **Lifecycle-clock + agent-status check runs AFTER signature and replay; `jti` is consumed even when the agent has just transitioned to `expired`/`revoked`.**
  - **Spec:** §4.5 step 6 ("reject if revoked, expired, or pending") precedes step 7 (signature) and step 8 (replay).
  - **Impl:** `:2337-2344` (signature) → `:2350-2354` (replay) → `:2356-2393` (lifecycle clock + status). A token whose agent just hit its session/max/absolute-lifetime clock has its `jti` burned before the agent is even checked, so the legitimate agent — once it reactivates — sees both an `agent_*` 403 and a missing single-use slot for that token.
  - **Suggested fix:** Hoist the lifecycle-clock + agent-status block above the signature verify, matching `AgentJwtVerifier:165-178`. Replay (`:2350-2354`) stays last.

### POST /agent/introspect

**Spec:** §5.12, §4.5
**Impl:** `AgentAuthRealmResourceProvider.java:642-1035`
**Summary:** RFC 7662 introspection. Same hand-rolled chain (deferred migration). Optional `{capability, arguments}` extension runs constraint check and returns `violations[]` both at top-level (for the README's direct-mode contract, U5) and under `extensions.constraint_check` (U6).

#### Conformance matrix

| # | Requirement | § | Impl | Verdict |
|---|-------------|---|------|---------|
| I1 | `POST /agent/introspect` with `{token}` body | §5.12 | `:642-720` | CONFORMANT |
| I2 | `400 invalid_request` on missing/non-string token | §5.13 | `:706-719` | CONFORMANT |
| I3 | `active=false` on every failure (malformed, unknown agent, non-active, sig fail, expired, replay, host inactive, aud mismatch) | §5.12 | `:721-862` | CONFORMANT |
| I4 | RFC 7662 fields when active: `active`, `client_id`, `sub`, `exp`, `iat`, `scope`, `username`/optional | §5.12 / RFC 7662 | `:954-971` — adds `agent_id`, `host_id`, `iss`, `mode`, `expires_at`, `aud`, `jti`, `capabilities` (U8) | CONFORMANT |
| I5 | Compact `agent_capability_grants` ({capability, status} only) | §5.12 | `:912-918` | CONFORMANT |
| I6 | Optional `user_id` when host linked | §5.12 | `:976-982` | CONFORMANT |
| I7 | `mode` ∈ {delegated, autonomous} | §5.12 | `:967` | CONFORMANT |
| I8 | `expires_at` ISO-8601 | §5.12 | `:968` | CONFORMANT |
| I9 | Optional `{capability, arguments}` extension; `violations[]` shape | §5.12 | `:921-1029` (top-level + extension) | CONFORMANT (U5/U6 below) |
| I10 | Server-to-server auth or aggressive rate limit | §5.12 | `:662-691` (shared-secret + 100 req/60 s limiter) | CONFORMANT |
| I11 | Replay after signature | §4.5/§4.6 | `:856-862` | CONFORMANT |
| I12 | Lifecycle-clock before status | §2.3-2.5 | `:742-754` | CONFORMANT |
| I13 | aud-acceptance set | §4.3 | `:790-833` (any effective-grant resolved location) | INTENDED DEVIATION (U7) |

#### Documented intentional deviations
- **D1 (introspect side).** Same gateway audience-semantics extension. Introspect doesn't yet know which capability the resource server will dispatch, so it admits the token if `aud` matches any of the agent's currently-effective grants' resolved locations.

#### Undocumented intentional deviations
- **U5.** **Top-level `violations[]` mirror.** `:1023-1028` mirrors `extensions.constraint_check.violations` at the top level so README direct-mode resource servers can do `body.violations.length === 0`. Self-flagged ("Audit E-F7"). Spec-strict readers can also rely on the extension key; benign duplication.
- **U6.** **`extensions.constraint_check` namespace.** `:1020-1022` nests the constraint result under an `extensions` envelope rather than top-level. §5.12 example puts these at the top level; the impl gives both shapes (U5).
- **U7.** **Multi-grant aud admission.** `:807-833` accepts any effective grant's resolved location. §4.3 is singular per execution; introspect doesn't yet know the cap. Reasonable but undocumented.
- **U8.** **Extra RFC 7662 fields.** RFC 7662 §2.2 explicitly allows additions; spec example shows a smaller set.

#### Violations (action required)

- **V4.** **Unknown constraint operator at introspect is swallowed as `active:false` instead of `400 unknown_constraint_operator`.**
  - **Spec:** §2.13 — server MUST return `400 unknown_constraint_operator`. §5.12 doesn't exempt introspect.
  - **Impl:** `:1006-1018` calls `ConstraintValidator#validate` inside the broad `try { ... } catch (Exception e) { return active:false }` at `:721-1034`. `IllegalArgumentException("Unknown constraint operator: …")` is caught at `:1032-1034` and downgraded. Execute correctly returns 400 (`:2505-2508`).
  - **Why violation:** A malformed grant should surface as a 400 to the resource server; downgrading hides config errors and makes a healthy agent look revoked.
  - **Suggested fix:** Catch `IllegalArgumentException` from the validator specifically and return `unknownConstraintOperatorResponse(...)` (already defined at `:4220-4227`).

- **V5.** **Authorization-header parse pre-check returns 401 even when the body's token is fine.**
  - **Spec:** §5.12 — the introspected token lives in the body. Authorization is for the *resource server's* identity (optional, server-policy).
  - **Impl:** `:696-704` — when no shared secret is configured, the impl tries to parse any `Bearer …` header and 401s on parse failure. A resource server forwarding its own client's Authorization header (common pattern) plus `{token: <agent_jwt>}` in the body sees 401 for unrelated reasons. The comment at `:693-695` already acknowledges the parse is "unrelated to resource-server auth".
  - **Why violation:** Conflates two distinct credentials and makes valid introspections fail because of irrelevant header content.
  - **Suggested fix:** Delete `:696-704`. Caller auth is the rate-limit + shared-secret block above; introspection only depends on the body's `token`.

## Action plan (prioritized)

| # | Pri | Title | Endpoint | § | Impl ref | Fix sketch |
|---|-----|-------|----------|---|----------|------------|
| 1 | P1 | Move agent-status check before signature so stale-clock tokens don't burn `jti` | execute | §4.5 step 6 vs. 7-8 | `:2337-2393` | Hoist lifecycle-clock + agent-status (`:2356-2393`) above the signature verify (`:2337-2344`); keep replay last. Mirrors `AgentJwtVerifier:165-178`. |
| 2 | P1 | Stop swallowing `unknown_constraint_operator` as `active:false` | introspect | §2.13/§5.12 | `:1006-1018, :1032-1034` | Catch `IllegalArgumentException` from `ConstraintValidator#validate` and return `unknownConstraintOperatorResponse(...)` (`:4220-4227`). |
| 3 | P1 | Drop the Authorization-header parse pre-check that 401s on irrelevant bearer tokens | introspect | §5.12 | `:696-704` | Delete the block. Caller auth = rate-limit + shared-secret (`:662-691`). |
| 4 | P2 | Migrate execute and introspect to `AgentJwtVerifier` so they inherit the JWKS-rotation iss tolerance and uniform check ordering | both | §4.5 | `:2312-2316, :841-845` (existing TODOs) | Refactor as flagged; per-endpoint reshaping of grant resolution + constraint extension required. |
| 5 | P3 | Document or drop the `name` alias for `capability` | execute | §5.11 | `:2395-2405` | README sentence or remove alias. |
| 6 | P3 | Document the introspect-side multi-grant aud admission and the `extensions.constraint_check` envelope | introspect | §5.12 | `:807-833, :1020-1022` | README sentence under introspect contract. |

## Methodology notes

**Spec subsections fetched:** §1.4, §2.13, §2.15, §4.3, §4.4, §4.5, §4.6, §5.11, §5.12, §5.13, §5.14.

**Files read in full:** `AgentAuthRealmResourceProvider.java` (focused on `:107-135`, `:642-1035`, `:2230-2658`, `:3826-3904`, `:4220-4344`); `AgentJwtVerifier.java`; `AgentJwtException.java`; `ConstraintValidator.java`; `ConstraintViolation.java`; `LifecycleClock.java`; `JwksCache.java`; `storage/jpa/AgentEntity.java`; `storage/jpa/AgentGrantEntity.java`; `README.md`.

**Verification gaps:**
- `AgentJwtVerifier` is the desired centralised pipeline but is currently catalog-only; execute/introspect open-code. Migration is action-plan item 4.
- §5.11 streaming MUSTs (the SSE `done` event, periodic revocation re-check on long-lived streams) are upstream concerns under the gateway pass-through model (D2). The gateway is transparent; the resource server owns these.
- §5.11 async polling at execute (the `status_url` MUST verify the same agent on each poll) has no in-gateway equivalent — there is no per-execution status URL synthesized by Keycloak. Out of scope under the gateway pass-through model.
