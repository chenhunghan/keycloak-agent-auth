# AAP v1.0-draft Audit — Browser Approval Flow

> **Source of truth:** https://agent-auth-protocol.com/specification/v1.0-draft
> **Audited:** 2026-04-28
> **Scope:** `/verify` (page + form), `/verify/approve`, `/verify/deny`, `/inbox`

Per §7.2: *"approve, deny, list pending requests is an implementation concern … these are not protocol endpoints."* The MUSTs that still bind these endpoints: §5.13 error envelope, §2.3/§3.3 state transitions, §8.11 (linked from §7) freshness + proof-of-presence. The GET surface is additionally bound by §7.1's `verification_uri` + `user_code` shape.

## Endpoints in scope

| Method | Path | Spec § | Impl |
|--------|------|--------|------|
| GET  | `/realms/{realm}/agent-auth/verify` | §7.1 | `AgentAuthRealmResourceProvider.java:2737-2884` |
| POST | `/realms/{realm}/agent-auth/verify` | impl-defined | `AgentAuthRealmResourceProvider.java:2989-3067` |
| POST | `/realms/{realm}/agent-auth/verify/approve` | impl-defined; §2.3/§3.3/§5.13/§8.11 | `:3074-3080` → `transitionPendingAgent:3095-3396` |
| POST | `/realms/{realm}/agent-auth/verify/deny` | impl-defined; §2.3/§3.3/§5.13/§8.11 | `:3087-3093` → `transitionPendingAgent:3095-3396` |
| GET  | `/realms/{realm}/agent-auth/inbox` | impl-defined (§7.2) | `:3514-3554` |

## Per-endpoint findings

### GET /verify

**Impl:** `AgentAuthRealmResourceProvider.java:2737-2884`. Inline-HTML page accepting `user_code` (device-flow) or `agent_id` (CIBA email deep-link extension). Bounces unauthenticated browsers through `/protocol/openid-connect/auth?max_age=300`.

| # | Spec requirement | § | Evidence | Verdict |
|---|---|---|---|---|
| 1 | `verification_uri` resolves to the rendered page | §7 approval-object | `buildDeviceAuthApprovalObject:4018-4034` → `issuerUrl()+"/verify"` | CONFORMANT |
| 2 | `user_code` matches a pending agent | §7.1 step 3 | `findAgentByUserCode(normalizeUserCode(uc))` at `:2757,3143` | CONFORMANT |
| 3 | Display-text safety on `name/reason/host_name/binding_message` (strip ctrl, cap length, escape, no markdown) | §8.11 | `sanitizeForDisplay:3580-3610` → `htmlEscape:3565-3571`; called from `:3618-3655, :3664-3707` | CONFORMANT |
| 4 | Render requested capabilities for approver review | §8.11 | `appendPendingGrants:3664-3707`, `appendApprovalContext:3618-3655` | CONFORMANT |
| 5 | Fresh-auth required (cookie alone insufficient) | §8.11 MUST | login bounce at `:2745-2747` with `max_age=approvalMaxAuthAgeSeconds()` (300s); POST gate `:3127-3135` via `isFreshAuth:3405-3429` | CONFORMANT |
| 6 | GET does not mutate state | §8.11 | GET only renders | CONFORMANT |

**D1 (documented).** `agent_id` query param accepted as CIBA email deep-link path (`:2749-2754`). README §"End user".
**U1 (undocumented).** Inline `StringBuilder` HTML, no FreeMarker template (`src/main/resources/` has no `*.ftl`). UI shape only.
**Violations:** none.

---

### POST /verify (form companion)

**Impl:** `AgentAuthRealmResourceProvider.java:2989-3067` (`verifyFormSubmit`). Form-encoded counterpart to JSON approve/deny. CSRF double-submit on cookie-style submissions, then funnels into `transitionPendingAgent`. Returns HTML.

| # | Requirement | § | Evidence | Verdict |
|---|---|---|---|---|
| 1 | Fresh-auth | §8.11 | inherits `transitionPendingAgent:3127-3135` | CONFORMANT |
| 2 | CSRF double-submit actually executed (README claim) | README | `:3018-3029` rejects with 403 unless form `csrf_token` == cookie `agent_auth_csrf` or bearer present; cookie at `:2877-2882` `HttpOnly; SameSite=Strict` | CONFORMANT |
| 3 | Service accounts blocked | §8.11 | `:3111-3115` → 403 `user_required` | CONFORMANT |
| 4 | 410 on terminal-state retries | §7.1 | `:3175-3181` → HTML 410 at `:3062-3065` | CONFORMANT |

**D2 (documented).** Bearer token required even with valid KC cookie (`:3098-3110`, `BearerTokenAuthenticator` only). README §"End user" calls this out explicitly.
**U2 (undocumented).** CSRF cookie path scoped to `/realms/{realm}/agent-auth/verify` (`:2956-2960`) — defense-in-depth.
**Violations:** none.

---

### POST /verify/approve

**Impl:** `:3074-3080` → `transitionPendingAgent:3095-3396`. Bearer-authenticated JSON. Blocks service-account tokens, enforces fresh `auth_time`, blocks write-capable approvals without proof-of-presence, then transitions agent + grants per §2.3/§3.3, links host (§2.9), populates host TOFU (§3.1).

| # | Requirement | § | Evidence | Verdict |
|---|---|---|---|---|
| 1 | `pending → active` (+ `activated_at`, `user_id`) | §2.3 | `:3273-3276` | CONFORMANT |
| 2 | Pending grants → `active`/`denied` per approver | §3.3, §3.3.1 | `:3284-3326`; `granted_by=userId`; restores `requested_constraints` | CONFORMANT |
| 3 | Stale approval (past `expires_in`) → 410 `approval_expired` | §7 (`expires_in` Required) | `:3187-3199` reads `approval.issued_at_ms`, default 600s | CONFORMANT |
| 4 | Terminal state → 410 `approval_terminal` | §7.1 | `:3175-3181` | CONFORMANT |
| 5 | Fresh-auth | §8.11 MUST | `:3127-3135`, `isFreshAuth:3405-3429` | CONFORMANT |
| 6 | Proof-of-presence for write-capable approvals | §8.11 MUST | `:3237-3266` checks `hasProofOfPresence` against `amr`/AMR note → 403 `webauthn_required` | CONFORMANT |
| 7 | Service accounts blocked | §8.11 | `:3111-3115` → 403 `user_required` | CONFORMANT |
| 8 | `{error, message}` envelope on every error | §5.13 | 401 (`:3107`), 403 (`:3113, :3131, :3151, :3261`), 404 (`:3168`), 409 (`:3206`), 410 (`:3178, :3194`) — all `Map.of("error", ..., "message", ...)` | CONFORMANT |
| 9 | `agent.user_id = approver` (single-user) | §3.3.1 | `:3275` | CONFORMANT |
| 10 | TOFU defaults populated on first approval | §3.1, §5.3 | `:3378-3387` | CONFORMANT |
| 11 | Missing `user_code` + `agent_id` → 400 `invalid_request` | §5.13 | `:3157-3166` | CONFORMANT |
| 12 | Unknown code → 404 `unknown_user_code` | §5.13 | `:3167-3172` | CONFORMANT |

**D3 (documented).** Entitlement gate flips a pending grant to `denied(insufficient_authority)` when the approver's org/role mapping doesn't entitle them (`:3290-3296`). README §"End user" + §"Multi-tenant scoping". Spec doesn't model org/role gates.
**D4 (documented).** Body's `capabilities` array narrows the active set; pending grants outside subset → `denied(user_denied)` (`:3318-3322`).
**D5 (documented).** `agent_id` accepted as alternative to `user_code` for CIBA email deep-link path; ownership cross-checked against `host.user_id` at `:3148-3156`. README.
**D6 (documented).** Test-mode escape hatch for fresh-auth (`agent-auth.test-mode=true` system property, only set by Testcontainers, `:3128`).
**U3 (undocumented).** `409 invalid_state` for non-pending agent with no pending grants (`:3204-3208`). Snake_case and machine-readable per §5.13, but not in the §5.13 common-codes list. Worth a README note.
**U4 (undocumented).** On register-flow denial `user_code` is preserved so retries resolve the rejected agent and return 410 (`:3344-3350`); capability-request denials clear it. Intentional per inline comment.
**Violations:** none.

---

### POST /verify/deny

**Spec:** §7.1 ("User denial is terminal for that attempt … client MUST NOT automatically retry"), §2.3 (`pending → rejected`), §3.3 grant denials.
**Impl:** `:3087-3093` → shares `transitionPendingAgent`.

#### Conformance matrix
| # | Spec requirement | Spec § | Impl evidence | Verdict |
|---|------------------|--------|---------------|---------|
| 1 | Agent → `rejected` (+ `rejection_reason=user_denied`) | §7.1, §2.3 | `:3329-3332` | CONFORMANT |
| 2 | Pending grants → `denied` | §3.3 | `:3333-3343`; drops `requested_constraints` | CONFORMANT |
| 3 | Subsequent approve on rejected agent → 410 (terminal) | §7.1 | `:3175-3181`. README claim verified by integration alignment commit `35bc0b0` | CONFORMANT |
| 4 | Capability-request denials don't transition the agent itself | §3.3 | `:3203, :3329` (the `if (!isCapabilityRequestApproval)` guard) | CONFORMANT |
| 5 | Same auth/fresh-auth/CSRF/error-envelope rules as approve | §8.11/§5.13 | shared body | CONFORMANT |

#### Undocumented intentional deviations
- **U5.** Same as U4 — register-flow vs capability-request denials handle `user_code` retention asymmetrically. Worth one README sentence.

#### Violations
- *(none)*

---

### GET /inbox

*Extension. §7.2: "list pending requests" is an implementation concern, not a protocol endpoint.*

**Impl:** `AgentAuthRealmResourceProvider.java:3514-3554`
**Summary:** Authenticated realm user lists pending approvals across all hosts linked to them. In-realm fallback when SMTP isn't configured.

#### Conformance matrix
| # | Spec requirement | Spec § | Impl evidence | Verdict |
|---|------------------|--------|---------------|---------|
| 1 | Endpoint MUST NOT relax §2.3/§3.3 gates | §2.3, §3.3 | `:3546` only filters by `pending`; never approves | CONFORMANT |
| 2 | Caller scoping: only show approvals for hosts linked to *this* user | §3.3.1 | `:3536-3552` `findHostsByUser(userId)` | CONFORMANT |
| 3 | Service accounts blocked | §8.11 | `:3530-3534` → 403 `user_required` | CONFORMANT |
| 4 | `{error, message}` envelope on errors | §5.13 | 401 (`:3522`), 403 (`:3531`) | CONFORMANT |
| 5 | Sanitises pending-grant payload (no `requested_constraints` leak) | §5.3/§5.4 wire shape | `:3549` `sanitizeAgentResponse` | CONFORMANT |

#### Undocumented intentional deviations
- **U6.** No pagination, no rate-limit, no `pending_approvals` cap. Users linked to many hosts get the entire list in one shot. Spec is silent (impl concern).

#### Violations
- *(none)*

---

## Cross-cutting: state transitions on approve/deny

| Source | Trigger | Target | Spec § | Impl |
|--------|---------|--------|--------|------|
| Agent `pending` | approve | `active` (+ `activated_at`, `user_id`) | §2.3 | `:3273-3276` |
| Agent `pending` | deny | `rejected` (+ `rejection_reason=user_denied`) | §2.3, §7.1 | `:3329-3332` |
| Agent `active`, grants `pending` | approve subset | grant `pending` → `active` (in subset, entitlement OK) / `denied(insufficient_authority)` (entitlement fail) / `denied(user_denied)` (outside subset) | §3.3, §3.3.1 | `:3284-3326` |
| Agent `active`, grants `pending` | deny | grant `pending` → `denied` | §3.3 | `:3333-3343` |
| Agent `rejected/revoked/claimed` | approve | 410 `approval_terminal` | §7.1 (no retry) | `:3175-3181` |
| Approval older than `expires_in` | any | 410 `approval_expired` | §7 | `:3187-3199` |
| First approval (host unlinked) | approve | host `pending → active`, `user_id` set, TOFU `default_capabilities` populated | §2.8/§2.9/§2.11/§3.1 | `:3366-3392` |

Single-user core (§3.3.1) preserved: `agent.user_id` set once on first approval; capability-request approvals use the approver's entitlement snapshot but record per-grant `granted_by` for audit.

## Action plan (prioritized)

| # | Priority | Title | Endpoint | Spec § | Impl ref | Fix sketch |
|---|----------|-------|----------|--------|----------|------------|
| 1 | low | Document `409 invalid_state` error code in README | approve/deny | §5.13 | `:3204-3208` | One row in README error table or docs/architecture.md |
| 2 | low | Document the `agent_id` body alternative in the approve/deny rows | approve/deny | §7.2 (impl) | `:3144-3156` | One README sentence: "CIBA path: pass `agent_id` instead of `user_code`; ownership checked against `host.user_id`" |
| 3 | low | Document register-vs-capability-request asymmetry on `user_code` retention after deny | deny | §7.1 wording is register-only | `:3344-3350` | One README clause distinguishing register flow (preserves code → 410 on retry) from capability-request denials (clears code) |
| 4 | low | Pagination/cap on `/inbox` for users linked to many hosts | `/inbox` | not spec | `:3537-3553` | Accept `?limit=&cursor=`; default cap 100 |

> No SPEC VIOLATIONs found in the browser approval flow as of this audit.

## Methodology notes

- Spec source: `https://agent-auth-protocol.com/specification/v1.0-draft`. The Next.js page truncates above ~512KB, so WebFetch summarisation cut off above §5.13. Worked around by `curl -sL > /tmp/aap-spec.html` and grep-ing the rendered HTML directly: §7 at lines 1464-1520, §8.11 at 1581-1604, §5.13 at 1116-1135.
- Implementation read in full: `AgentAuthRealmResourceProvider.java:2730-3554` (verify GET + POST + JSON approve/deny + inbox), `:3580-3707` (display sanitisation, `appendApprovalContext`, `appendPendingGrants`), `:3912-4055` (approval-object builders, user-code generation/normalisation, expiry config), `notify/CibaEmailNotifier.java` (the §7.2 push channel), `storage/jpa/AgentGrantEntity.java` (the secondary grant index).
- Audit framing relies on §7.2's literal: *"approve, deny, list pending requests is an implementation concern … these are not protocol endpoints."* Anything outside §2.3/§3.3 transitions, §5.13 envelope, and §8.11 security MUSTs is treated as deviation, not violation.
- Verified the README's two load-bearing claims: (a) `POST /verify` requires a bearer token even with KEYCLOAK_IDENTITY present (`:3098-3110` — `BearerTokenAuthenticator` only; no cookie fallback in `transitionPendingAgent`); (b) entitlement-gate denial reason is `insufficient_authority` not `user_denied` (`:3290-3296`).
- HTML rendering uses inline `StringBuilder`. No FreeMarker templates exist under `src/main/resources/`. Display strings flow through `sanitizeForDisplay` then `htmlEscape`. No agent-id, user-id, or token leakage observed on the GET page.
