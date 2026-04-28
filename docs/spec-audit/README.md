# AAP v1.0-draft Audit — Index & Cross-Group Action Plan

> **Source of truth:** https://agent-auth-protocol.com/specification/v1.0-draft
> **Audited:** 2026-04-28
> **Method:** Five parallel sub-agents, each owning an endpoint group, comparing impl behavior against the published spec only. Neither the README, the implementation, nor integration tests were treated as authoritative.

## Reports

| Group | Report | Endpoints | Findings |
|-------|--------|-----------|----------|
| Discovery + catalog | [discovery-catalog.md](./discovery-catalog.md) | 4 | 0 P0 · 1 P1 · 2 P2 |
| Agent + host lifecycle | [agent-host-lifecycle.md](./agent-host-lifecycle.md) | 9 | 3 P0 · 2 P1 · 6 P2 |
| Execution + introspection | [execution-introspection.md](./execution-introspection.md) | 2 | 0 P0 · 3 P1 · 1 P2 · 2 P3 |
| Browser approval flow | [approval-browser.md](./approval-browser.md) | 5 | 0 violations · 4 doc nits |
| Realm + org admin | [admin-org.md](./admin-org.md) | ~22 | 0 P0 · 0 P1 · 1 P2 · 1 P3 |
| **Total** | — | **~42** | **3 P0 · 6 P1 · 10 P2 · 7 P3** |

## Finding classification

Each sub-agent classified every finding into one of four buckets:

- **CONFORMANT** — impl matches spec; no action.
- **INTENDED DEVIATION (documented)** — README/CLAUDE.md/javadoc explicitly documents the deviation as an extension, profile, or relaxation. Out of the action plan.
- **INTENDED DEVIATION (undocumented)** — code-level intent is visible but not user-facing-documented; usually a doc gap. Lands in the action plan as P2/P3.
- **SPEC VIOLATION** — clearly contradicts a spec MUST/SHOULD with no reasonable rationale. Lands in the action plan as P0/P1.

## Master action plan (priority-ordered)

`P0` = MUST violation in core flow · `P1` = SHOULD violation or MUST in edge case · `P2` = nit / future-proofing / undocumented intentional · `P3` = docs only.

### P0 — fix first (3 items)

These are clear MUST violations on the security-critical path. Land each as its own commit.

| # | Title | Endpoint | Spec § | Impl ref | Source report |
|---|-------|----------|--------|----------|---------------|
| 1 | Reject self-rotation that re-uses the current key | `POST /agent/rotate-key`, `POST /host/rotate-key` | §5.8, §5.9 | `AgentAuthRealmResourceProvider.java:1244-1246, :1624-1635` | [agent-host-lifecycle](./agent-host-lifecycle.md) |
| 2 | Re-run entitlement gate on reactivation grants | `POST /agent/reactivate` | §5.6, §2.5 | `AgentAuthRealmResourceProvider.java:1443-1444, :4147-4201` | [agent-host-lifecycle](./agent-host-lifecycle.md) |
| 3 | Reject `auto_deny` caps at request time instead of stamping a denied grant | `POST /agent/register` | §5.3, §3.3 | `AgentAuthRealmResourceProvider.java:425-441, :503-506` | [agent-host-lifecycle](./agent-host-lifecycle.md) |

### P1 — fix soon (6 items)

| # | Title | Endpoint | Spec § | Impl ref | Source report |
|---|-------|----------|--------|----------|---------------|
| 4 | Move agent-status check before signature verify so stale-clock tokens don't burn `jti` | `POST /capability/execute` | §4.5 (steps 6 vs. 7-8) | `AgentAuthRealmResourceProvider.java:2337-2393` | [execution-introspection](./execution-introspection.md) |
| 5 | Stop swallowing `unknown_constraint_operator` as `active:false` | `POST /agent/introspect` | §2.13, §5.12 | `AgentAuthRealmResourceProvider.java:1006-1018, :1032-1034` | [execution-introspection](./execution-introspection.md) |
| 6 | Drop Authorization-header parse pre-check that 401s on irrelevant bearer tokens | `POST /agent/introspect` | §5.12 | `AgentAuthRealmResourceProvider.java:696-704` | [execution-introspection](./execution-introspection.md) |
| 7 | Stop returning 401 from `/capability/list` when public caps yield zero rows | `GET /capability/list` | §5.2 ("Servers that support unauthenticated listing MUST NOT 401") | `AgentAuthRealmResourceProvider.java:1770-1777` | [discovery-catalog](./discovery-catalog.md) |
| 8 | Project agent-response fields to the §3.2 protocol set (drop `agent_key_thumbprint`, `*_reset_at`, `absolute_lifetime_elapsed`, `user_code`, `agent_kid`, `approval.issued_at_ms`) | register / status / reactivate | §3.2, §5.3, §5.5, §5.6 | `sanitizeAgentResponse :3735-3776` | [agent-host-lifecycle](./agent-host-lifecycle.md) |
| 9 | Distinguish entitlement-denied from unknown caps in `request-capability` 400 body | `POST /agent/request-capability` | §5.4, §5.13 | `AgentAuthRealmResourceProvider.java:2076-2085, :2156-2161` | [agent-host-lifecycle](./agent-host-lifecycle.md) |

### P2 — nice to have (10 items)

| # | Title | Endpoint | Spec § | Impl ref | Source report |
|---|-------|----------|--------|----------|---------------|
| 10 | Project `/capability/describe` response to §2.12 fields (or document extras) | `GET /capability/describe` | §2.12, §5.2.1 | `AgentAuthRealmResourceProvider.java:1954` | [discovery-catalog](./discovery-catalog.md) |
| 11 | Replace `/health` string-literal JSON with `Map.of` | `GET /health` | n/a (extension) | `AgentAuthRealmResourceProvider.java:146` | [discovery-catalog](./discovery-catalog.md) |
| 12 | Document SA-host blocks `mode=delegated` | `POST /agent/register` | §2.8 | `:521-528` | [agent-host-lifecycle](./agent-host-lifecycle.md) |
| 13 | Document or guard JWKS-served agents calling `rotate-key` | `POST /agent/rotate-key` | §5.8 | `:1244` | [agent-host-lifecycle](./agent-host-lifecycle.md) |
| 14 | Document/guard JWKS-served hosts calling `host/rotate-key` | `POST /host/rotate-key` | §5.9 | `:1546-1646` | [agent-host-lifecycle](./agent-host-lifecycle.md) |
| 15 | Document `409 already_granted` and partial existing-grant echo | `POST /agent/request-capability` | §5.4 | `:2104-2106, :2163-2168` | [agent-host-lifecycle](./agent-host-lifecycle.md) |
| 16 | Add `Cache-Control: no-store` to per-grant status response | `GET /agent/{id}/capabilities/{name}/status` | (extension) | `:2715` | [agent-host-lifecycle](./agent-host-lifecycle.md) |
| 17 | Document or rebuild reactivation grants from live host defaults instead of snapshot | `POST /agent/reactivate` | §5.6 | `:4147-4201` | [agent-host-lifecycle](./agent-host-lifecycle.md) |
| 18 | Migrate execute and introspect to `AgentJwtVerifier` for uniform check ordering | `POST /capability/execute`, `POST /agent/introspect` | §4.5 | `:2312-2316, :841-845` | [execution-introspection](./execution-introspection.md) |
| 19 | Stamp `denied_by` on admin-denied / reject-cascade grants | `agents/{id}/capabilities/{cap}/approve` (auto-deny branch), `agents/{id}/reject` | §3.3 | `AgentAuthAdminResourceProvider.java:500-510, :386-394` | [admin-org](./admin-org.md) |

### P3 — docs / observability only (7 items)

| # | Title | Endpoint | Spec § | Impl ref | Source report |
|---|-------|----------|--------|----------|---------------|
| 20 | Document or drop the `name` alias for `capability` field | `POST /capability/execute` | §5.11 | `:2395-2405` | [execution-introspection](./execution-introspection.md) |
| 21 | Document introspect-side multi-grant aud admission and `extensions.constraint_check` envelope | `POST /agent/introspect` | §5.12 | `:807-833, :1020-1022` | [execution-introspection](./execution-introspection.md) |
| 22 | Document `409 invalid_state` error code in error-format docs | approve/deny | §5.13 | `:3204-3208` | [approval-browser](./approval-browser.md) |
| 23 | Document the `agent_id` body alternative on approve/deny rows | approve/deny | §7.2 (impl) | `:3144-3156` | [approval-browser](./approval-browser.md) |
| 24 | Document register-vs-capability-request asymmetry on `user_code` retention after deny | deny | §7.1 (register-only wording) | `:3344-3350` | [approval-browser](./approval-browser.md) |
| 25 | Pagination/cap on `/inbox` for users linked to many hosts | `GET /inbox` | (extension) | `:3537-3553` | [approval-browser](./approval-browser.md) |
| 26 | Document or implement host activation on link | `POST /hosts/{id}/link` | §2.11, §3.1 | `AgentAuthAdminResourceProvider.java:889-892` | [admin-org](./admin-org.md) |

## Suggested sequencing

1. **PR 1 — P0 burn-down.** Three commits, one per item: rotate-key key-equality check, reactivation entitlement gate, register-time `auto_deny` rejection. Each is small and independently testable.
2. **PR 2 — Verifier & catalog hardening.** P1 items 4-7 (verify-order, constraint-operator surfacing, header pre-check, list 401). All touch the JWT/catalog pipeline; one PR keeps the diff coherent.
3. **PR 3 — Wire-shape projections.** P1 item 8 (`sanitizeAgentResponse` projection) and P2 item 10 (`describe` projection). Both are "stop leaking internal fields" of the same flavor; treat as a single hygiene pass.
4. **PR 4 — Lifecycle & error-shape polish.** P1 item 9, P2 items 12-19. Mostly admin/lifecycle nits; group by file.
5. **PR 5 — Docs sweep.** All P3 items, plus README updates referenced inline by P2 docs items.

## Excluded from action plan (intentional, documented deviations)

These were classified as **INTENDED DEVIATION (documented)** and are NOT regressions:

- **Gateway-mode `aud` accept** — agent JWT with `aud=capability.location` accepted at `/capability/execute`, then proxied. Documented at README:138 as an extension profile. Operators wanting strict spec disable gateway mode.
- **Capability-name regex relaxation** — admin accepts `[a-zA-Z0-9_]+` instead of §2.14's SHOULD lowercase snake_case. Documented at README:180.
- **JWKS HTTPS strictness** — JWKS fetches require HTTPS except for localhost / container-test hostnames. Stricter than spec. Documented at README:236.
- **No `jwks_uri` in discovery** — server doesn't sign protocol responses; discovery omits the key. Documented at README:240.
- **`default_location` published in discovery, locationless caps rejected at admin time** — discovery surface conforms to §5.1 / §2.15; admin tightens it. Documented at README:182.
- **Agent-environments self-serve provisioning** — extension layered on top of §2.8 host establishment. Documented at README:123.
- **Pending-host orphan sweep** — extension to §7.1 device-flow garbage collection. Documented at README:110.
- **In-realm `/inbox`** — fallback for §7.2 CIBA when SMTP isn't configured. Documented at README:90.
- **Browser approval bearer-token requirement** — `POST /verify`, `verify/approve`, `verify/deny` require a bearer access token; the realm cookie alone isn't sufficient. Documented at README:82.

## Methodology notes

- Each sub-agent fetched the spec via WebFetch using anchor URLs (e.g. `…/v1.0-draft#53-agent-registration`). The published page is large (~512KB rendered); the browser-flow auditor worked around WebFetch summarisation by `curl`-ing the rendered HTML and grep-ing directly.
- Every finding cites a `file:line` (or `file:line-line`) and a spec `§X.Y`.
- README's documented deviations were honored — no documented intentional deviation was re-flagged as a violation.
- Two of the five reports note that they did not run the test suite during the audit; impl behavior was verified by static reading. Where ITs cross-check the auditor's claim (e.g. `AgentAuthDiscoveryIT` Cache-Control assertions), the auditor cites them.
