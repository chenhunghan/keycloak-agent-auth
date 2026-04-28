# AAP v1.0-draft Audit — Discovery & Capability Catalog

> **Source of truth:** https://agent-auth-protocol.com/specification/v1.0-draft
> **Audited:** 2026-04-28
> **Scope:** discovery, liveness, capability list, capability describe

## Endpoints in scope

| Method | Path | Spec § | Impl |
|--------|------|--------|------|
| GET | `/realms/{realm}/.well-known/agent-configuration` | §5.1, §5.1.1 | `AgentAuthWellKnownProvider.java:18-50` + `AgentAuthDiscoveryCacheFilter.java:22-29` |
| GET | `/realms/{realm}/agent-auth/health` | (extension — no spec) | `AgentAuthRealmResourceProvider.java:142-147` |
| GET | `/realms/{realm}/agent-auth/capability/list` | §5.2 | `AgentAuthRealmResourceProvider.java:1655-1848` |
| GET | `/realms/{realm}/agent-auth/capability/describe` | §5.2.1 | `AgentAuthRealmResourceProvider.java:1850-1963` |

## Per-endpoint findings

### GET /.well-known/agent-configuration

**Spec:** §5.1, §5.1.1
**Impl:** `AgentAuthWellKnownProvider.java:18-50`, `AgentAuthDiscoveryCacheFilter.java:22-29`
**Summary:** 12 conformant • 1 documented deviation • 0 undocumented • 0 violations

#### Conformance matrix

| # | Spec requirement | Spec § | Impl evidence | Verdict |
|---|------------------|--------|---------------|---------|
| 1 | MUST publish at `GET /.well-known/agent-configuration` | §5.1 | `AgentAuthWellKnownProviderFactory.java:11` (`PROVIDER_ID="agent-configuration"`) wired via Keycloak `WellKnownProvider` SPI | CONFORMANT |
| 2 | Required `version` (string) | §5.1, §5.1.1 | `AgentAuthWellKnownProvider.java:25` (`"1.0-draft"`) | CONFORMANT |
| 3 | Required `provider_name` (string) | §5.1 | `AgentAuthWellKnownProvider.java:26` | CONFORMANT |
| 4 | Required `description` (string) | §5.1 | `AgentAuthWellKnownProvider.java:27` | CONFORMANT |
| 5 | Required `issuer` (string, base URL) | §5.1 | `AgentAuthWellKnownProvider.java:21-22, 28` (realm `agent-auth` base) | CONFORMANT |
| 6 | Required `algorithms[]` containing `"Ed25519"` | §5.1 | `AgentAuthWellKnownProvider.java:29` | CONFORMANT |
| 7 | Required `modes[]` ⊆ {`delegated`,`autonomous`} | §5.1 | `AgentAuthWellKnownProvider.java:30` | CONFORMANT |
| 8 | Required `approval_methods[]` | §5.1 | `AgentAuthWellKnownProvider.java:31` (`device_authorization, ciba, admin`; `admin` permitted as profile extension per §1.4 / §10.10.3) | CONFORMANT |
| 9 | Required `endpoints` object with relative paths | §5.1 | `AgentAuthWellKnownProvider.java:33-46` — paths match the §5.1 example verbatim | CONFORMANT |
| 10 | Optional `default_location` | §5.1, §2.15 | `AgentAuthWellKnownProvider.java:48` | CONFORMANT |
| 11 | SHOULD `Cache-Control` header, `max-age=3600` RECOMMENDED | §5.1 | `AgentAuthDiscoveryCacheFilter.java:27` (`max-age=3600, public`) | CONFORMANT |
| 12 | SHOULD ignore unrecognized fields (forward compat) | §5.1.1 | N/A — server-side emit only | CONFORMANT |

#### Documented intentional deviations
- **D1.** No `jwks_uri` in the discovery payload. README.md:240 explicitly states "this extension does not sign protocol responses, so discovery does not publish a server `jwks_uri`." `jwks_uri` is optional in §5.1, so omission is conformant; the README turns it from "absent optional" into a declared posture.

#### Undocumented intentional deviations (likely doc gap)
- *(none)*

#### Violations (action required)
- *(none)*

---

### GET /capability/list

**Spec:** §5.2
**Impl:** `AgentAuthRealmResourceProvider.java:1655-1848`
**Summary:** 12 conformant • 1 documented deviation • 0 undocumented • 1 violation

#### Conformance matrix

| # | Spec requirement | Spec § | Impl evidence | Verdict |
|---|------------------|--------|---------------|---------|
| 1 | Three auth modes: anon / host JWT / agent JWT | §5.2 | `AgentAuthRealmResourceProvider.java:1674-1728` | CONFORMANT |
| 2 | Optional `query`, `cursor`, `limit` query params | §5.2 | `AgentAuthRealmResourceProvider.java:1659-1662` | CONFORMANT |
| 3 | Server supporting unauth listing MUST NOT return 401 | §5.2 | `AgentAuthRealmResourceProvider.java:1770-1777` returns 401 when `!isAuthenticated && visibleCapabilities.isEmpty()` | SPEC VIOLATION (V1) |
| 4 | Response `capabilities[]` with `name`, `description` | §5.2 | `AgentAuthRealmResourceProvider.java:1828-1837` | CONFORMANT |
| 5 | Authenticated agent MUST get `grant_status` on every cap | §5.2 | `AgentAuthRealmResourceProvider.java:1833-1834` | CONFORMANT |
| 6 | Optional pagination via `next_cursor` / `has_more` | §5.2 | `AgentAuthRealmResourceProvider.java:1822-1826, 1840-1842` (opaque base64 cursor) | CONFORMANT |
| 7 | Bad cursor → `400 invalid_request` | §5.13 | `AgentAuthRealmResourceProvider.java:1796-1807` | CONFORMANT |
| 8 | Bad limit → `400 invalid_request` | §5.13 | `AgentAuthRealmResourceProvider.java:1810-1814` | CONFORMANT |
| 9 | Error envelope `{error, message}` snake_case | §5.13 | All error returns use this shape | CONFORMANT |
| 10 | Catalog responses cacheable (private/public) | §10.6 | `AgentAuthRealmResourceProvider.java:1843-1847` | CONFORMANT |
| 11 | Malformed/unsupported-typ Bearer → `401 invalid_jwt` | §5.13 / §4.5 | `AgentAuthRealmResourceProvider.java:1675-1682` | CONFORMANT |
| 12 | `WWW-Authenticate: AgentAuth discovery="…"` on 401 | §5.14 | `AgentAuthRealmResourceProvider.java:1771-1773` | CONFORMANT |
| 13 | Verified host JWT for non-active host MUST NOT silently downgrade | §4.5.1 | `AgentAuthRealmResourceProvider.java:1693-1713` | CONFORMANT |

#### Documented intentional deviations
- **D1.** `query` matches `name`, `description`, **and `location`** (`AgentAuthRealmResourceProvider.java:1782-1788`). §5.2 says matching is "implementation-defined", so this is permitted; not user-visibly documented but inside §5.2's explicit latitude.

#### Undocumented intentional deviations (likely doc gap)
- *(none — see V1 below for the only outstanding behaviour issue.)*

#### Violations (action required)
- **V1.** *401 from list when public caps yield zero rows contradicts §5.2 MUST NOT*
  - **Spec:** §5.2 — "Servers that support unauthenticated capability listing MUST NOT return `401` — they return public capabilities or an empty list instead."
  - **Impl:** `AgentAuthRealmResourceProvider.java:1770-1777` returns `401 authentication_required` when `!isAuthenticated && visibleCapabilities.isEmpty()`.
  - **Why violation:** the same realm both *supports* unauth listing (a realm with public caps would respond 200) and refuses it depending on data shape. That's exactly the conditional 401 the MUST NOT proscribes — a client gets either 200 or 401 from one endpoint depending on whether the realm happens to have public caps. Spec's intended fallback is 200 + empty list.
  - **Suggested fix:** drop the 401 branch. Return `200 {"capabilities":[], "has_more":false, "next_cursor":null}` for unauthenticated callers when no public caps are visible. If the operator wants a discoverability hint, attach `WWW-Authenticate: AgentAuth discovery="…"` to the 200 response (informational) or expose an explicit "anonymous catalog disabled" discovery flag.

---

### GET /capability/describe

**Spec:** §5.2.1
**Impl:** `AgentAuthRealmResourceProvider.java:1850-1963`
**Summary:** 10 conformant • 0 documented deviations • 1 undocumented • 0 violations

#### Conformance matrix

| # | Spec requirement | Spec § | Impl evidence | Verdict |
|---|------------------|--------|---------------|---------|
| 1 | `name` query param required | §5.2.1 | `AgentAuthRealmResourceProvider.java:1856-1862` (400 invalid_request if missing/blank) | CONFORMANT |
| 2 | Unknown name → `404 capability_not_found` | §5.2.1 | `AgentAuthRealmResourceProvider.java:1864-1868` | CONFORMANT |
| 3 | Same three auth modes as `/list` | §5.2.1 | `AgentAuthRealmResourceProvider.java:1880-1930` | CONFORMANT |
| 4 | Response includes `name`, `description`, `input?`, `output?` | §5.2.1, §2.12 | `AgentAuthRealmResourceProvider.java:1954` (`new HashMap<>(cap)` echoes registry record) | CONFORMANT |
| 5 | Agent-authenticated caller MUST get `grant_status` | §5.2 | `AgentAuthRealmResourceProvider.java:1955-1957` | CONFORMANT |
| 6 | Missing `input` treated as empty schema | §5.2.1 | Describe wire echo simply omits `input`; downstream callers see no key → empty-schema semantics; cf. `AgentAuthRealmResourceProvider.java:4187-4189` | CONFORMANT |
| 7 | Existence-leak avoidance: non-public caps invisible to anon | §5.2 (auth model) | `AgentAuthRealmResourceProvider.java:1932-1939` (404, not 401/403) | CONFORMANT |
| 8 | Org/role-gated caps respond 404 to caller without entitlement | §5.2 | `AgentAuthRealmResourceProvider.java:1944-1952` | CONFORMANT |
| 9 | Cache-Control on the response | §10.6 | `AgentAuthRealmResourceProvider.java:1959-1962` | CONFORMANT |
| 10 | Error envelope conforms to §5.13 | §5.13 | All error returns use `{error, message}` | CONFORMANT |

#### Documented intentional deviations
- *(none)*

#### Undocumented intentional deviations (likely doc gap)
- **U1.** Describe response echoes the **entire registry record** via `new HashMap<>(cap)` (`AgentAuthRealmResourceProvider.java:1954`), which leaks impl-internal fields not defined in §2.12: `visibility`, `requires_approval`, `organization_id`, `required_role`, `created_by` (and any other admin metadata). §2.12 lists only `name`, `description`, `location`, `input`, `output`, `grant_status`. `location` is meaningful for direct-mode dispatch and is borderline-spec; the visibility / role / org fields are server-private RBAC scheme that an authenticated cross-org caller currently cannot see (gate at line 1944-1952 hides them) but a same-org authenticated caller does. Either (a) declare the extra fields as part of this implementation's profile in README.md, or (b) project the response to spec-defined fields plus a documented extension envelope (e.g. `x_keycloak_agent_auth`).

#### Violations (action required)
- *(none)*

---

### GET /agent-auth/health

**No spec equivalent — extension.**
**Impl:** `AgentAuthRealmResourceProvider.java:142-147`

```
Response.ok("{\"status\":\"ok\",\"provider\":\"agent-auth\"}").build()
```

- Returns a static literal — no realm state, no DB read, no auth required. Cannot leak.
- README.md:50-51 documents it ("Liveness probe; confirms the extension is loaded").
- Nit: the body is a hand-rolled JSON literal rather than a `Map.of` serialised through `JsonSerialization`; functionally equivalent, inconsistent with every other endpoint. Listed P2 in the action plan.

## Action plan (prioritized)

P0 = clear MUST violation in core flow • P1 = SHOULD violation or MUST in edge case • P2 = nit / future-proofing

| # | Priority | Title | Endpoint | Spec § | Impl ref | Fix sketch |
|---|----------|-------|----------|--------|----------|------------|
| 1 | P1 | Stop returning 401 from `/capability/list` when public caps yield zero rows | `/capability/list` | §5.2 | `AgentAuthRealmResourceProvider.java:1770-1777` | Replace the 401 branch with `Response.ok(emptyListBody())`. Either drop `WWW-Authenticate` or attach it to the 200 as an informational challenge. Update `AgentAuthDiscoveryIT` / catalog ITs. |
| 2 | P2 | Project `/capability/describe` response to spec fields (or document extras) | `/capability/describe` | §2.12, §5.2.1 | `AgentAuthRealmResourceProvider.java:1954` | Build the response map explicitly from `name`, `description`, `input`, `output`, `location` (+ `grant_status` when agent-auth'd); drop `visibility`, `requires_approval`, `organization_id`, `required_role`, `created_by`. Or keep echo + add a README "Discovery & catalog response shape" subsection declaring the extension fields. |
| 3 | P2 | Replace `/health` string-literal JSON with `Map.of` for consistency | `/health` | n/a (extension) | `AgentAuthRealmResourceProvider.java:146` | `return Response.ok(Map.of("status","ok","provider","agent-auth")).build();` |

## Methodology notes
- **Spec subsections fetched:** §1.4, §2.12, §2.14, §2.15, §4.5, §5.1, §5.1.1, §5.2, §5.2.1, §5.13, §5.14.
- **Files read:** `AgentAuthWellKnownProvider.java` (full), `AgentAuthWellKnownProviderFactory.java` (full), `AgentAuthDiscoveryCacheFilter.java` (full), `AgentAuthRealmResourceProvider.java:90-147,1640-1963,2962-2972,3906-3910,4078-4111`, `META-INF/services/org.keycloak.wellknown.WellKnownProviderFactory`, `AgentAuthDiscoveryIT.java` (cross-check on Cache-Control & version assertions), README.md in full.
- **Verification gaps:** I verified `AgentAuthDiscoveryCacheFilter` is auto-registered by Keycloak's RESTEasy via the `@Provider` annotation by confirming `AgentAuthDiscoveryIT` asserts `Cache-Control` containing `max-age=3600`. I did not run the suite during this audit. The `endpoints` block leaks the `verify` and admin paths only by omission — §5.1's example doesn't enumerate `verify` either, so this is not a finding.
- **Out of scope but adjacent:** `agentConfigurationDiscoveryUrl()` at `AgentAuthRealmResourceProvider.java:2968-2972` is reused by `/capability/execute`; only its catalog-endpoint use is audited here.
