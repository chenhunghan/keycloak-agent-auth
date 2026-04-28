# Execution / Introspection Spec Audit

Source of truth: Agent Auth Protocol v1.0-draft at <https://agent-auth-protocol.com/specification/v1.0-draft>. README.md was used only for endpoint inventory and to identify documented extension intent.

## Scope

Audited endpoints:

- `POST /realms/{realm}/agent-auth/capability/execute`
- `POST /realms/{realm}/agent-auth/agent/introspect`

Related implementation reviewed:

- `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java`
- `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/AgentJwtVerifier.java`
- `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/ConstraintValidator.java`
- `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/HostJwtVerifier.java`
- `/Users/chh/keycloak-agent-auth/README.md`

## Spec Baseline

- [§2.12](https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities) defines capabilities, including optional `location`; if absent, clients use `default_location`.
- [§2.13](https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints) defines per-grant constraints. Violating execution arguments are rejected with `constraint_violated`.
- [§2.15](https://agent-auth-protocol.com/specification/v1.0-draft#215-execution) says clients resolve a capability's location, sign an agent JWT with `aud` equal to that resolved location URL, and POST `{capability, arguments}` to that location. The location service verifies `aud`, active grants, constraints, and then processes the request. Sync, streaming SSE, and async `202` are all protocol modes.
- [§3.3](https://agent-auth-protocol.com/specification/v1.0-draft#33-agent-capability-grant) says effective capabilities are active grants whose grant-level `expires_at` is absent or still in the future.
- [§4.3](https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt) requires `typ=agent+jwt`, `iss`, `sub`, `aud`, `iat`, `exp`, `jti`, and optional `capabilities`; requests outside the `capabilities` claim must be rejected.
- [§4.5](https://agent-auth-protocol.com/specification/v1.0-draft#45-verification) requires agent JWT verification, host and agent state checks, signature verification, replay detection, grant resolution, optional `capabilities` intersection, constraint enforcement, and bounded revocation effect. The section contains issuer-audience wording that conflicts with §2.15/§4.3 for execution; this audit treats the endpoint-specific resolved-location audience rule as controlling for execution.
- [§4.6](https://agent-auth-protocol.com/specification/v1.0-draft#46-replay-detection) requires `jti` and duplicate rejection within the JWT max-age window.
- [§5.11](https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability) defines execute request/response shapes and SSE event requirements.
- [§5.12](https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect) defines `POST /agent/introspect` as `{token}` returning either compact active metadata or `{active:false}`. It recommends server-to-server protection, and if unauthenticated exposure is allowed, aggressive rate limiting is mandatory.
- [§5.13](https://agent-auth-protocol.com/specification/v1.0-draft#513-error-format) defines `{error,message}` and common/per-endpoint error codes.
- [§5.14](https://agent-auth-protocol.com/specification/v1.0-draft#514-resource-server-challenge-optional) allows a resource server to include `WWW-Authenticate: AgentAuth discovery="..."` on 401 responses.
- [§8.6](https://agent-auth-protocol.com/specification/v1.0-draft#86-capability-validation), [§8.17](https://agent-auth-protocol.com/specification/v1.0-draft#817-constraint-enforcement-atomicity), and [§8.18](https://agent-auth-protocol.com/specification/v1.0-draft#818-cross-server-capability-confusion) reinforce capability validation, constraint TOCTOU awareness, and strict `aud` enforcement.

Documented extension classification:

- README.md documents a gateway audience extension: Keycloak accepts an execution JWT whose `aud` is the resolved capability location even when the request is posted to Keycloak's `/capability/execute`, then proxies upstream. This intentionally relaxes the strict §5.11 sentence that says `aud` is this endpoint's URL, but it preserves the §2.15/§4.3 resolved-location audience identity. This is an intended extension, not a finding by itself.
- README.md also documents that capabilities must be registered with an explicit `location` because this implementation has no local backend dispatcher for locationless capabilities. That is an implementation profile decision; the execute handler's `capability_misconfigured` branch should remain unreachable if admin validation is intact.

## Findings

### F1: Introspection rate limiting is bypassable with any parseable Bearer token

- Endpoint: `POST /agent/introspect`
- Severity: P1
- Spec: [§5.12 Introspect](https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect)
- Code: `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:622`
- Current behavior: unauthenticated rate limiting runs only when the `Authorization` header is missing or does not start with `Bearer `. If a caller sends any syntactically parseable JWT as `Authorization: Bearer ...`, the handler does not authenticate the caller and also skips the unauthenticated rate limit.
- Expected behavior: either protect introspection with real server-to-server authentication, or treat every unauthenticated caller as unauthenticated for rate limiting regardless of whether it provided a parseable bearer-shaped string.
- Rationale: §5.12 says introspection exposes agent identity, grants, and user association. Servers should protect it; if they expose it without caller authentication, they must rate-limit aggressively. The current branch creates a trivial rate-limit bypass.
- Concrete fix steps: add explicit resource-server authentication policy, for example a configured shared secret, mTLS/forwarded client cert check, or Keycloak client/service-account token verification. Track a boolean like `resourceServerAuthenticated`; apply the unauthenticated rate limit whenever it is false. Do not use "JWT parsed successfully" as authentication.

### F2: Gateway execute buffers upstream SSE instead of streaming it

- Endpoint: `POST /capability/execute`
- Severity: P1
- Spec: [§2.15 Execution](https://agent-auth-protocol.com/specification/v1.0-draft#215-execution), [§5.11 Execute Capability](https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability)
- Code: `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:2476`
- Current behavior: the proxy uses `HttpURLConnection`, sets a 30 second read timeout, calls `readAllBytes()`, and only then builds the JAX-RS response. It also drops upstream headers other than `Content-Type`.
- Expected behavior: for `Content-Type: text/event-stream`, the gateway should return a streaming response as bytes/events arrive, preserve SSE content type, and avoid treating a long-lived stream as a timeout. Async responses should preserve relevant headers such as `Retry-After` when upstream supplies them.
- Rationale: §2.15 and §5.11 define stream as a first-class interaction mode. README.md also says SSE responses pass through verbatim. Buffering until close prevents clients from receiving incremental events and can convert valid streams into 500s.
- Concrete fix steps: replace the blocking `readAllBytes()` branch for SSE with JAX-RS `StreamingOutput` or an async response that copies the upstream input stream to the response output stream. Copy safe upstream headers such as `Content-Type`, `Cache-Control`, and `Retry-After`. Use a streaming-aware timeout policy distinct from sync JSON calls.

### F3: Execute does not require the owning host to be active

- Endpoint: `POST /capability/execute`
- Severity: P1
- Spec: [§2.11 Host States](https://agent-auth-protocol.com/specification/v1.0-draft#211-host-states), [§4.5 Verification](https://agent-auth-protocol.com/specification/v1.0-draft#45-verification)
- Code: `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:2251`
- Current behavior: execute rejects missing hosts, `revoked` hosts, and `pending` hosts, but it does not reject `rejected` or any other non-active host state.
- Expected behavior: execution should require the resolved owning host to be `active`; all non-active states should fail closed before grant checks and proxying.
- Rationale: §2.11 says terminal hosts must not be used, and §4.5 requires rejecting invalid host state during agent JWT verification. Introspection already uses `!"active".equals(hostDataForAgent.get("status"))`; execute should match that stricter behavior.
- Concrete fix steps: replace the two-state host check with a single active-state guard after host lookup, returning existing specific errors where useful (`host_revoked`, `host_pending`) and a safe 403 such as `unauthorized` or `host_rejected` for other non-active states. Apply the same helper to other agent-authenticated endpoints for consistency.

### F4: Active grant checks ignore grant-level expiration

- Endpoint: `POST /capability/execute`, `POST /agent/introspect`
- Severity: P1
- Spec: [§3.3 Agent Capability Grant](https://agent-auth-protocol.com/specification/v1.0-draft#33-agent-capability-grant), [§5.11 Execute Capability](https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability), [§5.12 Introspect](https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect)
- Code: `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:2366`, `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:814`
- Current behavior: execute and introspect treat a grant as usable when `status` is `"active"`, without checking a grant-level `expires_at`.
- Expected behavior: effective grants are `status=active` and `expires_at` either absent/null or in the future.
- Rationale: §3.3 explicitly defines effective capabilities this way. A stale grant with an old `expires_at` would still authorize execution and still be reported as active to resource servers.
- Concrete fix steps: add a shared helper such as `isEffectiveActiveGrant(Map<String,Object> grant, Instant now)` that checks status and parses grant `expires_at`. Use it in execute active-grant lookup, introspection grant filtering, JWT `capabilities` intersection paths, and any grant-status response path that reports effective authorization.

### F5: Introspection malformed `token` type is returned as inactive instead of invalid request

- Endpoint: `POST /agent/introspect`
- Severity: P2
- Spec: [§5.12 Introspect](https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect), [§5.13 Error Format](https://agent-auth-protocol.com/specification/v1.0-draft#513-error-format)
- Code: `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:639`, `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:931`
- Current behavior: the handler casts `requestBody.get("token")` to `String` without checking the type. A non-string token throws and is caught by the broad catch-all, returning `200 {"active":false}`.
- Expected behavior: missing or incorrectly typed request fields are `400 invalid_request`; `{active:false}` is for a syntactically valid token that fails validation or maps to an inactive/unknown agent.
- Rationale: §5.12 makes `token` a required string, and §5.13 classifies invalid parameter types as `invalid_request`. Returning inactive hides caller bugs and makes malformed introspection requests indistinguishable from valid inactive tokens.
- Concrete fix steps: validate `token instanceof String && !blank` before parsing. Keep parse/validation failures for the introspected token mapped to `{active:false}`, but do not let malformed request bodies fall into the same catch-all.

### F6: Agent JWT host-rotation fallback is not implemented on execute/introspect

- Endpoint: `POST /capability/execute`, `POST /agent/introspect`
- Severity: P2
- Spec: [§4.5 Verification](https://agent-auth-protocol.com/specification/v1.0-draft#45-verification), [§8.7 Host Key Rotation](https://agent-auth-protocol.com/specification/v1.0-draft#87-host-key-rotation)
- Code: `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:2231`, `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:763`
- Current behavior: execute requires JWT `iss` to equal `agentData.host_id`, then loads the host by that value. Introspect also returns inactive when JWT `iss` differs from the stored host id. There is no fallback path for a JWKS-based host whose signing-key thumbprint changed before stored host/agent rows were rebound.
- Expected behavior: when host lookup by `iss` fails during agent JWT verification, the server should be able to resolve the agent by `sub`, find its parent host, and validate the rotation race according to the host's JWKS identity rules before accepting or rejecting the token.
- Rationale: §4.5 and §8.7 require a fallback for the race window where a JWKS host has rotated keys and agent JWTs arrive with the new `iss` before the auth server has updated the host identifier.
- Concrete fix steps: centralize execute/introspect agent JWT verification in `AgentJwtVerifier` and add host JWKS fallback support there. On `iss` mismatch, only allow fallback for JWKS-backed hosts after resolving the host by the agent's stored parent, fetching the host JWKS, and confirming `iss` matches the key identified by the JWT/header policy. Reject inline-key mismatches.

### F7: Introspection constraint-check extension shape conflicts with README guidance

- Endpoint: `POST /agent/introspect`
- Severity: P3
- Spec: [§2.13 Scoped Grants](https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints), [§5.12 Introspect](https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect)
- Code: `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:900`
- Current behavior: when `{capability, arguments}` is provided, constraint results are placed under `extensions.constraint_check.violations`. README.md says `/agent/introspect` returns a `violations[]` array and direct-mode resource servers should reject when `violations` is present and non-empty.
- Expected behavior: core §5.12 does not define this extension, but the implemented extension should match the documented integration contract or README should be corrected to the implemented shape.
- Rationale: resource servers following README.md will look for top-level `violations` and miss violations nested under `extensions.constraint_check`, allowing direct-mode requests they meant to reject.
- Concrete fix steps: choose one extension contract. Prefer preserving compact §5.12 grants while adding a top-level `violations` alias for backward compatibility, or update README/examples and resource-server samples to consume `extensions.constraint_check.violations`.

## Action Plan

1. Add real resource-server authentication or non-bypassable unauthenticated rate limiting to `/agent/introspect` first; it is the most exposed security issue.
2. Extract a shared agent-authenticated verification helper for execute/introspect/request-capability that enforces host active state, agent lifecycle state, replay order, `capabilities` restrictions, and JWKS host-rotation fallback consistently.
3. Introduce a shared effective-grant predicate and use it anywhere grants authorize execution, introspection, status, or capability-scoped JWT acceptance.
4. Rework gateway proxying to preserve streaming semantics and important response headers. Add focused coverage for SSE, async `202` with `Retry-After`, and upstream error passthrough.
5. Tighten introspection request validation so malformed request bodies return `400 invalid_request`, while invalid introspected JWTs continue returning `{active:false}`.
6. Resolve the documented constraint-check extension contract: either emit the README-described top-level `violations[]` or update docs/examples to match the current `extensions.constraint_check` shape.
