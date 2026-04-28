# Registration, Lifecycle, and Key Management Spec Audit

## Scope

Audited the README-listed registration/lifecycle/key-management endpoints against the Agent Auth Protocol v1.0-draft at https://agent-auth-protocol.com/specification/v1.0-draft:

- `POST /realms/{realm}/agent-auth/agent/register`
- `GET /realms/{realm}/agent-auth/agent/status`
- `GET /realms/{realm}/agent-auth/agent/{agentId}/capabilities/{capabilityName}/status`
- `POST /realms/{realm}/agent-auth/agent/request-capability`
- `POST /realms/{realm}/agent-auth/agent/revoke`
- `POST /realms/{realm}/agent-auth/agent/reactivate`
- `POST /realms/{realm}/agent-auth/agent/rotate-key`
- `POST /realms/{realm}/agent-auth/host/revoke`
- `POST /realms/{realm}/agent-auth/host/rotate-key`

README.md was used only to identify endpoint inventory and documented design extensions. Integration tests were not used as source of truth.

Primary implementation files reviewed:

- `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java`
- `src/main/java/com/github/chh/keycloak/agentauth/HostJwtVerifier.java`
- `src/main/java/com/github/chh/keycloak/agentauth/AgentJwtVerifier.java`
- `src/main/java/com/github/chh/keycloak/agentauth/LifecycleClock.java`
- `src/main/java/com/github/chh/keycloak/agentauth/storage/AgentAuthStorage.java`

## Spec Baseline

- Host JWTs: `typ=host+jwt`; `iss` MUST be the thumbprint of the signing public key for both inline and JWKS hosts; `aud` is the discovery issuer; `jti` is required. See https://agent-auth-protocol.com/specification/v1.0-draft#42-host-jwt.
- Agent JWTs: `typ=agent+jwt`; `iss` is host identifier, `sub` is agent id, `aud` is the auth server issuer for non-execution auth-server calls and the resolved location for execution. The optional `capabilities` claim narrows allowed operations. See https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt.
- Host-authenticated endpoints MUST run the §4.5.1 host-JWT verification pipeline: look up host by `iss`, fall back to `host_jwks_url`, verify signature, check timestamps, reject replayed `jti`, then reject terminal hosts; pending hosts are only allowed for registration. See https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification.
- Agent-authenticated endpoints MUST run the §4.5 verification pipeline: resolve host/agent, reject non-active agent or invalid host, verify signature, then check `exp`/`iat`/`jti`, then enforce grant/capability restrictions and constraints. See https://agent-auth-protocol.com/specification/v1.0-draft#45-verification and https://agent-auth-protocol.com/specification/v1.0-draft#46-replay-detection.
- Agent states are `pending`, `active`, `expired`, `revoked`, `rejected`, `claimed`; only `active` agents can authenticate. Reactivation resets session/max-lifetime clocks but not absolute lifetime. See https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states through https://agent-auth-protocol.com/specification/v1.0-draft#26-revocation.
- Host states are `active`, `pending`, `revoked`, `rejected`; terminal hosts must not register agents and all agents under revoked/rejected hosts must also be revoked/rejected. See https://agent-auth-protocol.com/specification/v1.0-draft#211-host-states.
- Registration returns `agent_id`, `host_id`, `name`, `mode`, `status`, `agent_capability_grants`, and conditional `approval`. Pending grants include only `capability` and `status`; active grants include full capability details and effective constraints. Pending retries SHOULD return the existing agent/current or refreshed approval; active/rejected/revoked/claimed matching agents SHOULD return `409 agent_exists`. See https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration.
- Request-capability returns only the newly requested grants and a conditional approval object; the agent remains active while individual grants may be pending. See https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability.
- Status returns the full agent view and all grant metadata; grant metadata follows §5.3 grant shape. See https://agent-auth-protocol.com/specification/v1.0-draft#55-status.
- Reactivate accepts only expired agents, rejects terminal/pending agents, revokes existing grants, grants host defaults through registration-like auto-approval, resets clocks, and returns the status-shaped response plus conditional `approval`. See https://agent-auth-protocol.com/specification/v1.0-draft#56-reactivate.
- Agent revoke response is exactly `{ "agent_id": "...", "status": "revoked" }`. Agent rotate-key response is exactly `{ "agent_id": "...", "status": "active" }`. Host rotate-key response is exactly `{ "host_id": "...", "status": "active" }`. Host revoke response is exactly `{ "host_id": "...", "status": "revoked", "agents_revoked": n }`. See https://agent-auth-protocol.com/specification/v1.0-draft#57-revoke through https://agent-auth-protocol.com/specification/v1.0-draft#510-revoke-host.
- Approval objects must include `method`, `expires_in`, `interval`, plus method-specific fields such as device `verification_uri`/`user_code`. See https://agent-auth-protocol.com/specification/v1.0-draft#75-approval-methods.
- Standard error shape is `{ "error": "...", "message": "..." }`. See https://agent-auth-protocol.com/specification/v1.0-draft#513-error-format.

## Findings

### F1. JWKS host JWT verification does not enforce `iss == signing-key thumbprint`

- Endpoint: `GET /agent/status`, `POST /agent/reactivate`, `POST /agent/revoke`, `POST /agent/rotate-key`, `POST /host/revoke`, `POST /host/rotate-key`, and `GET /agent/{agentId}/capabilities/{capabilityName}/status`
- Severity: P1
- Spec: https://agent-auth-protocol.com/specification/v1.0-draft#42-host-jwt and https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification
- Code: `src/main/java/com/github/chh/keycloak/agentauth/HostJwtVerifier.java:183`
- Current behavior: `HostJwtVerifier` verifies inline-key hosts by comparing the computed thumbprint to `iss`, but explicitly skips that check for JWKS-based hosts after resolving the key. The code comment says the fetched JWK does not have to match `iss`.
- Expected behavior: For JWKS-based hosts, the JWT header `kid` selects a JWKS key, and the resolved signing key's SHA-256 JWK thumbprint MUST match the JWT `iss`. During fallback lookup by `host_jwks_url`, the server should accept only if that thumbprint matches and then update/rebind the stored host identifier as required by §4.5.1.
- Rationale: §4.2 says the host `iss` is always the thumbprint of the signing key, including JWKS hosts. Skipping this check weakens host identity binding and diverges from the protocol's rotation model.
- Concrete fix steps:
  1. In `HostJwtVerifier.verify`, compute the resolved host key thumbprint for both inline and JWKS keys.
  2. Reject when `!thumbprint.equals(iss)` regardless of key source.
  3. For `foundByJwksFallback`, migrate/rebind the host record to the new `iss` before processing or return enough structured state so callers can do it consistently.
  4. Update endpoint callers to avoid ad-hoc rotated-key checks that conflict with the centralized §4.5.1 result.

### F2. Agent JWT verification paths do not implement the §4.5 host fallback and some endpoints check replay before signature

- Endpoint: `POST /agent/request-capability`
- Severity: P1
- Spec: https://agent-auth-protocol.com/specification/v1.0-draft#45-verification and https://agent-auth-protocol.com/specification/v1.0-draft#46-replay-detection
- Code: `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:1835`, `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:1848`, `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:1875`, `src/main/java/com/github/chh/keycloak/agentauth/AgentJwtVerifier.java:149`
- Current behavior: `requestCapability` consumes `jti` before verifying the agent JWT signature, then looks up the host directly by JWT `iss`. `AgentJwtVerifier` also looks up the host directly by stored `host_id` and has no fallback path for a JWKS host whose signing-key thumbprint changed.
- Expected behavior: Agent-authenticated auth-server calls should resolve host/agent per §4.5, verify the JWT signature, then check `exp`/`iat`/`jti` replay. If lookup by `iss` fails, the server should look up the agent by `sub`, resolve its parent host, and verify the new `iss` against the host JWKS rotation path.
- Rationale: Pre-signature replay consumption lets an unauthenticated forged token burn a legitimate `jti`. Missing JWKS fallback breaks the documented/spec rotation path for agent-authenticated non-execution calls after a JWKS-served host rotates out of band.
- Concrete fix steps:
  1. Replace `requestCapability`'s open-coded JWT verification with `AgentJwtVerifier`, or extend `AgentJwtVerifier` so it covers request-capability-specific checks.
  2. Move replay detection after signature, identity, and status checks.
  3. Add §4.5 host fallback for `iss` misses using `sub -> agent -> stored host -> host_jwks_url`.
  4. Verify fallback `iss` against the resolved host JWKS signing key thumbprint.

### F3. `request-capability` does not lazily apply lifecycle clocks before accepting an active-looking agent

- Endpoint: `POST /agent/request-capability`
- Severity: P1
- Spec: https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states, https://agent-auth-protocol.com/specification/v1.0-draft#24-lifetime-clocks, and https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability
- Code: `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:1901`
- Current behavior: The endpoint reads the stored `status` directly and allows the request when that value is `active`. Unlike status/introspect/execute, it does not call `LifecycleClock.applyExpiry` before deciding whether the agent can authenticate.
- Expected behavior: Before processing an agent-authenticated capability escalation, apply session TTL, max lifetime, and absolute lifetime evaluation. If the clocks demote the agent to `expired` or `revoked`, reject as non-active and persist the transition.
- Rationale: §2.3 permits only active agents to authenticate. A stale stored `active` value after `expires_at` or max lifetime has passed can otherwise continue escalating capabilities.
- Concrete fix steps:
  1. Call `LifecycleClock.applyExpiry(agentData)` after loading the agent and before status checks.
  2. Persist any status transition with `updated_at`.
  3. Return the existing `agent_expired` / `agent_revoked` errors after the transition.
  4. Prefer centralizing this in `AgentJwtVerifier` so all agent-authenticated auth-server endpoints behave consistently.

### F4. Pending grant responses include `status_url`, violating the core pending-grant wire shape

- Endpoint: `POST /agent/register`, `POST /agent/request-capability`
- Severity: P2
- Spec: https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration and https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability
- Code: `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:567`, `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:2060`, `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:3336`
- Current behavior: Pending grants are stored and returned with a `status_url` pointing to `GET /agent/{agentId}/capabilities/{capabilityName}/status`. `sanitizeGrantsForResponse` strips only `requested_constraints`, not `status_url`.
- Expected behavior: Pending grants in registration, status, reactivation, and request-capability responses include only `capability` and `status`. Polling is through the approval object's `interval` and `GET /agent/status`; §5.4 says clients poll status until pending grants become active/denied.
- Rationale: The per-grant status endpoint is documented in README as an extension, but adding `status_url` inside core grant objects changes the normative response shape. Clients following §5.3/§5.4 will not expect method-specific polling URLs embedded per grant.
- Concrete fix steps:
  1. Remove `status_url` from core pending grant responses.
  2. If the extension is retained, advertise it under an `extensions` object or a clearly documented non-core top-level field.
  3. Update `sanitizeGrantsForResponse` to strip all internal/extension-only grant fields from core responses unless an extension response mode is explicitly requested.

### F5. Agent revoke and agent rotate-key return full agent records instead of lifecycle/key-management response shapes

- Endpoint: `POST /agent/revoke`, `POST /agent/rotate-key`
- Severity: P2
- Spec: https://agent-auth-protocol.com/specification/v1.0-draft#57-revoke and https://agent-auth-protocol.com/specification/v1.0-draft#58-key-rotation
- Code: `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:1118`, `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:1185`, `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:1195`
- Current behavior: `rotateAgentKey` and `revokeAgent` return `sanitizeAgentResponse(agentData)`, which can include `host_id`, `name`, `mode`, public-key material, timestamps, full grant arrays, approval data, and other stored fields.
- Expected behavior: Revoke returns only `agent_id` and `status: "revoked"`. Agent rotate-key returns only `agent_id` and current `status` (expected `"active"`).
- Rationale: These endpoints are lifecycle/key-management acknowledgements, not status endpoints. Returning full stored agent records leaks unnecessary implementation detail and diverges from the specified contract.
- Concrete fix steps:
  1. Change `revokeAgent` success responses to `Map.of("agent_id", agentId, "status", "revoked")`.
  2. Change already-revoked handling to the same success shape if idempotency is desired, or document and standardize any non-idempotent extension behavior.
  3. Change `rotateAgentKey` success response to `Map.of("agent_id", agentId, "status", agentData.get("status"))`.
  4. Add response-shape tests around these endpoints.

### F6. Agent key rotation allows pending agents and does not check host state

- Endpoint: `POST /agent/rotate-key`
- Severity: P2
- Spec: https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification and https://agent-auth-protocol.com/specification/v1.0-draft#58-key-rotation
- Code: `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:1091`, `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:1102`
- Current behavior: The endpoint rejects terminal and expired agents, but it does not reject `pending` agents. It also does not inspect `verified.hostData()` to reject pending/rejected/revoked hosts before rotating the agent key.
- Expected behavior: Host-authenticated key rotation should be processed only for a valid host under §4.5.1. Pending hosts are only allowed for registration, and the §5.8 response says the agent status should be `active`.
- Rationale: Pending agents cannot authenticate and are still awaiting approval. Allowing key mutation under a pending or rejected host creates lifecycle behavior outside the spec and may desynchronize the approval record from the key that was approved.
- Concrete fix steps:
  1. Require `verified.hostData()` to exist and have `status == "active"` before mutating agent keys.
  2. Reject pending agents with `403 agent_pending` or `409 invalid_state`.
  3. Return the compact §5.8 shape after successful rotation.

### F7. Host revoke is not response-compatible when the host is already revoked

- Endpoint: `POST /host/revoke`
- Severity: P3
- Spec: https://agent-auth-protocol.com/specification/v1.0-draft#510-revoke-host and https://agent-auth-protocol.com/specification/v1.0-draft#513-error-format
- Code: `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:1365`
- Current behavior: A self-revoke call for an already-revoked host returns `409 already_revoked`.
- Expected behavior: The §5.10 response shape is `{ "host_id": "...", "status": "revoked", "agents_revoked": n }`. The spec does not define a `409 already_revoked` branch for this endpoint.
- Rationale: Revocation endpoints are easier for clients to retry when idempotent. The current behavior is not explicitly documented in README as an intended extension.
- Concrete fix steps:
  1. Return `200` with `agents_revoked: 0` for already-revoked hosts, or document a deliberate non-idempotent extension.
  2. Keep the standard error shape only for truly invalid requests/auth failures.

### F8. Host rotate-key response includes non-core `previous_host_id`

- Endpoint: `POST /host/rotate-key`
- Severity: P3
- Spec: https://agent-auth-protocol.com/specification/v1.0-draft#59-rotate-host-key
- Code: `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:1504`
- Current behavior: The response includes `host_id`, `status`, and `previous_host_id`.
- Expected behavior: The core response includes only `host_id` and `status`.
- Rationale: `previous_host_id` is useful operationally, but it is not a core field and is not documented in README as an extension response field.
- Concrete fix steps:
  1. Remove `previous_host_id` from the core response, or move it under `extensions.previous_host_id`.
  2. Document the extension if clients depend on it.

### F9. Grant status polling endpoint is an extension with no core Server API coverage

- Endpoint: `GET /agent/{agentId}/capabilities/{capabilityName}/status`
- Severity: Extension/no core spec coverage
- Spec: https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability and https://agent-auth-protocol.com/specification/v1.0-draft#55-status
- Code: `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:2528`; README inventory at `README.md:61`
- Current behavior: The implementation exposes a per-grant polling endpoint that returns `{ agent_id, capability, status, reason? }`.
- Expected behavior: Core AAP v1.0-draft does not define this endpoint. Clients poll `GET /agent/status` at the approval object's `interval` and inspect the grant array.
- Rationale: README explicitly inventories the endpoint, so the endpoint itself is a documented extension. The spec issue is only when core response bodies embed this extension as `status_url` on pending grants (see F4).
- Concrete fix steps:
  1. Keep the endpoint as an extension if needed.
  2. Document it in an "extensions" section with request/response shape and auth requirements.
  3. Do not surface it inside core grant objects unless the response makes clear that it is extension metadata.

### F10. Documented Keycloak organization/service-account capability gates are extensions, not core spec violations

- Endpoint: `POST /agent/register`, `POST /agent/request-capability`, status/reactivation responses containing capability grants
- Severity: Extension/no core spec coverage
- Spec: https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities and https://agent-auth-protocol.com/specification/v1.0-draft#33-agent-capability-grant
- Code: `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:449`, `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:1960`; README design rationale at `README.md:191` and `README.md:226`
- Current behavior: Capability visibility/granting is additionally gated by Keycloak Organizations, `required_role`, service-account host policy, `auto_deny`, and per-host TOFU `default_capabilities`.
- Expected behavior: AAP defines capability/grant fields and approval semantics, but does not define multi-tenancy, Keycloak organizations, service-account host policy, or `auto_deny`.
- Rationale: README explicitly documents these as Keycloak-specific design decisions. Treat them as extensions as long as protocol-facing responses still preserve core field semantics.
- Concrete fix steps:
  1. Keep extension fields out of core response objects unless namespaced or documented.
  2. Ensure extension denial paths still use standard `{error, message}` and do not widen capabilities beyond requested constraints.
  3. Add extension documentation that maps Keycloak org/role decisions to AAP visibility/grant outcomes.

## Action Plan

1. Centralize host and agent JWT verification before changing endpoint behavior. Make `HostJwtVerifier` and `AgentJwtVerifier` implement the exact §4.5/§4.5.1 order and JWKS thumbprint/fallback rules, then migrate `registerAgent` and `requestCapability` away from open-coded verification.
2. Fix lifecycle enforcement on `requestCapability` by applying `LifecycleClock` before accepting an active-looking stored status.
3. Normalize lifecycle/key-management response bodies for revoke/rotate-key endpoints to match §5.7-§5.10.
4. Remove or namespace extension metadata in core responses, especially pending grant `status_url` and host rotate `previous_host_id`.
5. Decide and document idempotency behavior for repeated host/agent revocation. Prefer idempotent success shapes unless there is a deliberate product reason to reject retries.
6. Keep the per-grant status endpoint and Keycloak org/service-account gating as documented extensions, but isolate their response fields from core AAP shapes.
