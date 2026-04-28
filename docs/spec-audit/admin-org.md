# Admin / Org-Admin Endpoint Spec Audit

## Scope

Audited the documented realm-admin and org-admin endpoints under `/admin/realms/{realm}/agent-auth` against the Agent Auth Protocol v1.0-draft at https://agent-auth-protocol.com/specification/v1.0-draft.

The spec does not define a normative admin REST API. It explicitly treats host pre-registration, host linking, user/admin revocation, approval UI, and service/directory onboarding as server-specific dashboard/API mechanisms. This audit therefore treats the admin/org-admin endpoints as extension/control-plane APIs and checks whether they create or mutate protocol-visible host, agent, capability, grant, or approval records in ways that violate the core model consumed by `/agent/register`, `/agent/status`, `/capability/list`, `/capability/describe`, `/capability/execute`, `/agent/introspect`, approval, revocation, and cleanup flows.

README.md was used only as endpoint inventory and extension-rationale context. Integration tests were not used as source of truth.

Endpoints reviewed:

- `POST /admin/realms/{realm}/agent-auth/capabilities`
- `PUT /admin/realms/{realm}/agent-auth/capabilities/{name}`
- `DELETE /admin/realms/{realm}/agent-auth/capabilities/{name}`
- `POST /admin/realms/{realm}/agent-auth/hosts`
- `GET /admin/realms/{realm}/agent-auth/hosts/{id}`
- `POST /admin/realms/{realm}/agent-auth/hosts/{id}/link`
- `DELETE /admin/realms/{realm}/agent-auth/hosts/{id}/link`
- `GET /admin/realms/{realm}/agent-auth/agents/{id}`
- `GET /admin/realms/{realm}/agent-auth/agents/{id}/grants`
- `POST /admin/realms/{realm}/agent-auth/agents/{id}/capabilities/{capability}/approve`
- `POST /admin/realms/{realm}/agent-auth/agents/{id}/expire`
- `POST /admin/realms/{realm}/agent-auth/agents/{id}/reject`
- `POST /admin/realms/{realm}/agent-auth/pending-agents/cleanup`
- `POST /admin/realms/{realm}/agent-auth/organizations/{orgId}/capabilities`
- `GET /admin/realms/{realm}/agent-auth/organizations/{orgId}/capabilities`
- `PUT /admin/realms/{realm}/agent-auth/organizations/{orgId}/capabilities/{name}`
- `DELETE /admin/realms/{realm}/agent-auth/organizations/{orgId}/capabilities/{name}`
- `POST /admin/realms/{realm}/agent-auth/organizations/{orgId}/hosts`
- `POST /admin/realms/{realm}/agent-auth/organizations/{orgId}/agent-environments`
- `GET /admin/realms/{realm}/agent-auth/organizations/{orgId}/agent-environments`
- `DELETE /admin/realms/{realm}/agent-auth/organizations/{orgId}/agent-environments/{clientId}`

## Spec Baseline

- Admin APIs are not part of the core interoperable surface. Sections §2.8, §2.9, §2.6, §5.7, §5.10, and §7.2 leave dashboards/admin APIs and approval surfaces to the server.
- Hosts are durable client identities. §2.8 allows pre-registration through a server-specific mechanism, but the resulting host still has protocol fields from §3.1: Ed25519 `public_key` or JWKS URL, optional `user_id`, `default_capabilities`, and status.
- Delegated agents act for a specific user (§2.2.1). The data model assumes one effective `agent.user_id` at a time (§3.2, §3.3.1). Server-side grant approvers may differ from the effective user, but `granted_by` is audit metadata and does not change `agent.user_id`.
- Host linking (§2.9) binds an unlinked host to one user; once linked, future delegated agents through that host may be auto-approved within defaults. Host unlinking must revoke delegated agents.
- Autonomous agent claiming (§2.10) is mandatory when a host becomes linked: active autonomous agents are marked `claimed`, their grants are revoked, and activity is attributed to the user.
- Host states (§2.11) are `active`, `pending`, `revoked`, and `rejected`. A pending host may register agents, but agents under it must remain pending until the host is approved. Terminal hosts must not register agents and must cascade terminal state to agents.
- Capability records (§2.12) require `name` and `description`; `location` is optional in the spec, but if present it is the URL used for execution. If absent, clients use discovery `default_location` (§2.15, §5.1).
- Capability names are opaque, with lowercase snake_case only a SHOULD (§2.14), not a MUST.
- Grants may carry constraints (§2.13). Servers must not widen constraints beyond what the agent requested without new approval.
- Registration/status/request-capability responses carry full active-grant metadata; pending grants are compact; denied grants carry optional reason (§5.3-§5.5).
- Revocation is permanent (§2.6, §5.7), and host revocation cascades to all agents (§5.10).
- Device authorization is mandatory (§7.1); CIBA is recommended (§7.2); custom methods such as `admin` are extension-profile behavior (§7.4, §10.10.3) and must be explicitly documented/discoverable.
- Pending-agent cleanup is recommended and deletes pending agents rather than revoking them (§7.1, §10.9). Pending-host cleanup is analogous but not mandated.

## Findings

### AAP-ADMIN-001: Admin-created unowned delegated authority

- Endpoint: `POST /admin/realms/{realm}/agent-auth/hosts`; also exposed through `POST /admin/realms/{realm}/agent-auth/agents/{id}/capabilities/{capability}/approve`
- Severity: P1
- Classification: likely implementation mistake / core protocol violation
- Spec: https://agent-auth-protocol.com/specification/v1.0-draft §2.2.1, §2.9, §3.2, §3.3.1, §5.3, §7.4
- Code: `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthAdminResourceProvider.java:551`, `:598`, `:462`, `:479`; consumed by `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:539`, `:596`
- Current behavior: realm-admin host pre-registration creates an `active` host immediately, and only sets `user_id` when optional `client_id` is supplied. A delegated agent registered later under that active unlinked host can become `active` when no approval is required. Separately, admin grant approval can activate a pending delegated agent and pending host, but it records only `granted_by`; it does not set `host.user_id` or `agent.user_id`.
- Expected behavior: an `active` delegated agent should have a single effective user context. Admin approval may be the approving actor, but the effective user must come from a linked host/user or an explicit server-defined approval profile that defines different subject semantics.
- Rationale: §3.3.1 allows `granted_by` to differ from `agent.user_id` for audit, but does not let it replace the agent's effective user context. An active delegated agent without `user_id` can appear grantable in status and can execute realm-wide capabilities while not actually acting on behalf of any user.
- Concrete fix steps:
  1. Make realm-admin host pre-registration without `client_id` either create a `pending` host, require an explicit `user_id`, or mark the host as autonomous-only.
  2. Reject delegated registration under an active unlinked pre-registered host unless the request is routed into a user approval flow.
  3. For admin grant approval of delegated agents, require an existing linked `host.user_id` or accept and validate an explicit `user_id` body field, then set both `host.user_id` and `agent.user_id` when activating the pending host/agent.
  4. Keep `granted_by` as the admin identity; do not use it as the effective user.

### AAP-ADMIN-002: Admin grant approval bypasses org/role entitlement gate

- Endpoint: `POST /admin/realms/{realm}/agent-auth/agents/{id}/capabilities/{capability}/approve`
- Severity: P2
- Classification: likely implementation mistake in documented extension behavior
- Spec: https://agent-auth-protocol.com/specification/v1.0-draft §3.3, §5.3, §5.5, §10.10.1; README extension rationale documents `organization_id`/`required_role` enforcement at approval and introspection
- Code: `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthAdminResourceProvider.java:435`; compare user approval gate at `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:3063`
- Current behavior: admin approval promotes any pending grant to `active` once the capability exists and the grant is pending. It does not check whether the agent's effective user satisfies the capability's `organization_id` or `required_role` gates. Later execution and introspection re-check entitlements and fail/strip the grant.
- Expected behavior: admin-mediated approval should apply the same entitlement gate as user approval, or explicitly deny the grant with `reason=insufficient_authority` when the effective user cannot hold it.
- Rationale: §5.5 says status reflects the server's current capability state for the agent. Returning an active grant that execution/introspection immediately treats as unauthorized makes the status API lie about protocol-visible authority. This also contradicts the documented multi-tenant extension promise that org/role gates are enforced at approval.
- Concrete fix steps:
  1. Resolve the effective user from `agent.user_id` or `host.user_id` before approving.
  2. Reuse the entitlement check used by registration/request-capability/user approval.
  3. If no effective user exists for a delegated agent, apply AAP-ADMIN-001 behavior.
  4. If entitlement fails, leave the agent active if appropriate but mark the grant `denied` with `reason=insufficient_authority` instead of `active`.

### AAP-ADMIN-003: Admin host pre-registration accepts non-Ed25519 OKP keys

- Endpoint: `POST /admin/realms/{realm}/agent-auth/hosts`; `POST /admin/realms/{realm}/agent-auth/organizations/{orgId}/hosts`; `POST /admin/realms/{realm}/agent-auth/organizations/{orgId}/agent-environments`
- Severity: P2
- Classification: likely implementation mistake / spec violation
- Spec: https://agent-auth-protocol.com/specification/v1.0-draft §3.1, §4.1, §5.1
- Code: `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthAdminResourceProvider.java:530`, `:885`, `:1024`; verifier rejects later at `src/main/java/com/github/chh/keycloak/agentauth/HostJwtVerifier.java:155`
- Current behavior: admin host creation parses `host_public_key` as a Nimbus `OctetKeyPair` and computes the thumbprint, but does not check `crv == Ed25519`. That can persist an `active` host with an unsupported OKP curve; later host JWT verification rejects it as `host_public_key must be Ed25519`.
- Expected behavior: admin host pre-registration should reject unsupported host keys before persistence, with the same Ed25519 requirement enforced by protocol registration and host JWT verification.
- Rationale: discovery advertises only Ed25519, and §3.1 defines inline host `public_key` as Ed25519. Persisting an active but unverifiable host creates protocol-visible broken state.
- Concrete fix steps:
  1. Add a shared `parseEd25519HostKey` helper in `AgentAuthAdminResourceProvider`.
  2. After `OctetKeyPair.parse`, require `Curve.Ed25519`.
  3. Return `400 unsupported_algorithm` or `400 invalid_request` consistently with existing protocol endpoints.
  4. Apply the helper to realm host pre-registration, org host pre-registration, and org agent-environment creation.

### AAP-ADMIN-004: Capability `location` is required by extension but not validated as a URL

- Endpoint: realm and org capability create/update endpoints
- Severity: P2
- Classification: likely implementation mistake in documented extension behavior
- Spec: https://agent-auth-protocol.com/specification/v1.0-draft §2.12, §2.15, §5.1, §5.11
- Code: `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthAdminResourceProvider.java:1574`; consumed by `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:2401`, `:2468`
- Current behavior: admin validation requires `location` to be a non-blank string, but accepts malformed values or non-absolute/non-HTTP locations. The capability can then appear in `/capability/list` and `/capability/describe`, but execution may fail with runtime URI/URL errors.
- Expected behavior: because this implementation intentionally requires `location`, it should also require it to be a valid absolute execution URL usable by clients and the gateway.
- Rationale: §2.12 and §2.15 define `location` as the URL to which the client sends execution requests and uses as the agent JWT audience. A catalog entry with a malformed location breaks discovery-to-execution interoperability.
- Concrete fix steps:
  1. Parse `location` with `URI.create` inside admin validation.
  2. Require an absolute URI with scheme and host.
  3. Prefer restricting to `https`, with any localhost/test exceptions explicitly documented if needed.
  4. Return `400 invalid_capability_location` before storing malformed capability records.

### AAP-ADMIN-005: Realm capability CRUD can silently create org-scoped capabilities

- Endpoint: `POST/PUT /admin/realms/{realm}/agent-auth/capabilities[/{name}]`
- Severity: P3
- Classification: likely implementation mistake in documented extension behavior; no core spec coverage for orgs
- Spec: https://agent-auth-protocol.com/specification/v1.0-draft §5.2, §10.10; README documents realm-admin capability CRUD as realm-wide and org-admin CRUD as path-derived org-scoped
- Code: `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthAdminResourceProvider.java:90`, `:135`, `:1602`
- Current behavior: the realm-admin capability endpoints accept `organization_id` from the request body if it is a non-blank string. The org-admin endpoints correctly force `organization_id` from the path and prevent body override.
- Expected behavior: realm-admin endpoints documented as realm-wide should reject or strip `organization_id`; realm admins that need org-scoped capabilities should use the org path or an explicit superuser org-management path.
- Rationale: multi-tenancy is an extension, but split endpoint semantics matter. Allowing tenant scope through the realm-wide endpoint bypasses the path-derived tenant invariant and can create capabilities that are invisible or mis-scoped if the supplied org id is wrong.
- Concrete fix steps:
  1. In realm `registerCapability` and `updateCapability`, reject body `organization_id` with `400 invalid_request`, or strip it and store `null`.
  2. Keep `required_role` allowed for single-tenant role gating if desired.
  3. Document the intended realm-admin route for org-scoped writes, likely the existing `/organizations/{orgId}/capabilities` path with realm-admin override.

## Non-Actionable Classifications

- Admin/org-admin endpoint existence: intended extension/no core spec coverage. The spec repeatedly allows server dashboards/admin APIs for pre-registration, linking, revocation, and approval surfaces.
- Org-admin capabilities, hosts, and agent-environment provisioning: intended design/extension. AAP has no multi-tenant org model; README explicitly documents Keycloak Organizations, `organization_id`, `required_role`, service-account hosts, managed clients, and a 50-client quota.
- `visibility`, `requires_approval`, `auto_deny`, `write_capable`, `organization_id`, and `required_role` on capability records: intended extension/no core spec coverage, as long as they do not cause core-visible state to misrepresent authority.
- Requiring `location` at admin create/update time: documented extension/implementation constraint. The spec allows missing `location` with fallback to `default_location`, but README explains this implementation rejects locationless capabilities because its gateway cannot execute them directly.
- Uppercase capability names accepted by admin validation: documented relaxation. §2.14 only says lowercase snake_case SHOULD be used; it is not a MUST.
- Capability deletion leaving stored grants intact: acceptable when runtime paths fail closed. §2.12 says removed capability grants become inoperative and execution must return `403 capability_not_granted`; the implementation does that and decorates admin reads with `inoperative`.
- `GET /admin/.../agents/{id}/grants`: intended operational extension/no core spec coverage. It exposes the secondary index, not a protocol endpoint.
- Pending-agent cleanup endpoint and scheduled cleanup: aligned with §7.1 and §10.9. Orphan pending-host cleanup is an operational extension, not a spec requirement.
- Discovery advertising `approval_methods: ["device_authorization", "ciba", "admin"]`: acceptable extension-profile behavior if the `admin` semantics remain documented. Per §5.1, clients SHOULD ignore methods they do not recognize.

## Action Plan

1. Fix delegated effective-user handling first (AAP-ADMIN-001). This is the only finding that can create active delegated protocol authority with no user context.
2. Add entitlement checks to admin grant approval (AAP-ADMIN-002) and align denial behavior with `/verify/approve`.
3. Centralize admin host key validation and enforce Ed25519 across realm/org/env host creation (AAP-ADMIN-003).
4. Tighten capability `location` validation for all capability create/update paths (AAP-ADMIN-004).
5. Decide whether realm-admin capability CRUD is strictly realm-wide. If yes, reject `organization_id` there and keep org-scoped writes on the path-derived org endpoints (AAP-ADMIN-005).
