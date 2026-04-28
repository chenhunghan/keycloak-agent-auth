# Agent Auth Protocol v1.0-draft Endpoint Audit

Source of truth: https://agent-auth-protocol.com/specification/v1.0-draft

README.md was used only to enumerate this implementation's documented endpoints and to identify explicitly documented extension rationale. Integration tests were not used as normative input.

## Reports

- [Discovery, liveness, and catalog](discovery-catalog.md)
- [Registration, lifecycle, and key management](registration-lifecycle.md)
- [Execution and introspection](execution-introspection.md)
- [Browser and end-user approval](approval-browser.md)
- [Admin and org-admin control plane](admin-org.md)

## Highest-Priority Action Queue

1. Fix JWT verification binding/order across catalog, lifecycle, execution, introspection, and request-capability paths.
   - Enforce Agent JWT `iss` -> parent-host binding in catalog auth.
   - Enforce Host JWT `iss == signing-key thumbprint` for JWKS-backed hosts.
   - Move `request-capability` replay checks after signature/identity verification.
   - Add the spec's host/JWKS fallback where agent-authenticated paths currently do direct host lookups only.
2. Close active-authority gaps.
   - Apply lifecycle expiry before `request-capability`.
   - Require the owning host to be `active` for execute and related agent-authenticated checks.
   - Honor grant-level `expires_at` when deciding effective grants.
   - Prevent admin flows from creating active delegated authority without an effective `user_id`.
3. Harden exposed approval/introspection surfaces.
   - Add real resource-server authentication or non-bypassable unauthenticated rate limiting for `/agent/introspect`.
   - Require fresh user authentication before approve/deny completion.
   - Fix CIBA email deep links so `agent_id` links render an actionable approval form.
4. Normalize protocol response shapes.
   - Remove or namespace pending-grant `status_url` fields.
   - Return compact spec shapes from agent revoke/rotate-key and host rotate-key.
   - Validate malformed introspection request bodies as `400 invalid_request`.
5. Tighten admin-created protocol records.
   - Apply org/role entitlement checks in admin grant approval.
   - Enforce Ed25519 for admin-created hosts.
   - Validate capability `location` as an absolute usable URL.
   - Keep realm-wide and org-scoped capability CRUD semantics distinct.

## Documented Extensions / Non-Core Behavior

These are deviations from the plain core protocol surface that the audit classifies as intended or non-core, rather than immediate implementation mistakes:

- Keycloak realm-scoped discovery path: `/realms/{realm}/.well-known/agent-configuration`.
- Omitted server `jwks_uri`, because this implementation does not sign protocol responses.
- Custom `admin` approval method.
- Required capability `location`, because this implementation proxies to resource servers and has no local dispatcher for locationless capabilities.
- Liveness endpoint `GET /agent-auth/health`.
- Keycloak Organizations, realm roles, service-account host ownership, and managed agent environments.
- Per-grant status polling endpoint, if retained as an explicit extension and kept out of core grant objects.
