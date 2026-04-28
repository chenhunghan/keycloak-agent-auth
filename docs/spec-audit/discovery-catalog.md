# Discovery, Liveness, and Catalog Endpoint Spec Audit

## Scope

Audited the documented endpoint surface from `README.md` against the Agent Auth Protocol v1.0-draft, using only the published spec as normative source of truth:

- `GET /realms/{realm}/.well-known/agent-configuration`
- `GET /realms/{realm}/agent-auth/health`
- `GET /realms/{realm}/agent-auth/capability/list`
- `GET /realms/{realm}/agent-auth/capability/describe`

Implementation files inspected:

- `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthWellKnownProvider.java`
- `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthDiscoveryCacheFilter.java`
- `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java`
- `src/main/java/com/github/chh/keycloak/agentauth/AgentJwtVerifier.java`
- `src/main/java/com/github/chh/keycloak/agentauth/HostJwtVerifier.java`
- storage/admin paths only where needed to understand catalog response shape.

## Spec Baseline

- [§5.1 Discovery](https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery): discovery is `GET /.well-known/agent-configuration`, requires no auth, returns `version`, `provider_name`, `description`, `issuer`, `algorithms`, `modes`, `approval_methods`, `endpoints`, and optional `default_location` / `jwks_uri`; endpoint paths are relative to `issuer`; discovery responses SHOULD be cacheable with about `max-age=3600`.
- [§5.1.1 Versioning](https://agent-auth-protocol.com/specification/v1.0-draft#511-versioning): clients MUST check `version`; clients SHOULD ignore unrecognized response fields where possible.
- [§2.12 Capabilities](https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities): core capability fields are `name`, `description`, optional `location`, optional `input`, optional `output`, and `grant_status` only when authenticated with an agent JWT.
- [§2.14 Capability Naming](https://agent-auth-protocol.com/specification/v1.0-draft#214-capability-naming): names are opaque stable identifiers; servers may adopt conventions.
- [§5.2 List Capabilities](https://agent-auth-protocol.com/specification/v1.0-draft#52-list-capabilities): supports no auth, Host JWT, and Agent JWT. No auth returns public capabilities only. Host JWT returns capabilities available to the host's linked user. Agent JWT returns capabilities with `grant_status` (`granted` / `not_granted`) on every returned capability. Response entries are lightweight: `name`, `description`, and `grant_status` when agent-authenticated. Servers with no public capability set MAY return `401 authentication_required` with an AgentAuth discovery challenge.
- [§5.2.1 Describe Capability](https://agent-auth-protocol.com/specification/v1.0-draft#521-describe-capability): same auth modes as list. Returns one capability object with §2.12 fields and `grant_status` when agent-authenticated. Unknown capability names MUST return `404 capability_not_found`; clients treat missing `input` as an empty schema.
- [§4.3 Agent JWT](https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt), [§4.5 Verification](https://agent-auth-protocol.com/specification/v1.0-draft#45-verification), and [§4.5.1 Host JWT Verification](https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification): catalog Agent JWTs must use `aud = issuer`; agent verification must use `iss` to resolve/validate the parent host and verify the agent belongs to that host; host verification rejects revoked/rejected hosts and allows pending hosts only for registration.
- [§5.13 Error Responses](https://agent-auth-protocol.com/specification/v1.0-draft#513-error-responses): Agent Auth errors use `{ "error": "...", "message": "..." }`; common `401 invalid_jwt` covers invalid, expired, or signature-failed JWTs; catalog-specific errors include `401 authentication_required` for list and `404 capability_not_found` for describe.
- [§5.14 Resource Server Challenge](https://agent-auth-protocol.com/specification/v1.0-draft#514-resource-server-challenge-optional): `WWW-Authenticate: AgentAuth discovery="..."` is an optional 401 challenge pointing at an absolute discovery URL.

## Findings

### Actionable

#### P1: Agent JWT catalog auth does not bind `iss` to the agent's parent host

- Classification: likely implementation mistake / spec violation.
- Endpoint: `GET /capability/list`, `GET /capability/describe`.
- Spec reference: [§4.3](https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt), [§4.5 steps 2-5](https://agent-auth-protocol.com/specification/v1.0-draft#45-verification), [§5.2](https://agent-auth-protocol.com/specification/v1.0-draft#52-list-capabilities), [§5.2.1](https://agent-auth-protocol.com/specification/v1.0-draft#521-describe-capability).
- Code reference: `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:1557`, `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:1733`, `src/main/java/com/github/chh/keycloak/agentauth/AgentJwtVerifier.java:121`, `src/main/java/com/github/chh/keycloak/agentauth/AgentJwtVerifier.java:126`, `src/main/java/com/github/chh/keycloak/agentauth/AgentJwtVerifier.java:131`, `src/main/java/com/github/chh/keycloak/agentauth/AgentJwtVerifier.java:144`.
- Current behavior: catalog endpoints call `AgentJwtVerifier.verify(...)`; the verifier checks `aud`, `sub`, agent status, stored `agentData.host_id`, host status, signature, and replay, but never extracts or validates the JWT `iss` against the host. A valid agent-signed JWT can therefore carry a mismatched/missing host issuer and still unlock agent-authenticated catalog behavior.
- Expected spec behavior: Agent JWT verification extracts `iss` and `sub`, resolves the host by `iss` (with the spec's JWKS rotation fallback where applicable), looks up the agent by `sub`, and verifies that the agent belongs to the resolved host before processing.
- Rationale: `iss` is a required Agent JWT claim identifying the host. Skipping it weakens the host-agent binding that the catalog relies on when returning agent-specific grant status.
- Concrete fix steps:
  1. In `AgentJwtVerifier.verify`, require non-blank `claims.getIssuer()`.
  2. Resolve the host from `iss` before accepting the stored `agentData.host_id`; support the existing host rotation/JWKS fallback if this implementation intends to support that path for agent JWTs.
  3. Reject when the resolved host is missing, non-active, or does not match the agent's stored parent host.
  4. Add focused coverage for `agent+jwt` with valid agent signature but wrong/missing `iss` on both catalog endpoints.

#### P2: Malformed or unknown Bearer tokens are silently downgraded to unauthenticated catalog access

- Classification: likely implementation mistake / spec violation.
- Endpoint: `GET /capability/list`, `GET /capability/describe`.
- Spec reference: [§5.2 auth modes](https://agent-auth-protocol.com/specification/v1.0-draft#52-list-capabilities), [§5.2.1 auth modes](https://agent-auth-protocol.com/specification/v1.0-draft#521-describe-capability), [§5.13 common `invalid_jwt`](https://agent-auth-protocol.com/specification/v1.0-draft#513-error-responses).
- Code reference: `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:90`, `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:95`, `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:100`, `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:104`, `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:1536`, `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:1716`.
- Current behavior: `sniffJwtType` returns `null` for malformed JWTs, missing `typ`, or unrecognized `typ`. The catalog handlers interpret `null` the same as no auth and continue with public-only visibility, returning `200` if public capabilities exist or `404 capability_not_found` for hidden describe targets.
- Expected spec behavior: an omitted `Authorization` header is the no-auth mode; a supplied but invalid Bearer JWT should fail as `401 invalid_jwt` rather than being treated as anonymous.
- Rationale: Silent downgrade can mask client bugs and makes invalid credentials behave differently depending on whether public capabilities happen to exist.
- Concrete fix steps:
  1. Split `sniffJwtType` into a typed result: no header, malformed token, unsupported `typ`, host JWT, agent JWT.
  2. Preserve anonymous behavior only when the header is absent.
  3. Return `401 invalid_jwt` for malformed Bearer values, missing/unknown `typ`, and unsupported JWT types.
  4. Reuse the same behavior in both list and describe.

#### P2: Known non-active Host JWTs are downgraded to public catalog access

- Classification: likely implementation mistake / spec violation.
- Endpoint: `GET /capability/list`, `GET /capability/describe`.
- Spec reference: [§5.2 Host JWT mode](https://agent-auth-protocol.com/specification/v1.0-draft#52-list-capabilities), [§5.2.1 auth modes](https://agent-auth-protocol.com/specification/v1.0-draft#521-describe-capability), [§4.5.1 step 8](https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification), [§5.13 errors](https://agent-auth-protocol.com/specification/v1.0-draft#513-error-responses).
- Code reference: `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:1539`, `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:1546`, `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:1552`, `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:1719`, `src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:1722`, `src/main/java/com/github/chh/keycloak/agentauth/HostJwtVerifier.java:198`.
- Current behavior: `HostJwtVerifier` verifies the token but does not reject known non-active hosts. The catalog handlers only mark a Host JWT as authenticated when the stored host is `active` and linked; otherwise they fall through to anonymous public catalog behavior.
- Expected spec behavior: once a Host JWT is supplied and maps to a known host, host verification should reject revoked/rejected hosts and should not allow pending hosts outside registration. Active but unlinked hosts can reasonably receive only public capabilities because §5.2 defines Host JWT catalog visibility in terms of the host's linked user.
- Rationale: A terminal or pending principal should not be normalized into anonymous success, especially because the HTTP outcome then depends on the public catalog contents.
- Concrete fix steps:
  1. After host verification in catalog handlers, distinguish unknown/dynamic hosts, active unlinked hosts, and known non-active hosts.
  2. Return an error for known `revoked`, `rejected`, or `pending` hosts before public fallback.
  3. Keep the intentional public-only fallback only for absent auth, unknown dynamic hosts if desired, and active unlinked hosts with no linked-user catalog.

### Intended Design / Extension

- Discovery path is realm-scoped as `GET /realms/{realm}/.well-known/agent-configuration` rather than root-scoped `GET /.well-known/agent-configuration`. This is explicitly documented as a Keycloak WellKnownProvider integration in `README.md:43` and `README.md:247`. The discovery payload's `issuer` is `/realms/{realm}/agent-auth`, and endpoint paths are relative to that issuer as required by §5.
- Discovery omits `jwks_uri`. This is allowed because §5.1 makes it optional for future server-signed responses; `README.md:240` explicitly says this extension does not sign protocol responses and therefore does not expose server JWKS.
- Discovery advertises custom approval method `admin` at `AgentAuthWellKnownProvider.java:31`. §5.1 permits additional custom approval methods; `README.md:250` documents the extension rationale.
- Capability registration requires `location` even though §2.12 makes capability `location` optional when `default_location` exists. This is an intentional implementation constraint documented in `README.md:182` and `AgentAuthAdminResourceProvider.java:1551`, because this implementation does not provide a backend dispatcher for locationless capabilities.
- `GET /agent-auth/health` is a liveness extension with no core spec coverage. It is documented only as a liveness probe in `README.md:45` and implemented at `AgentAuthRealmResourceProvider.java:115`.
- `GET /capability/describe` returns persisted extension fields such as `visibility`, `requires_approval`, `organization_id`, and `required_role` because it copies the stored capability map at `AgentAuthRealmResourceProvider.java:1765`. These fields are outside the §2.12 core capability model, but §5.1.1 tells clients to ignore unrecognized response fields where possible.

## Action Plan

1. Fix `AgentJwtVerifier` to enforce the Agent JWT `iss` / parent-host binding before the catalog endpoints trust agent-authenticated requests.
2. Treat supplied-but-invalid Bearer tokens as `401 invalid_jwt`; reserve anonymous catalog behavior for truly absent auth.
3. Reject known non-active Host JWT principals on catalog endpoints instead of downgrading them to anonymous public behavior.
4. Keep the documented Keycloak discovery path, omitted `jwks_uri`, `admin` approval method, required capability `location`, liveness endpoint, and describe-extension fields as explicitly documented extensions/non-core behavior.
