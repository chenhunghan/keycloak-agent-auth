# Browser / End-User Approval Endpoint Spec Audit

## Scope

This audit covers the documented browser/end-user approval endpoints in
`/Users/chh/keycloak-agent-auth`:

- `GET /realms/{realm}/agent-auth/verify`
- `POST /realms/{realm}/agent-auth/verify`
- `POST /realms/{realm}/agent-auth/verify/approve`
- `POST /realms/{realm}/agent-auth/verify/deny`
- `GET /realms/{realm}/agent-auth/inbox`

The normative source is only the Agent Auth Protocol v1.0-draft:
https://agent-auth-protocol.com/specification/v1.0-draft

`README.md` was used only for endpoint inventory and to identify explicitly
documented implementation rationale. Integration tests were not used as source
of truth.

## Spec Baseline

- Section 5.3 registration: when approval is required, the response includes an
  approval object; pending grants include only `capability` and `status`; the
  user may partially approve capabilities; denial is reflected per grant; a
  fully denied registration still results in an active agent identity with
  denied/empty grants. The `reason` field is displayed to the user on approval
  screens.
- Section 5.4 capability request: the agent remains `active`; only new grant
  statuses change; if any new grant is pending, the response includes an
  approval object and the client polls `GET /agent/status`.
- Section 5.6 reactivation: expired agents may return to `pending` when default
  capability re-granting requires approval, and the client polls status until
  approval completes or expires.
- Section 7 approval methods: the core protocol defines approval objects, not
  browser approval endpoints. All approval methods include `method`,
  `expires_in`, and `interval`; `device_authorization` additionally requires
  `verification_uri` and `user_code`, with optional
  `verification_uri_complete`; CIBA uses server notification and has
  implementation-defined user approval/listing surfaces.
- Section 7.1 device authorization: users authenticate and approve at the
  verification URL; clients poll status until `active`, `rejected`, or expiry.
  User denial is terminal for that registration attempt.
- Section 7.2 CIBA: the server notifies the user through email/push/SMS/in-app
  or similar; the user-facing approve/deny/list surfaces are not protocol
  endpoints, but must still complete the normative approval flow.
- Sections 7.3-7.5: polling is the core baseline; real-time notification and
  custom approval methods are extensions; servers select the approval method and
  may ignore client preference.
- Section 8.10 approval gravity: first-time host approval is a high-risk trust
  boundary; requested capabilities must be clear; attacker-controlled display
  fields such as `name`, `reason`, `host_name`, and `binding_message` must be
  sanitized and not rendered as trusted content.
- Section 8.11 approval self-authorization: approval pages and CIBA approvals
  must require fresh user authentication before completing approval; long-lived
  session cookies alone are insufficient. Write/action-capable approval must use
  proof of physical presence or an out-of-band channel.
- Section 10.9: pending agents should be cleaned up after a server-defined
  threshold.
- Section 10.10: extension profiles are outside the core interoperability
  surface and should be explicitly documented when clients/servers depend on
  them.

## Findings

### P1: Approval completion accepts any valid user token without enforcing fresh authentication

- Endpoint: `POST /realms/{realm}/agent-auth/verify`,
  `POST /realms/{realm}/agent-auth/verify/approve`,
  `POST /realms/{realm}/agent-auth/verify/deny`
- Spec: https://agent-auth-protocol.com/specification/v1.0-draft#811-approval-self-authorization
- Code:
  `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:2898`
  and
  `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:3038`
- Current behavior: `transitionPendingAgent` authenticates a bearer realm-user
  token and rejects service accounts, but it does not enforce an `auth_time`
  freshness window before approving or denying. The browser page redirects to
  Keycloak login only when no identity cookie is present, and the POST path
  relies on token validity rather than recent authentication.
- Expected behavior: completing approval or denial should require fresh user
  authentication for both device-authorization and CIBA approval completions.
  A long-lived token or session cookie should not be enough. Existing
  proof-of-presence logic for write-capable grants is useful but does not
  replace the general freshness requirement.
- Rationale: Agent Auth treats browser/session self-authorization as a core
  threat. An agent with browser or notification access can replay an old session
  or token unless the approval completion path checks recency.
- Concrete fix steps:
  1. Add a fresh-auth helper that reads `auth.token().getAuthTime()` or the
     Keycloak session timestamp and rejects tokens older than a short server
     policy window, for example 5 minutes.
  2. Apply that helper before both approve and deny transitions, including the
     `agent_id` CIBA path.
  3. Update the browser login redirect to request freshness, for example with
     `max_age=0` or an operator-configurable `max_age`, so the form naturally
     leads to a fresh token.
  4. Keep the existing service-account rejection and write-capable
     proof-of-presence check.

### P1: CIBA email deep links point to a browser page that cannot process `agent_id`

- Endpoint: `GET /realms/{realm}/agent-auth/verify` and
  `POST /realms/{realm}/agent-auth/verify`
- Spec: https://agent-auth-protocol.com/specification/v1.0-draft#72-ciba-client-initiated-backchannel-authentication
- Code:
  `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/notify/CibaEmailNotifier.java:167`,
  `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:2604`,
  and
  `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:2811`
- Current behavior: the CIBA notifier emails
  `/realms/{realm}/agent-auth/verify?agent_id=...`, but `verifyPage` only reads
  `user_code`, and the HTML form/submit handler only posts `user_code`. The
  lower-level transition helper can approve by `agent_id`, but the browser page
  never passes `agent_id` through.
- Expected behavior: the implementation-defined CIBA approval UI should route a
  notified linked user to an actionable approve/deny surface. The current inbox
  fallback can still work, but the documented email deep link does not.
- Rationale: Section 7.2 leaves the UI path to the server, but the server still
  must deliver a usable user approval channel when it chooses CIBA. README also
  explicitly documents CIBA email plus `/inbox` fallback as intended behavior.
- Concrete fix steps:
  1. Add `@QueryParam("agent_id")` to `verifyPage`.
  2. Allow `verifyPage` to load a pending approval by `agent_id`, render the
     same approval form, and include hidden `agent_id` when no `user_code`
     exists.
  3. Add `@FormParam("agent_id")` to `verifyFormSubmit` and pass it through to
     `transitionPendingAgent`.
  4. Preserve the existing owner check in `transitionPendingAgent` for
     `agent_id` approvals; avoid leaking details before a fresh authenticated
     approver is established.
  5. Alternatively, change the notifier link to the documented inbox route and
     make the email copy explicit that approval happens from the inbox.

### P2: The approval HTML does not show enough requested authority for informed approval

- Endpoint: `GET /realms/{realm}/agent-auth/verify`
- Spec:
  https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration
  and
  https://agent-auth-protocol.com/specification/v1.0-draft#810-approval-gravity
- Code:
  `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:2669`
- Current behavior: the page renders host ID and agent name, then asks the user
  to approve or deny. It does not render requested capability names,
  descriptions, constraints, `reason`, `host_name`, or CIBA `binding_message`.
  It escapes the displayed strings it does render, which is good, but it does
  not limit display-field length at render time.
- Expected behavior: approval screens should clearly present the requested
  capabilities and request context. Section 5.3 says `reason` is displayed to
  the user on approval screens; section 8.10 says first-time host approval is
  high risk and requested capabilities must be presented clearly. All
  attacker-controlled display fields should be sanitized, length-limited, and
  treated as untrusted text.
- Rationale: Without the actual grants and request reason, users cannot make
  the partial/full approval decision the protocol models. The current screen
  also undercuts the approval gravity guidance for unknown host registration.
- Concrete fix steps:
  1. Render pending grants from `agent_capability_grants`, including capability
     descriptions from the registry where available.
  2. Render the stored request `reason`, `host_name`, and CIBA
     `binding_message` when present.
  3. Apply a shared display sanitizer that escapes, strips control characters,
     and caps length before HTML output.
  4. Consider extending the form to support partial approval by sending the
     approved `capabilities` subset to `transitionPendingAgent`, since the
     helper already supports subset approval.

### P3: `GET /inbox` does not reject service-account tokens

- Endpoint: `GET /realms/{realm}/agent-auth/inbox`
- Spec: https://agent-auth-protocol.com/specification/v1.0-draft#72-ciba-client-initiated-backchannel-authentication
- Code:
  `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:3246`
- Current behavior: `inbox` authenticates a bearer token and lists pending
  approvals for `auth.user().getId()`, but unlike approval completion it does
  not reject `auth.user().getServiceAccountClientLink() != null`.
- Expected behavior: the inbox is a user-facing CIBA approval surface and should
  be limited to real realm users, consistent with the documented endpoint
  inventory and the approval completion path.
- Rationale: Approval completion is protected from service accounts, but inbox
  listing can still expose pending approval metadata to a non-human principal if
  a service-account user is linked to hosts or otherwise appears in host user
  mappings.
- Concrete fix steps:
  1. Add the same service-account rejection used in `transitionPendingAgent`.
  2. Return `403 user_required` with the existing message style.
  3. Keep approval completion as the final authority check.

### P3: Approval and pending-grant `status_url` fields are non-core and not explicitly documented as extensions

- Endpoint: approval object consumed by the scoped browser flow; affects
  `GET /verify` users indirectly through the approval flow returned by
  registration, capability request, and reactivation.
- Spec:
  https://agent-auth-protocol.com/specification/v1.0-draft#7-approval-methods
  and
  https://agent-auth-protocol.com/specification/v1.0-draft#1010-extension-profiles
- Code:
  `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:3492`,
  `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:3507`,
  and
  `/Users/chh/keycloak-agent-auth/src/main/java/com/github/chh/keycloak/agentauth/AgentAuthRealmResourceProvider.java:568`
- Current behavior: `buildCibaApprovalObject` and
  `buildDeviceAuthApprovalObject` include `approval.status_url`, and pending
  grants sometimes include per-grant `status_url`.
- Expected behavior: core approval polling is communicated by `interval` and
  `GET /agent/status`; pending grants are specified as compact
  `{ capability, status }`. Unknown response fields are generally survivable,
  but this shape is not part of the core approval schema and is not documented
  as a server extension in README.
- Rationale: This is likely a compatibility/documentation issue rather than a
  runtime security bug. Section 10.10 says extension profiles are outside core
  interoperability and should be explicitly documented if clients/servers depend
  on them.
- Concrete fix steps:
  1. Decide whether `status_url` is meant to be supported client surface.
  2. If yes, document it as a server-defined response extension and clarify that
     core clients should still poll `GET /agent/status` using `interval`.
  3. If no, remove `approval.status_url` and pending-grant `status_url` from
     response shapes while keeping internal routing unchanged.

## Action Plan

1. Fix the approval completion freshness check first. This is the clearest
   normative security gap because section 8.11 says fresh authentication is
   mandatory for approval completion.
2. Repair the CIBA browser deep-link path so email notifications land on an
   actionable approval/denial page, or change the notifier to send users to the
   inbox explicitly.
3. Upgrade the approval page content so users see requested capabilities,
   request reason, host display name, constraints, and CIBA binding message with
   safe text rendering.
4. Harden `/inbox` by rejecting service accounts.
5. Either document or remove the non-core `status_url` response fields.

Positive notes from the reviewed code:

- `POST /verify/approve` and `/verify/deny` require a bearer access token and
  reject service accounts.
- `agent_id` approvals are owner-gated to the linked host user.
- Denial of a pending registration is terminal for that attempt and subsequent
  approval resolves to `410`.
- Approval expiry is enforced using the persisted approval issue timestamp.
- The browser form uses HTML escaping for rendered fields and has a double-submit
  CSRF guard for cookie-style submissions.
