# TODO

Living list of things we want to come back to. Each item carries enough context to start work without re-discovering why it's here.

## Storage

- [x] **Replace JSON-blob payload storage with proper typed columns.**
  ✅ Shipped 2026-04-25 across Phases 3 (agent grants → join table)
  and 6a/6b/6c (capability/host/agent typed columns) of the multi-
  tenant authz plan below. PAYLOAD blob columns dropped from all four
  agent-auth tables. Real FKs to KC's KEYCLOAK_REALM/KEYCLOAK_USER/
  KEYCLOAK_ORG are still soft string references; see Phase 6's
  "Outstanding" note for why and when to revisit.

## §5.2 capability listing — spec gaps

- [x] **Reconcile the §5.2 host-defaults filter with Phase 1's user-
  entitlement gate.** Resolved 2026-04-26: removed the host-defaults
  filter from `/capability/list`. The listing view is now gated solely
  by the Phase 1 user-entitlement check (`org_id` + `required_role` on
  cap vs the linked user's KC org/roles), which is the spec-aligned
  reading of §5.2's "capabilities available to the host's linked user."
  `host.default_capability_grants` is preserved for the reactivation
  flow (`buildReactivationGrants`) — it stays a meaningful host-scoped
  concept, just not a list-time narrowing. The two-layer model was
  confusing for API consumers and the spec wording leans single-layer.

## Multi-tenant AAP ↔ Keycloak authorization integration

> **Status:** committed plan, phased delivery. Promoted from a design
> draft on 2026-04-25 after walking a concrete deployment scenario:
> 3 customer orgs in one Keycloak realm with isolated capability
> registries. The seven design questions Q1–Q7 each resolved cleanly
> under that scenario. The git history before that date preserves the
> draft's full options analysis if anyone wants to see what was
> considered.

### Scenario

3 customer orgs (e.g. Acme, Globex, Initech) coexist in one Keycloak
realm. Each org has its own capability registry — Acme caps invisible
to non-Acme users. Each user belongs to one or more orgs. Hosts and
agents inherit a tenant boundary from their owner user.

### Three layers, three auth modes (orientation)

Every AAP-related call decomposes into three layers, and the layers
map onto Keycloak primitives differently:

| Layer | What it answers | Auth proof | Where the answer lives |
|---|---|---|---|
| **1. Cryptographic identity** | "who is the principal" (host, agent) | `host+jwt` / `agent+jwt`, signature checked against the JWT-embedded public key | AAP-only; KC identity tables not consulted. |
| **2. Resource access** | "may this principal touch this capability/host/agent" | derived from the principal → owner user → KC roles / groups / orgs | KC's identity tables, queried via FK. *This is the layer this plan is mostly about.* |
| **3. Runtime state** | "is the principal in the right state right now" | status flags, grants, constraints | AAP runtime tables. |

Three corresponding auth modes in play across the protocol surface:

- **AAP cryptographic** (`host+jwt`, `agent+jwt`) on the protocol-side endpoints.
- **KC user OIDC** on `/verify/approve` and `/verify/deny` — the user IS the bearer, identity is direct.
- **KC admin OIDC + role** on the admin API — `manage-realm` for realm-wide ops, `manage-organization` for org-scoped (Phase 5).

Today the impl does layer 1 and layer 3 well. The phased plan below
makes layer 2 load-bearing — the principal → user link gates who can
be granted what via KC role and organization mappings.

### Decisions

| Q | Decision | Why |
|---|---|---|
| **Q1** FK coupling | Real FKs on `realm_id`, `user_id`, `organization_id` (where set) | Tenant isolation is a security boundary; integrity must be data-layer-enforced — soft refs lose to a single missing `WHERE org_id = ?`. |
| **Q2** Host owner mandatory | Yes, always; autonomous hosts use a service-account user | A host without a user has no tenant — "Globex's host" stops being meaningful under multi-tenancy. |
| **Q3** Gate primitive | KC Organizations (tenant boundary) + KC Roles (intra-tenant gate) — combination | Native KC primitives. UMA is overkill; AAP-native ACL duplicates what KC already does. |
| **Q4** Cascade | Hybrid: eager on user-delete + org-membership changes; lazy on role changes | Org changes move the tenant boundary (eager-worthy); role drift acceptable until execute time. |
| **Q5** SA mapping | One SA per confidential client; client belongs to one org | Fleet-level tenant attribution. Per-host SA gives unnecessary granularity; per-realm SA crosses tenant boundaries. |
| **Q6** `/verify/approve` layer-2 check | Wire it (Phase 2) | Without it, users can be tricked into approving cross-tenant caps — a tenant-boundary violation, not just permissiveness. |
| **Q7** Capability registration | Realm-admin + org-admin self-service | Tenants own their schema; realm-admin handles platform-wide caps. |

### Sub-decisions

**Realm-wide caps (`organization_id IS NULL`).** Visible to all
authenticated users in the realm. Composition with `visibility`:

| visibility × org_id | Visible to |
|---|---|
| `public`, NULL | anonymous + everyone |
| `public`, set | anonymous (org filter is skipped without an identity) |
| `authenticated`, NULL | any authenticated user |
| `authenticated`, set | only authenticated org members |

Org gating applies only to authenticated callers — there's no identity
to org-match against for anonymous traffic, so `(public, set)` reduces
to "anonymous can see it." Only realm-admin can mint or edit NULL-org
caps; the org-admin endpoint derives `organization_id` from the
admin's scope and never accepts it from the request body. Migration
of existing caps is a no-op semantically — they're all NULL today,
which under this rule means "visible to all", matching today's
behavior.

**Cross-org users at grant time.** No "justifying_org" column on
grants — the cap's `organization_id` is the source of truth.
Authorization is `(cap.org_id ∈ user.orgs at evaluation time) AND
(cap.required_role ⊆ user.roles at evaluation time)`. If Alice is in
both Acme and Globex, she has access to both registries; if she
later leaves Acme, grants for `org_id=Acme` caps cascade-revoke (Q4
eager) regardless of when they were created. Lazy re-check of role
drift happens at `/agent/introspect` — the response strips grants
whose cap fails the gate against current user state.

### Phased delivery

Phases 1–4 are the multi-tenancy MVP — ✅ all shipped 2026-04-25.
The tenant boundary is now enforced end-to-end: visibility (Phase 1),
approval and lazy re-eval (Phase 2), grants index (Phase 3), eager
cascade (Phase 4). Phases 5–6 are quality-of-life and still pending.

1. **Phase 1 — Capability schema + listing filter.** ✅ Shipped
   2026-04-25. Added `organization_id` and `required_role` to the
   capability payload (JSON-blob fields, no Liquibase migration).
   Realm-admin write endpoints accept and validate the new fields.
   `/capability/list` and `/capability/describe` apply the gate when
   the caller is authenticated; describe returns 404 (not 403) on
   gate failure to avoid leaking the cap's existence. Test fixture
   uses KC native Organizations (feature flag enabled in
   `TestcontainersSupport`, realm-level toggle in the test realm
   import).

2. **Phase 2 — Approval-time + introspect-time enforcement.** ✅
   Shipped 2026-04-25. `/verify/approve` now layer-2-checks each
   pending grant against the approver's KC entitlement; gate-failed
   grants flip to `status=denied` with `reason=insufficient_authority`
   (mirroring the existing partial-approval shape, but distinguishing
   the cause from `user_denied` for audit/UI). `/agent/introspect`
   now lazy-re-evaluates the gate against the agent's user on every
   call, stripping grants whose cap fails the current entitlement —
   the lazy half of Q4's hybrid cascade. Eager cascade on
   org-membership changes still owed by Phase 4.

3. **Phase 3 — Grant join table (storage refactor, scoped).** ✅
   Shipped 2026-04-25. Added `AGENT_AUTH_AGENT_GRANT(agent_id,
   capability_name, status, granted_by, reason, constraints_json,
   created_at, updated_at)` with composite PK + indexes on
   `(capability_name, status)` and `(agent_id, status)`. The blob
   nested in `AGENT_AUTH_AGENT.PAYLOAD` remains the source of truth
   for application reads — the new table is a sync-on-write secondary
   index that `JpaStorage.putAgent` maintains via delete-and-replace
   on every save. `deletePendingAgentsOlderThan` cascades the bulk
   delete to grants. New `findGrantsByAgent` SPI method exposes the
   table; admin endpoint `GET /agents/{id}/grants` lets ITs verify
   the sync. Phase 4's eager cascade and future Phase 6 read-path
   swaps will query this table directly.

4. **Phase 4 — Eager cascade on org-membership change.** ✅ Shipped
   2026-04-25. `AgentAuthUserEventListenerProviderFactory.postInit`
   now also subscribes to `OrganizationModel.OrganizationMemberLeave
   Event` (KC's native ProviderEvent). When a user leaves an org, the
   handler walks their agents (via the new `findAgentsByUser` SPI
   method backed by the indexed `AGENT_AUTH_AGENT.USER_ID` column),
   inspects each `active` grant's cap, and marks grants whose
   `organization_id` matches the removed org as `revoked` with
   `reason=org_membership_removed`. Grants on other orgs (or
   NULL-org caps) untouched. Phase 3's secondary index syncs on the
   resulting `putAgent`. With Phase 2's lazy re-eval at introspect
   on role drift, this completes Q4's hybrid cascade.

5. **Phase 5 — Org-admin self-service + SA-as-host pattern.** ✅
   Shipped 2026-04-25. Added four org-scoped admin endpoints under
   `/admin/realms/{realm}/agent-auth/organizations/{orgId}/capabilities`
   (POST, GET list, PUT, DELETE). `organization_id` is taken from the
   path — body is overridden, preventing tenant-confusion writes.
   Auth gate (`requireOrgAdmin`) accepts realm-admin (super-user) or
   `manage-organization` realm-management role + org membership;
   non-members hitting an org's endpoints get 403, missing orgs get
   404. Cross-org PUT/DELETE attempts get 404, never modifying the
   target. SA-as-host pattern landed via an optional `client_id`
   field on `POST /admin/.../hosts`: the endpoint resolves the
   confidential client's service-account user and stores it as the
   pre-registered host's `user_id`, so autonomous workloads can
   skip the post-claim approval flow. The recommended pattern is
   one SA per confidential client; operators provision the client
   with `serviceAccountsEnabled=true` and pass the client_id.

6. **Phase 6 — Remaining storage normalization.** ✅ Substages 6a/6b/6c
   shipped 2026-04-25 (no-migration path: pre-production codebase, no
   existing data). Typed columns now everywhere; PAYLOAD blob columns
   dropped from AGENT_AUTH_CAPABILITY (6a), AGENT_AUTH_HOST (6b),
   AGENT_AUTH_AGENT (6c). Round-trip is via per-entity {entity}ToMap +
   apply{Entity}Fields helpers in JpaStorage; null columns are omitted
   from the projected map so unset fields preserve "absent vs explicit
   null" JSON semantics. Indexed ORGANIZATION_ID and REQUIRED_ROLE on
   capability make Phase 1's filter and Phase 4's cascade SQL-efficient
   (previously in-Java scans of all caps). Phase 6c also added a
   "skip grants-table sync when grants array unchanged" optimization
   to avoid lock contention when a long-running streaming proxy holds
   a transaction concurrently with revoke.

   **Outstanding (deferred to a future phase if pain emerges):** real
   FKs from agent-auth tables to KEYCLOAK_REALM, KEYCLOAK_USER,
   KEYCLOAK_ORG. Data-layer referential integrity is still enforced
   only at the application level (cascade listeners + soft
   string-string lookups). Adding KC FKs would require declaring our
   Liquibase changesets to depend on KC's, which is fragile across KC
   version bumps. Keep soft for now; revisit if a stale-id orphan bug
   shows up.

### Open implementation items

- Confirm the KC Organizations API surface (`OrganizationProvider`
  membership-lookup call shape, availability on `provided`-scope
  `keycloak-server-spi`). Phase 1 needs this for the listing filter.
- Multi-org test fixture pattern — programmatic org creation +
  membership via admin REST, reusable across the phase ITs.
- After Phase 1 ships, decide whether to keep the §5.2 host-defaults
  filter as additional narrowing or remove it (see the §5.2 entry
  above).
