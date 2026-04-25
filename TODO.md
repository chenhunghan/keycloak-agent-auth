# TODO

Living list of things we want to come back to. Each item carries enough context to start work without re-discovering why it's here.

## Storage

- [ ] **Replace JSON-blob payload storage with proper typed columns.**
  Today every entity in `storage/jpa/` (`HostEntity`, `AgentEntity`,
  `CapabilityEntity`, `RotatedHostEntity`) keeps four typed columns
  (`ID` / `STATUS` / `CREATED_AT` / `UPDATED_AT`) plus a `PAYLOAD TEXT`
  that holds the full record as a JSON blob. That was the right call to
  ship the JPA migration quickly — adding optional fields is a
  zero-migration change — but it has real costs:

  - Cannot index, sort, or filter on any field that lives inside the
    blob (e.g. "list capabilities by visibility", "find agents by host
    user_id", "find capabilities pointing at a given location URL").
  - Cannot enforce referential integrity (e.g. agent → host FK,
    grant → capability FK).
  - Constraint checks (`max` / `min` / `in` on a grant) require parsing
    JSON every execute call instead of reading column values.
  - Multi-tenancy is awkward — `CapabilityEntity` has no realm column
    today, so the registry is global. A normalised schema would make
    realm scoping a one-line addition rather than a JSON migration.

  The replacement is the obvious normalised shape:

  - `AGENT_AUTH_HOST(host_id PK, public_key_jwk, jwks_url, jwks_kid,
    user_id FK, status, created_at, updated_at, last_used_at, …)`
  - `AGENT_AUTH_AGENT(agent_id PK, host_id FK, user_id, mode,
    name, status, public_key_jwk, jwks_url, jwks_kid,
    activated_at, expires_at, …)`
  - `AGENT_AUTH_AGENT_GRANT(agent_id FK, capability_name FK,
    status, granted_by, constraints_json, …)` — promote grants from
    nested array to a real join table; `constraints_json` can stay TEXT.
  - `AGENT_AUTH_CAPABILITY(name PK, realm_id, description, location,
    visibility, requires_approval, auto_deny, default_grants_json,
    input_schema_json, output_schema_json, …)`
  - `AGENT_AUTH_ROTATED_HOST(old_host_id PK, new_host_id FK,
    rotated_at)` — already mostly normalised; just confirm shape.

  Migration plan (rough sketch):

  1. New Liquibase changeset adds the typed columns next to the
     existing `PAYLOAD` column on each table.
  2. One-shot Java migration changeset reads `PAYLOAD`, populates the
     new columns, leaves the blob in place.
  3. Update `JpaStorage` reads/writes to use the typed columns; keep
     blob writes for one release as a safety net.
  4. Final changeset drops the `PAYLOAD` column.

  Don't tackle this until either an indexed query or referential
  integrity becomes painful — both are visible features (admin UI,
  multi-tenant), so the trigger will be obvious. Until then the blob
  is fine.

  **Scheduling note (2026-04-25):** the multi-tenant authz plan below
  splits this entry across Phase 3 (agent grants → join table — needed
  for efficient cascade queries) and Phase 6 (remaining typed columns
  + real FKs). Phase 4's eager cascade on org-membership changes is
  the trigger that makes the agent-grants table painful to keep as a
  blob; that's when this work starts in earnest.

## §5.2 capability listing — spec gaps

- [ ] **Reconcile the §5.2 host-defaults filter with Phase 1's user-
  entitlement gate.** The current §5.2 filter narrows the
  authenticated-visibility view for verified host JWTs from linked
  hosts to those caps in `host.default_capability_grants` — a host-
  scoped pre-approval. Phase 1 of the multi-tenant authz plan below
  adds a user-entitlement gate (`org_id` + `required_role`) that
  filters by the spec's "capabilities available to the host's linked
  user" wording. After Phase 1 ships, decide whether to keep the
  host-defaults filter as additional narrowing (defensible: "what this
  host has pre-approved") or remove it (the user-entitlement gate is
  the spec-aligned answer). Either is defensible; pick one and document.

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

5. **Phase 5 — Org-admin self-service + SA-as-host pattern.** New
   admin endpoints scoped under
   `/admin/realms/{realm}/organizations/{orgId}/capabilities`,
   mintable by `manage-organization` holders (org_id derived from
   path, never request body). Document the recommended SA-per-
   confidential-client pattern; admin endpoint to register an
   autonomous host with an SA owner.

6. **Phase 6 — Remaining storage normalization.** Folds the existing
   "Storage" entry above. Typed columns on host/agent/capability,
   real FKs from agent-auth tables to `KEYCLOAK_REALM`,
   `KEYCLOAK_USER`, `KEYCLOAK_ORG`, drop JSON blobs. Defense-in-depth
   layer: integrity now enforced at the data layer, not just app code.

### Open implementation items

- Confirm the KC Organizations API surface (`OrganizationProvider`
  membership-lookup call shape, availability on `provided`-scope
  `keycloak-server-spi`). Phase 1 needs this for the listing filter.
- Multi-org test fixture pattern — programmatic org creation +
  membership via admin REST, reusable across the phase ITs.
- After Phase 1 ships, decide whether to keep the §5.2 host-defaults
  filter as additional narrowing or remove it (see the §5.2 entry
  above).
