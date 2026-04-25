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

## §5.2 capability listing — spec gaps

- [ ] **Host-JWT capability listing should filter by the host's linked user.**
  Spec §5.2: a host JWT on `/capability/list` should return "capabilities
  available to the host's linked user. Used before agent registration."
  Our `AgentAuthRealmResourceProvider.listCapabilities` accepts a host+jwt
  but returns the full union of public + authenticated capabilities,
  with no consideration of `host.user_id` or the host's
  `default_capability_grants`. Once host linking landed (§2.9, commit
  78760f6) the substrate for filtering is now in place — needs to be
  wired in. Behavior today is more permissive than the spec, not less,
  so this is correctness/intent rather than user-visible breakage.

- [ ] **Verify the host+jwt signature on read-only discovery endpoints.**
  `listCapabilities` currently treats `typ=host+jwt` as authenticated
  on a header-tag check alone — no signature verification, no host
  lookup. The agent+jwt branch right above does full verification. The
  asymmetry was deliberate (read-only discovery has a low security bar)
  but it means anyone can craft a `host+jwt`-typed unsigned token and
  see every `authenticated`-visibility capability. Tighten the host+jwt
  branch to at least parse `host_public_key`, verify the signature, and
  confirm `iss` matches the JWK thumbprint. Same fix applies to
  `describeCapability` (line 1746+) which inherits the same loose check.

- [ ] **Non-spec `?visibility=authenticated` query param on
  `/capability/list`.** We accept this and use it to force a 401 if the
  caller is unauthenticated. Spec §5.2 doesn't define it. If we want to
  claim verbatim spec compliance, either drop it or move it under a
  vendor-prefixed namespace. Behaviour is invisible to spec-conforming
  clients, so low priority — but worth deciding.

## DRAFT — AAP ↔ Keycloak authorization integration

> **Status: design draft, not a plan.**
> This section is a record of the open questions we've discussed but
> not settled. Nothing here is a committed work item — the bullets
> describe options, not decisions. The "Storage" typed-columns refactor
> and the "§5.2 capability listing — spec gaps" entries above are
> foundational regardless of how any of this resolves; treat them as
> independent. We need more discussion (and probably a concrete
> deployment scenario) before promoting any of this draft into a
> committed plan.

### Framing — three layers, three auth modes

Every AAP-related call decomposes into three layers, and the layers
map onto Keycloak primitives differently:

| Layer | What it answers | Auth proof | Where the answer lives |
|---|---|---|---|
| **1. Cryptographic identity** | "who is the principal" (host, agent) | `host+jwt` / `agent+jwt`, signature checked against the JWT-embedded public key | AAP-only; KC identity tables not consulted. |
| **2. Resource access** | "may this principal touch this capability/host/agent" | derived from the principal → owner user → KC roles / groups / orgs | KC's identity tables, queried via FK. *This is the layer that's mostly unwritten today.* |
| **3. Runtime state** | "is the principal in the right state right now" | status flags, grants, constraints | AAP runtime tables. |

Three corresponding auth modes in play across the protocol surface:

- **AAP cryptographic** (`host+jwt`, `agent+jwt`) on the protocol-side endpoints.
- **KC user OIDC** on `/verify/approve` and `/verify/deny` — the user IS the bearer, identity is direct.
- **KC admin OIDC + role** on the admin API — `manage-realm` for realm-wide ops, `manage-organization` for org-scoped (proposed).

Today our impl does layer 1 and layer 3 well. The "fit into KC's authz
model" question is mostly about layer 2 — making the principal → user
link load-bearing so that role / group / org mappings naturally gate
who can be granted what.

### Open questions

Each of these blocks gates the design but doesn't have a settled
answer. Options are described, not endorsed.

#### Q1. How tightly should AAP entities couple to KC's schema?

- **Real foreign keys** into `KEYCLOAK_USER`, `KEYCLOAK_REALM`,
  optionally `KEYCLOAK_ORG`. Pro: indexed joins, native
  `ON DELETE CASCADE`, referential integrity. Con: hard schema
  coupling — if a future KC version renames a table we follow.
- **Soft references** (store user_id / realm_id as strings, integrity
  enforced by application code). Pro: portable, decouples AAP storage
  from KC schema evolution. Con: integrity bugs on app errors,
  joins are ad-hoc.
- **Mixed** — real FK on `realm_id` (we already depend on KC's per-
  realm SPI mounting), soft string for `user_id` (so AAP entities
  could in principle survive being lifted out of KC).

Worth deciding before any column-level work, since it's the call that
shapes the migration.

#### Q2. Must every host have an owner user?

- **Yes, always** — `host.user_id NOT NULL`, with autonomous hosts
  pointing at a Keycloak service-account user (existing KC primitive).
  Pro: every host is queryable through KC's identity model; cascade
  semantics are uniform; group/org membership flows transitively.
  Con: migration cost (existing unlinked hosts need an owner assigned).
- **No, owner is optional** — keep `host.user_id` nullable, accept
  that some hosts have no KC identity attached. Pro: simpler migration,
  matches AAP §2.7's "host MAY exist without any linked user". Con:
  layer 2 has to handle the "no user" case as a special path; admin
  UIs and audit reports degrade.
- **Yes for delegated, optional for autonomous** — middle ground that
  matches the spec's wording most literally.

This question gates almost everything else in this section, because
"who's the owner user" is what the rest of the layer-2 model hangs
off of.

#### Q3. Where does the gate for "user U is allowed to grant capability C" live?

This is the core architectural question. Today there's effectively no
gate: a user (or admin) approves anything they're asked to. Options:

- **KC realm/client roles** — capability gets a nullable
  `required_role` column; user must hold the role (directly or via
  group inheritance) to be granted. Pro: native KC primitive,
  operators already manage roles. Con: another column to model,
  role-name conventions need to be defined (e.g. `aap:cap:transfer_money`?).
- **KC organizations** — capability scoped to an org via
  `organization_id`; user must be a member to be granted. Pro: tenant
  isolation falls out for free. Con: not granular enough for "users
  in this org with the accountant role" — would need to combine with
  roles.
- **Combination** — both `organization_id` (multi-tenancy) and
  `required_role` (intra-tenant authorization) on capability; gate is
  `(org_id IS NULL OR user.orgs CONTAINS org_id) AND (required_role
  IS NULL OR user.roles CONTAINS required_role)`.
- **AAP-native ACL** — new tables (`AGENT_AUTH_CAP_ACL`) mapping
  capabilities to authorized users/groups directly. Pro: doesn't
  re-use KC primitives we might want to evolve separately. Con:
  parallel authz system to maintain alongside KC's.
- **UMA / Authorization Services** — capability as a UMA-protected
  resource, grants as permission tickets, KC's policy engine evaluates.
  Pro: maximum policy expressivity (time-based, JS, role aggregates).
  Con: heavyweight, opaque to most operators, two parallel token
  formats (UMA RPT vs AAP agent+jwt).

Currently leaning toward **combination of orgs + roles**. UMA looks
overkill for the access shape we have. AAP-native ACL would
double-work effort that KC already does. But this needs more thought
— specifically whether `required_role` is the right level of
abstraction or whether we want a richer policy hook.

#### Q4. What's the cascade on user-side changes?

When a user is deleted, has a role removed, or leaves an organization:

- **Strict cascade** — re-evaluate all that user's hosts/agents/grants;
  revoke anything no longer authorized. Pro: tight security model,
  promptness guarantees. Con: an event listener with potentially large
  blast radius; failure modes around partial cascades.
- **Lazy re-check** — keep grants in place, re-check authorization at
  introspect / execute time. Pro: simpler implementation, naturally
  consistent. Con: "I removed the role 5 minutes ago and the agent is
  still running" — security people hate this.
- **Hybrid** — strict cascade on user delete (per AAP §2.6's explicit
  obligation), lazy re-check on role / group / org membership changes.

#### Q5. Service-account-as-host-owner — what's the mapping unit?

If we go with Q2-yes (every host has a user), autonomous daemons need
a service-account user. Options:

- **One service account per autonomous host** — N hosts, N service
  accounts. Clearest audit trail.
- **One service account per client app** — confidential client like
  `acme-bank-mcp-client` has one SA, all hosts that client provisions
  share it. Less clutter, less granular revocation.
- **One service account per realm** ("system" user) — every unowned
  host points at it. Simplest migration, weakest audit.

Best answer probably depends on what operators actually deploy. We
should pick a recommended pattern and document it; don't need to
enforce it in code.

#### Q6. Should the `/verify/approve` (device-flow) endpoint enforce the layer-2 access check now?

Today any logged-in realm user can approve any pending agent's
requested grants — there's no "is this user allowed to grant this
capability" check. Options:

- **Wire it now** with whatever Q3 answer we settle on, even
  partially.
- **Wait for the full integration** — accept that today's behavior is
  permissive but functional; defer until we've thought through Q1–Q4.
- **Add a coarse interim gate** — e.g. just "user must be a member of
  the same realm as the host" (which is trivially true today but
  becomes meaningful if hosts ever become cross-realm-discoverable).

#### Q7. Organization-admin self-service for capability registration?

- **Realm-admin only** (today) — only `manage-realm` holders can
  write to the capability registry.
- **Plus org-admin for org-scoped capabilities** — `manage-organization`
  holders can write capabilities under their own `organization_id`,
  but only NULL-org capabilities still require realm-admin.
- **Plus user self-service for user-scoped capabilities** — collapses
  to single-member orgs anyway; not recommended.

Q7 effectively asks "are organizations real tenants in our model, or
just a visibility filter?" — if real tenants, they need write
authority over their own scope.

### One specific direction (also a draft)

The shape that's been kicking around in our discussion, written down
not as a recommendation but so we can argue about it:

- Q1: real FK on `realm_id`, real FK on `user_id`, real FK on
  `organization_id` where present.
- Q2: every host has a user (real or service-account).
- Q3: combination — `organization_id` + `required_role` columns on
  capability.
- Q4: hybrid cascade — strict on user delete, lazy on role/org changes.
- Q5: one service-account user per client app, picked at host
  pre-registration time.
- Q6: wire the layer-2 check at approval time once Q3 settles.
- Q7: realm-admin + org-admin-self-service.

If we pick that combination, the schema sketch from earlier discussion
becomes coherent (typed columns, `realm_id` everywhere, `user_id`
NOT NULL on host, `organization_id` + `required_role` on capability,
`AGENT_AUTH_AGENT_GRANT` as a real join table). But each Q's choice
ripples — answering them differently changes the schema and the
runtime checks.

### What we'd need before promoting any of this to a plan

- A concrete deployment scenario that pushes the design (e.g., "we
  want to onboard 3 customer orgs into one realm and need their
  capability registries isolated").
- A decision on Q1 (FK vs. soft) — everything else is contingent.
- A decision on Q2 (host ownership requirement) — gates Q4 and Q5.
- A decision on Q3 (the gate primitive) — gates Q6 and Q7.
- An IT story that covers cross-tenant isolation, role-revocation
  cascade, and service-account host ownership.

Until those are answered, the existing committed items above (typed
columns, §5.2 spec gaps) are the right next steps — they're useful
no matter which way Q1–Q7 land.
