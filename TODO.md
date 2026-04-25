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

## Multi-tenancy — capability registry scoping

The spec is silent on how capabilities are scoped (only hint is §5.2's
"capabilities available to the host's linked user", with the filter
left to the implementation). Today the registry is realm-wide and only
realm admins can write. That's fine for single-tenant deployments;
breaks down the moment we want a realm to host multiple teams or
companies whose capabilities shouldn't bleed into each other.

- [ ] **Scope capabilities to Keycloak Organizations (KC 26.x+).**
  Add an `organization_id` column to `AGENT_AUTH_CAPABILITY` (nullable):

  - `NULL` → realm-wide capability. Registered by realm admins via
    the existing `POST /admin/realms/{r}/agent-auth/capabilities`.
    Visible to any authenticated caller in the realm. Preserves
    today's behavior.
  - Set → org-scoped capability. Registered via a new entry point
    (e.g. body field `organization_id`, or a new path
    `POST /admin/realms/{r}/organizations/{orgId}/agent-auth/capabilities`).
    Caller must hold `manage-organization` on that org. Visible only
    to members of that org.

  `/capability/list` filter, when caller identity is resolvable:

  ```
  WHERE organization_id IS NULL
     OR organization_id IN (orgs the caller belongs to)
  ```

  Caller's orgs come from Keycloak's `OrganizationProvider` keyed off
  the user that the host or agent is linked to (from §2.9 host linking
  → `host.user_id` → user's org memberships).

  This makes §5.2's "capabilities available to the host's linked user"
  precise: realm-wide caps + caps in orgs the linked user belongs to.

  **Why org-scoping and not user-scoping**: capabilities are owned by
  the *service* that runs the resource server, which is almost always
  a team / company, not a single user. A user-scoped registry would
  collapse to "personal orgs of one" in practice. Keycloak Organizations
  gives us membership, role-gated management, and token claims out of
  the box; we'd be reinventing them otherwise.

  **Tied to the typed-columns refactor above** — adding
  `organization_id` to a JSON-blob `PAYLOAD` doesn't help, because the
  `/capability/list` filter needs to be an indexed `WHERE` clause to
  avoid scanning every row. Do this *with* the typed-columns migration
  in one Liquibase changelog, not as a separate migration on top of
  the blob.

  Migration considerations:

  1. Existing rows get `organization_id = NULL` — preserves today's
     "realm-wide, registered by realm admin" behavior. No user-visible
     regression.
  2. Realm admins keep `manage-realm`-gated write access to NULL-org
     capabilities; org admins get `manage-organization`-gated write
     access scoped to their org_id.
  3. Cross-org isolation needs IT coverage: org A's caller must NOT be
     able to register/update/delete a capability with `organization_id
     = orgB`, even if they have `manage-organization` on org A.
  4. Discovery doc (`/.well-known/agent-configuration`) doesn't change
     — the per-caller filter is applied at `/capability/list` time.

  **Out of scope here**: per-user private capabilities. If someone
  genuinely needs them, they can model as a single-member org. Don't
  add a third dimension unless a real use case appears.

  Trigger to act on this: a deployment scenario where a realm hosts
  more than one tenant whose capabilities shouldn't be visible to the
  others. Until then realm-only is fine.
