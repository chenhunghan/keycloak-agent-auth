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
