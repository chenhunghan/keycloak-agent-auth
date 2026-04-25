# Agent Auth Protocol — Rust example

A minimal end-to-end walk-through of the AAP roles, in Rust, against the Keycloak instance `docker compose up` spins up.

This demo mirrors the flows covered by `AgentAuthFullJourneyE2E.java` in the main test suite, from the client side:

1. **Autonomous journey** — admin registers an auto-approved capability → agent registers in autonomous mode → active immediately → execute → introspect → revoke → post-revoke execute rejected → post-revoke introspect inactive.
2. **Delegated journey** — admin registers an approval-required capability → agent registers in delegated mode (pending) → admin approves the grant → active → execute → introspect → revoke → post-revoke execute rejected → post-revoke introspect inactive.

## What lives in each file

| File | Role | What it does |
|------|------|--------------|
| `src/client.rs` | **Client** (AAP §1.5) | Holds the Ed25519 host keypair. Mints `host+jwt` (§4.2) for register / status / revoke / introspect; mints `agent+jwt` (§4.3) for `/capability/execute` and introspect target. Only process speaking HTTPS to Keycloak. |
| `src/agent.rs` | **Agent** (AAP §2.1) | Stub for the AI reasoning loop. Holds no keys. Forwards tool invocations through the Client. |
| `src/rs.rs` | **Resource Server** core | Minimal `hyper`-based HTTP server hosting the capability's business logic. |
| `src/bin/rs.rs` | RS entrypoint | Boots the resource server on port 3000 inside docker compose. |
| `src/admin.rs` | Admin plumbing | Gets an admin OIDC token, `POST`s a capability definition, approves grants via the admin API. |
| `src/bin/demo.rs` | Wiring | Walks both journeys. |

## Run it

**Prereqs**: Rust 1.82+. The demo brings up its own stack (Keycloak + extension + resource server) via its own compose file:

```sh
cd examples/rust
docker compose up -d
```

`compose.yaml` uses `include:` to reuse the repo-root compose (Keycloak), then adds the resource server on the same compose network. Two services come up: `keycloak` (published at `localhost:28080`) and `resource-server` (reachable as `resource-server:3000` from inside the network only; not published to the host).

> If your Docker Compose is older than 2.20 (no `include:` support), run both files explicitly:
> ```sh
> docker compose -f ../../docker-compose.yml -f compose.yaml up -d
> ```

Wait ~15 s for Keycloak to boot:

```sh
curl -sf http://localhost:28080/realms/master/agent-auth/health
# → {"status":"ok","provider":"agent-auth"}
```

Then:

```sh
cargo run --bin demo
```

Expected tail of output:

```
=== autonomous journey (capability: greet_autonomous_XXXXXXXX) ===
1. admin registers capability (requires_approval=false)
2. agent registers (mode=autonomous)
   agent_id=...  status=active
3. execute via gateway
[Agent XXXXXXXX…] invoke greet_autonomous_XXXXXXXX({"name":"autonomous"})
   backend returned: "Hello, autonomous!"
4. introspect
   active=true
5. revoke
6. post-revoke execute (expected: rejected)
   status=403
7. post-revoke introspect (expected: active=false)
   active=false
autonomous journey: OK

=== delegated journey (capability: greet_delegated_XXXXXXXX) ===
...
delegated journey: OK

All journeys: OK
```

## Knobs

| Env var | Default | Meaning |
|---------|---------|---------|
| `KC_BASE` | `http://localhost:28080` | Keycloak base URL |
| `KC_REALM` | `master` | Realm to use |
| `KC_ADMIN_USER` | `admin` | Admin user for capability registration |
| `KC_ADMIN_PASS` | `admin` | Admin password |
| `RS_LOCATION` | `http://resource-server:3000/exec/greet` | Capability location URL (as Keycloak sees it) |

## What this deliberately does NOT cover

Same scope as `examples/js`: gateway-mode execution only, no host-key persistence, no device-flow approval (admin path used for delegated journey), no key rotation.
