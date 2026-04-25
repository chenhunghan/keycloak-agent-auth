# Agent Auth Protocol — Go example

A minimal end-to-end walk-through of the AAP roles, in Go, against the Keycloak instance `docker compose up` spins up.

This demo mirrors the flows covered by `AgentAuthFullJourneyE2E.java` in the main test suite, from the client side — same steps, same assertions as the TypeScript example under `../js/`:

1. **Autonomous journey** — admin registers an auto-approved capability -> agent registers in autonomous mode -> active immediately -> execute -> introspect -> revoke -> post-revoke execute rejected -> post-revoke introspect inactive.
2. **Delegated journey** — admin registers an approval-required capability -> agent registers in delegated mode (pending) -> admin approves the grant -> active -> execute -> introspect -> revoke -> post-revoke execute rejected -> post-revoke introspect inactive.

## What lives in each file

| File | Role | What it does |
|------|------|--------------|
| `internal/client/client.go` | **Client** (AAP §1.5) | Holds the host keypair. Mints `host+jwt` (§4.2) for register / status / revoke / introspect; mints `agent+jwt` (§4.3) for `/capability/execute` and introspect target. The only process that speaks HTTP to Keycloak. |
| `internal/agent/agent.go` | **Agent** (AAP §2.1) | Stub for the AI reasoning loop. Does NOT hold keys, does NOT call Keycloak directly. Forwards tool invocations through the Client. |
| `internal/rs/rs.go` | **Resource Server** core | Minimal `net/http` server hosting the capability's business logic. |
| `cmd/rs/main.go` | RS entrypoint | Boots the resource server on `$PORT` inside docker compose. |
| `internal/admin/admin.go` | Admin plumbing | Gets an admin OIDC token, `POST`s a capability definition, approves grants via the admin API. |
| `cmd/demo/main.go` | Wiring | Walks both journeys. |

## Run it

**Prereqs**: Go 1.23+. The demo brings up its own stack (Keycloak + extension + resource server) via its own compose file — the root compose stays focused on just Keycloak, so switch into this directory first:

```sh
cd examples/go
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
# -> {"status":"ok","provider":"agent-auth"}
```

Then:

```sh
cd examples/go
go run ./cmd/demo
```

Expected tail of output:

```
=== autonomous journey (capability: greet_autonomous_XXXXXXXX) ===
1. admin registers capability (requires_approval=false)
2. agent registers (mode=autonomous)
   agent_id=...  status=active
3. execute via gateway
[Agent XXXX…] invoke greet_autonomous_XXXXXXXX({"name":"autonomous"})
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
1. admin registers capability (requires_approval=true)
2. agent registers (mode=delegated) → expect pending
   agent_id=...  status=pending
3. admin approves grant
   agent status=active
4. execute via gateway
...
delegated journey: OK

All journeys: OK
```

## The round-trip, annotated

```
Agent (stub)
  │  InvokeTool("greet_*", {name})
  ▼
Client
  │  mint agent+jwt (iss=thumbprint(hostPub), sub=agent_id,
  │  aud=http://localhost:28080/.../capability/execute,
  │  typ=agent+jwt, alg=EdDSA, exp=+60s)
  │  POST /capability/execute
  ▼
Keycloak (this extension)
  │  verify agent+jwt, look up agent, run constraint checks
  │  proxy to capability.location (= http://resource-server:3000/...)
  ▼
Resource Server (compose service)
  │  execute business logic
  │  return {data: {greeting: "Hello, ..."}}
  ▲
Keycloak  streams the response back unchanged
  ▲
Client    unwraps, returns to Agent
  ▲
Agent     prints
```

## What this deliberately does NOT cover

- **Persisting the host key** — a real Client stores it on disk / Keychain / Secrets Manager. This demo regenerates it per run.
- **Device-flow approval** — approval-required grants are approved by an *admin* here for brevity. The extension also supports AAP §7.1 device_authorization; see `AgentAuthDeviceApprovalIT.java`.
- **Direct-mode execution** — the Client posting to `capability.location` itself and the RS calling `/agent/introspect`. Gateway mode was picked for minimum moving parts.
- **Key rotation and reactivation** — covered by the Java IT suite.
- **Multiple agents under one host** — trivial to add (call `RegisterAgent` again).

## Knobs

| Env var | Default | Meaning |
|---------|---------|---------|
| `KC_BASE` | `http://localhost:28080` | Keycloak base URL |
| `KC_REALM` | `master` | Realm to use |
| `KC_ADMIN_USER` | `admin` | Admin user for capability registration |
| `KC_ADMIN_PASS` | `admin` | Admin password |
| `RS_LOCATION` | `http://resource-server:3000/exec/greet` | Capability location URL (as Keycloak sees it) |
