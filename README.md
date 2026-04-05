# Keycloak Agent Auth Protocol Extension

A Keycloak extension implementing the [Agent Auth Protocol](https://agent-auth-protocol.com/) (v1.0-draft), which establishes AI agents as first-class principals with their own identity, scoped capabilities, and independent lifecycle.

## Why Keycloak?

Keycloak is a natural fit for Agent Auth because it already manages users, sessions, tokens, and approval flows. This extension adds agent-specific concepts (hosts, agents, capability grants) while reusing Keycloak's existing infrastructure for user identity, device authorization, and CIBA.

## Architecture

**Hybrid model** -- Keycloak handles the auth plane; resource servers handle capability execution.

```
Agent (any language)
  |
  | 1. Discover
  | GET /realms/{realm}/.well-known/agent-configuration
  v
Keycloak (this extension)
  |  - Discovery, agent registration, lifecycle, introspect
  |  - Centralized capability registry
  |  - User approval via device authorization / CIBA
  |
  | 2. Register
  | POST /realms/{realm}/agent-auth/agent/register
  | Authorization: Bearer <host+jwt>
  v
Keycloak
  |  - Verifies host JWT (Ed25519)
  |  - Creates agent record
  |  - Triggers approval flow if needed
  |  - Returns agent_id + capability grants
  |
  | 3. Execute capability
  | POST <capability-location>
  | Authorization: Bearer <agent+jwt>
  v
Resource Server (any language)
  |  - Receives agent JWT
  |  - Calls KC introspect to validate
  |  - Checks grants + constraints
  |  - Executes business logic
  |  - Returns result to agent
```

### What lives in Keycloak (this extension)

| Concern | Endpoint | Description |
|---------|----------|-------------|
| Discovery | `GET /.well-known/agent-configuration` | Protocol discovery (WellKnownProvider SPI) |
| Registration | `POST /agent/register` | Register agent under a host |
| Status | `GET /agent/status` | Check agent status + grants |
| Revocation | `POST /agent/revoke` | Permanently revoke an agent |
| Reactivation | `POST /agent/reactivate` | Reactivate an expired agent |
| Introspect | `POST /agent/introspect` | Validate agent JWT (RFC 7662 model) |
| Key rotation | `POST /agent/rotate-key` | Replace agent's public key |
| Host revocation | `POST /host/revoke` | Revoke host + cascade to all agents |
| Host key rotation | `POST /host/rotate-key` | Replace host's public key |
| Capability request | `POST /agent/request-capability` | Request additional capabilities |
| Capability listing | `GET /capability/list` | List available capabilities |
| Capability detail | `GET /capability/describe` | Get full capability schema |
| **Admin:** registration | `POST /admin/.../agent-auth/capabilities` | Register capabilities (admin API) |

### What lives in the resource server

| Concern | Description |
|---------|-------------|
| Capability execution | Receives forwarded requests, runs business logic |
| JWT validation | Calls Keycloak's `/agent/introspect` to verify agent JWTs |

The resource server can be written in **any language** -- it only needs to accept agent JWTs and call KC's introspect endpoint (a simple HTTP POST).

## Centralized Capability Registry

Capabilities are registered in Keycloak by administrators via the admin API. This makes Keycloak the single source of truth for what capabilities exist and who has access to them.

```
Admin / Resource Server
  |
  | Register capabilities at deploy time
  | POST /admin/realms/{realm}/agent-auth/capabilities
  | {
  |   "name": "check_balance",
  |   "description": "Check account balance",
  |   "location": "https://banking-api.example.com/execute",
  |   "input": { JSON Schema },
  |   "output": { JSON Schema }
  | }
  v
Keycloak (capability registry)
  |
  | Agents discover capabilities here
  | GET /capability/list
  | GET /capability/describe?name=check_balance
```

Each capability has:
- **name** -- stable identifier (e.g. `check_balance`, `transfer_money`)
- **description** -- human-readable explanation
- **location** -- URL where the resource server executes it
- **input/output** -- JSON Schema for arguments and results
- **visibility** -- who can see it (public, authenticated)
- **requires_approval** -- whether user approval is needed before granting

### Capability Constraints

Grants can carry constraints that restrict what arguments an agent can supply:

```json
{
  "capability": "transfer_money",
  "status": "active",
  "constraints": {
    "amount": { "min": 0, "max": 1000 },
    "currency": { "in": ["USD", "EUR"] },
    "destination_account": "acc_456"
  }
}
```

Supported constraint operators: `max`, `min`, `in`, `not_in`, and exact value matching.

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Architecture | Hybrid (KC auth + external execution) | Avoids building a parallel auth system inside KC; lets KC do what it's good at |
| Discovery | `/realms/{realm}/.well-known/agent-configuration` via WellKnownProvider SPI | Follows KC's own OpenID discovery pattern |
| Crypto | Nimbus JOSE+JWT for Ed25519 | Already on KC classpath, high-level API, well-audited |
| Storage | JPA entities + Liquibase via JpaEntityProvider SPI | Only supported mechanism for custom entities in KC 26.x (Map Storage SPI was removed) |
| Scoping | Global env toggle + per-realm attribute override (planned) | Start simple, add granularity later |
| Approval flows | Device Authorization + CIBA | Both supported by KC natively; covers CLI and mobile agent scenarios |
| Capabilities | Centralized in KC | Single source of truth; resource servers just execute |

## Protocol Reference

This extension implements [Agent Auth Protocol v1.0-draft](https://agent-auth-protocol.com/specification).

Key protocol concepts:
- **Host** -- persistent identity of the client environment where agents run (Ed25519 keypair)
- **Agent** -- per-agent identity with scoped capabilities and independent lifecycle
- **host+jwt / agent+jwt** -- short-lived Ed25519-signed JWTs (EdDSA, RFC 8037)
- **Delegated mode** -- agent acts on behalf of a user who approves requests
- **Autonomous mode** -- agent operates without user in the loop
- **Agent states** -- pending, active, expired, revoked, rejected, claimed

## Development

### Prerequisites

- Java 21+
- Maven 3.9+
- Docker (for integration tests)

### Build

```bash
mvn package -Pquick          # compile + package, skip tests
mvn test                      # unit tests only
mvn verify                    # unit + integration tests (starts Keycloak in Docker)
```

### Commit Messages

This repository uses Conventional Commits.

```bash
./scripts/install-hooks.sh
```

The hook rejects commit subjects that do not match formats like `feat: ...` or `fix(scope): ...`.

Release automation is handled by release-please.

Release asset uploads are verified in GitHub Actions.

### Local development with Docker Compose

```bash
mvn package -Pquick
docker compose up
```

Keycloak will be available at `http://localhost:8080` with the extension loaded. The agent-auth endpoints are at `/realms/{realm}/agent-auth/...`.

### Project structure

```
src/main/java/.../agentauth/
  AgentAuthRealmResourceProvider.java        # JAX-RS resource (all protocol endpoints)
  AgentAuthRealmResourceProviderFactory.java # Keycloak RealmResourceProvider SPI factory
  AgentAuthAdminResourceProvider.java        # Admin REST resource (capability CRUD, agent expiry)
  AgentAuthAdminResourceProviderFactory.java # Keycloak AdminRealmResourceProvider SPI factory
  AgentAuthWellKnownProvider.java            # /.well-known/agent-configuration document
  AgentAuthWellKnownProviderFactory.java     # Keycloak WellKnownProvider SPI factory
  ConstraintValidator.java                   # Capability constraint enforcement
  ConstraintViolation.java                   # Violation record
  InMemoryRegistry.java                      # In-process storage (dev/test only)

src/test/java/.../agentauth/
  support/
    BaseKeycloakIT.java                      # Shared Testcontainers Keycloak singleton
    TestKeys.java                            # Ed25519 key generation helpers
    TestJwts.java                            # host+jwt / agent+jwt builders
    TestcontainersSupport.java               # Testcontainers configuration
  AgentAuthDiscoveryIT.java                  # §5.1  Discovery
  AgentAuthCapabilityCatalogIT.java          # §5.2  List/Describe capabilities
  AgentAuthRegistrationIT.java               # §5.3  Agent registration
  AgentAuthCapabilityRequestIT.java          # §5.4  Request capability
  AgentAuthLifecycleIT.java                  # §5.5–§5.10 Status, revoke, reactivate, key rotation
  AgentAuthCapabilityExecuteIT.java          # §5.11 Execute capability
  AgentAuthIntrospectIT.java                 # §5.12 Token introspection
  AgentAuthErrorResponseIT.java              # §5.13–§5.14 Error format + WWW-Authenticate
  AgentAuthAdminCapabilityRegistrationIT.java# Admin capability CRUD
  AgentAuthKeycloakIT.java                   # Sanity check (Keycloak starts, extension loads)
  ConstraintValidatorTest.java               # Constraint validation unit tests (no Docker)
  AgentAuthRealmResourceProviderFactoryTest.java # Factory unit tests (no Docker)
```
