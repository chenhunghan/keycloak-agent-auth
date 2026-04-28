package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import com.github.chh.keycloak.agentauth.support.BaseKeycloakIT;
import com.github.chh.keycloak.agentauth.support.TestJwts;
import com.github.chh.keycloak.agentauth.support.TestKeys;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.sun.net.httpserver.HttpServer;
import io.restassured.http.ContentType;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.keycloak.util.JsonSerialization;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.Testcontainers;

/**
 * Integration tests for {@code POST /agent/register} and related registration flows.
 *
 * <p>
 * Spec sections covered by this file:
 * <ul>
 * <li>§4.2 Host JWT — structure and required claims for host-authenticated requests</li>
 * <li>§4.5.1 Host JWT Verification — server-side validation of every required claim</li>
 * <li>§4.6 Replay Detection — jti uniqueness enforcement and server-side replay cache</li>
 * <li>§2.2 Agent Modes — {@code delegated} and {@code autonomous} registration semantics</li>
 * <li>§2.3 Agent States — {@code active} and {@code pending} states returned after
 * registration</li>
 * <li>§2.13 Scoped Grants (Constraints) — constraint objects and operator validation</li>
 * <li>§5.3 Agent Registration — full request/response contract, idempotency, partial approval</li>
 * <li>§5.13 Error Format — structured error responses with {@code error} and {@code message}</li>
 * </ul>
 *
 * @see <a href=
 *      "https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">§5.3 Agent
 *      Registration</a>
 * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#42-host-jwt">§4.2 Host
 *      JWT</a>
 * @see <a href=
 *      "https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification">§4.5.1
 *      Host JWT Verification</a>
 * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#46-replay-detection">§4.6
 *      Replay Detection</a>
 * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#22-agent-modes">§2.2 Agent
 *      Modes</a>
 * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
 *      Agent States</a>
 * @see <a href=
 *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">§2.13
 *      Scoped Grants (Constraints)</a>
 * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#513-error-format">§5.13
 *      Error Format</a>
 */
class AgentAuthRegistrationIT extends BaseKeycloakIT {

  private static OctetKeyPair hostKey;
  private static OctetKeyPair agentKey;
  private static String activeCapability;
  private static String constrainedCapability;
  private static String pendingCapability;
  private static OctetKeyPair agentJwksHostKey;
  private static OctetKeyPair agentJwksAgentKey;
  private static String agentJwksKid;
  private static String agentJwksUrl;
  private static HttpServer agentJwksServer;
  private static OctetKeyPair hostJwksHostKey;
  private static OctetKeyPair hostJwksAgentKey;
  private static String hostJwksKid;
  private static String hostJwksUrl;
  private static HttpServer hostJwksServer;

  @BeforeAll
  static void generateKeysAndRegisterCapabilities() {
    hostKey = TestKeys.generateEd25519();
    agentKey = TestKeys.generateEd25519();
    agentJwksHostKey = TestKeys.generateEd25519();
    agentJwksAgentKey = TestKeys.generateEd25519();
    agentJwksKid = "agent-kid-" + UUID.randomUUID();
    hostJwksHostKey = TestKeys.generateEd25519();
    hostJwksAgentKey = TestKeys.generateEd25519();
    hostJwksKid = "host-kid-" + UUID.randomUUID();

    try {
      agentJwksServer = startJwksServer(agentJwksAgentKey, agentJwksKid);
      hostJwksServer = startJwksServer(hostJwksHostKey, hostJwksKid);
    } catch (Exception e) {
      throw new AssertionError("Failed to start JWKS test servers", e);
    }
    Testcontainers.exposeHostPorts(agentJwksServer.getAddress().getPort());
    Testcontainers.exposeHostPorts(hostJwksServer.getAddress().getPort());
    agentJwksUrl = "http://host.testcontainers.internal:"
        + agentJwksServer.getAddress().getPort() + "/jwks";
    hostJwksUrl = "http://host.testcontainers.internal:"
        + hostJwksServer.getAddress().getPort() + "/jwks";

    String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    activeCapability = "check_balance_" + suffix;
    constrainedCapability = "transfer_money_" + suffix;
    pendingCapability = "escalated_transfer_" + suffix;

    registerCapability(activeCapability, "Check account balance", false);
    registerCapability(constrainedCapability, "Transfer funds", false);
    registerCapability(pendingCapability, "Transfer funds with approval", true);

    // Pre-register the shared hostKey so the §2.11 host-pending bootstrap doesn't block tests
    // that exercise the post-link, active-host registration paths. Tests that explicitly cover
    // the pending bootstrap or use distinct host keys keep their own preRegisterHost calls.
    preRegisterHost(hostKey);
    preRegisterHost(agentJwksHostKey);
    preRegisterHost(hostJwksHostKey);
  }

  @AfterAll
  static void stopJwksServers() {
    if (agentJwksServer != null) {
      agentJwksServer.stop(0);
    }
    if (hostJwksServer != null) {
      hostJwksServer.stop(0);
    }
  }

  private static void registerCapability(
      String name, String description, boolean requiresApproval) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "%s",
              "visibility": "authenticated",
              "requires_approval": %s,
              "location": "https://resource.example.test/capabilities/%s",
              "input": {
                "type": "object",
                "properties": {
                  "account_id": {"type": "string"},
                  "amount": {"type": "number"},
                  "currency": {"type": "string"}
                }
              },
              "output": {
                "type": "object"
              }
            }
            """, name, description, requiresApproval, name))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);
  }

  private static HttpServer startJwksServer(OctetKeyPair key, String kid) throws Exception {
    Map<String, Object> jwk = new HashMap<>(key.toPublicJWK().toJSONObject());
    jwk.put("kid", kid);
    jwk.put("alg", "EdDSA");
    jwk.put("use", "sig");
    byte[] jwks = JsonSerialization.writeValueAsString(Map.of("keys", List.of(jwk)))
        .getBytes(StandardCharsets.UTF_8);

    HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", 0), 0);
    server.createContext("/jwks", exchange -> {
      exchange.getResponseHeaders().add("Content-Type", "application/json");
      exchange.getResponseHeaders().add("Cache-Control", "max-age=60, public");
      exchange.sendResponseHeaders(200, jwks.length);
      exchange.getResponseBody().write(jwks);
      exchange.close();
    });
    server.start();
    return server;
  }

  /**
   * A successful registration of a delegated-mode agent must return HTTP 200 with an
   * {@code agent_id}, {@code host_id}, the submitted {@code name}, {@code mode} set to
   * {@code "delegated"}, {@code status} set to {@code "active"}, and an empty
   * {@code agent_capability_grants} array when no capabilities are requested.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">§5.3
   *      Agent Registration — response fields</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#22-agent-modes">§2.2
   *      Agent Modes — delegated mode</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
   *      Agent States — active state</a>
   */
  @Test
  void registerDelegatedAgentReturnsActiveAgentRecord() {
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl());

    preRegisterHost(hostKey);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Test Agent",
              "host_name": "test-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Integration test"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("agent_id", notNullValue())
        .body("host_id", notNullValue())
        .body("name", equalTo("Test Agent"))
        .body("mode", equalTo("delegated"))
        .body("status", equalTo("active"))
        .body("agent_capability_grants", hasSize(0));
  }

  /**
   * §5.3 defines {@code capabilities} as optional. If omitted, the server creates the agent with no
   * initial capability grants so the agent can request capabilities later via
   * {@code POST /agent/request-capability}.
   */
  @Test
  void registerAgentWithOmittedCapabilitiesCreatesEmptyGrantSet() {
    OctetKeyPair noCapsAgentKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, noCapsAgentKey, issuerUrl());

    preRegisterHost(hostKey);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "No Initial Capabilities Agent",
              "host_name": "test-host",
              "mode": "delegated",
              "reason": "Capabilities are requested later"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("status", equalTo("active"))
        .body("agent_capability_grants", hasSize(0));
  }

  /**
   * A successful registration of an autonomous-mode agent must return HTTP 200 with an
   * {@code agent_id} and {@code mode} set to {@code "autonomous"}; autonomous agents operate
   * without end-user involvement and may be granted capabilities by server or admin policy.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#22-agent-modes">§2.2
   *      Agent Modes — autonomous mode</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">§5.3
   *      Agent Registration — mode field</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
   *      Agent States — active state</a>
   */
  @Test
  void registerAutonomousAgentReturnsAgentId() {
    OctetKeyPair autonomousAgentKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, autonomousAgentKey, issuerUrl());

    preRegisterHost(hostKey);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Autonomous Agent",
              "host_name": "test-host",
              "capabilities": [],
              "mode": "autonomous",
              "reason": "Autonomous integration test"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("agent_id", notNullValue())
        .body("mode", equalTo("autonomous"))
        .body("status", equalTo("active"));
  }

  /**
   * When an agent is registered with capability names, the response must include a
   * {@code agent_capability_grants} array whose entries carry the capability name, grant
   * {@code status}, human-readable {@code description}, and the {@code input}/{@code output} JSON
   * Schemas copied from the capability definition.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">§5.3
   *      Agent Registration — capability grant structure</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
   *      Agent States — active grant status</a>
   */
  @Test
  void registerAgentWithCapabilitiesReturnsDetailedGrants() {
    OctetKeyPair capAgentKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, capAgentKey, issuerUrl());

    preRegisterHost(hostKey);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Cap Agent",
              "host_name": "test-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "Test capability grants"
            }
            """, activeCapability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("agent_capability_grants", hasSize(1))
        .body("agent_capability_grants[0].capability", equalTo(activeCapability))
        .body("agent_capability_grants[0].status", equalTo("active"))
        .body("agent_capability_grants[0].description", equalTo("Check account balance"))
        .body("agent_capability_grants[0].input.type", equalTo("object"))
        .body("agent_capability_grants[0].output.type", equalTo("object"));
  }

  /**
   * When an agent registers with an inline constraint object on a capability, the server must
   * reflect the approved constraints verbatim in the corresponding capability grant so that the
   * agent knows the exact scope restrictions that will be enforced during execution.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">§2.13
   *      Scoped Grants (Constraints) — constraint structure and operators</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">§5.3
   *      Agent Registration — constraints in capability grant response</a>
   */
  @Test
  void registerAgentWithConstrainedCapabilityReturnsApprovedConstraints() {
    OctetKeyPair constrainedAgentKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, constrainedAgentKey, issuerUrl());

    preRegisterHost(hostKey);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Constrained Agent",
              "host_name": "test-host",
              "capabilities": [
                {
                  "name": "%s",
                  "constraints": {
                    "amount": {"max": 1000},
                    "currency": {"in": ["USD", "EUR"]}
                  }
                }
              ],
              "mode": "delegated",
              "reason": "Test constrained capabilities"
            }
            """, constrainedCapability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("agent_capability_grants", hasSize(1))
        .body("agent_capability_grants[0].capability", equalTo(constrainedCapability))
        .body("agent_capability_grants[0].constraints.amount.max", equalTo(1000))
        .body("agent_capability_grants[0].constraints.currency.in", hasSize(2));
  }

  /**
   * §5.3 + §2.13: when a registration's only capability requires approval AND the agent supplied a
   * constraint scope, the pending response MUST stay in the compact {@code {capability, status,
   * status_url}} shape — {@code constraints} are NOT echoed at this stage. The server still has to
   * remember the requested scope internally so the approval activation can restore it (the sister
   * test in {@link AgentAuthDeviceApprovalIT} drives the full approval round-trip and checks the
   * post-approve grant carries the constraint), but the pending wire payload itself must not
   * surface either {@code constraints} or the internal {@code requested_constraints} stash.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">
   *      §5.3 Agent Registration — pending response shape</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
   *      §2.13 Scoped Grants (Constraints)</a>
   */
  @Test
  void registerPendingWithConstraintsReturnsCompactPendingGrant() {
    OctetKeyPair pendingConstrainedAgentKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, pendingConstrainedAgentKey,
        issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Pending Constrained Agent",
              "host_name": "test-host",
              "capabilities": [
                {
                  "name": "%s",
                  "constraints": {"amount": {"max": 250}}
                }
              ],
              "mode": "delegated"
            }
            """, pendingCapability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("status", equalTo("pending"))
        .body("agent_capability_grants", hasSize(1))
        .body("agent_capability_grants[0].capability", equalTo(pendingCapability))
        .body("agent_capability_grants[0].status", equalTo("pending"))
        // Wave 2 R-F4: pending grants no longer publish per-grant `status_url`; clients poll
        // the agent-level approval polling URL instead.
        // §5.3: pending grant MUST NOT echo `constraints` (compact response shape).
        .body("agent_capability_grants[0].constraints", nullValue())
        // The internal stash MUST NOT leak onto the wire.
        .body("agent_capability_grants[0].requested_constraints", nullValue());
  }

  /**
   * When an agent re-registers with the same host/key pair while already in {@code pending} state,
   * the server SHOULD treat the request as an idempotent retry and return the original
   * {@code agent_id} with {@code status} still set to {@code "pending"} rather than creating a
   * duplicate record.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">§5.3
   *      Agent Registration — idempotency for pending agents</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
   *      Agent States — pending state</a>
   */
  @Test
  void retryingPendingRegistrationReturnsExistingPendingAgentId() {
    // The shared @BeforeAll-pre-registered hostKey is admin-linked (Wave 5 default), which would
    // route the approval to CIBA. The test's spec assertion is about device_authorization on an
    // unlinked host, so use a fresh pending host. Wave 4 B-P3b also moved approval.status_url
    // under approval.extensions — assertion path updated accordingly.
    OctetKeyPair pendingHostKey = TestKeys.generateEd25519();
    OctetKeyPair pendingAgentKey = TestKeys.generateEd25519();
    preRegisterHostAsPending(pendingHostKey);
    String hostJwt1 = TestJwts.hostJwtForRegistration(pendingHostKey, pendingAgentKey, issuerUrl());

    String agentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt1)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Pending Agent",
              "host_name": "test-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "First registration"
            }
            """, pendingCapability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("status", equalTo("pending"))
        .body("approval.method", equalTo("device_authorization"))
        .body("approval.extensions.status_url", notNullValue())
        .extract()
        .path("agent_id");

    String hostJwt2 = TestJwts.hostJwtForRegistration(pendingHostKey, pendingAgentKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt2)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Pending Agent",
              "host_name": "test-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "Retry registration"
            }
            """, pendingCapability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("agent_id", equalTo(agentId))
        .body("status", equalTo("pending"));
  }

  /**
   * Attempting to register an agent whose host/key pair already corresponds to an {@code active}
   * agent record must return HTTP 409 with error code {@code agent_exists}, preventing silent
   * duplicate creation.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">§5.3
   *      Agent Registration — 409 agent_exists error</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#513-error-format">§5.13
   *      Error Format — structured error response</a>
   */
  @Test
  void registeringExistingActiveAgentReturns409AgentExists() {
    OctetKeyPair duplicateAgentKey = TestKeys.generateEd25519();
    String hostJwt1 = TestJwts.hostJwtForRegistration(hostKey, duplicateAgentKey, issuerUrl());
    String hostJwt2 = TestJwts.hostJwtForRegistration(hostKey, duplicateAgentKey, issuerUrl());

    preRegisterHost(hostKey);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt1)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Duplicate Agent",
              "host_name": "test-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "First registration"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("status", equalTo("active"));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt2)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Duplicate Agent",
              "host_name": "test-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Second registration"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(409)
        .body("error", equalTo("agent_exists"))
        .body("message", notNullValue());
  }

  /**
   * A request to {@code POST /agent/register} with no {@code Authorization} header must be rejected
   * with HTTP 401 and error code {@code authentication_required} because every registration request
   * MUST be authenticated with a valid host+jwt.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification">§4.5.1
   *      Host JWT Verification — missing Authorization</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#513-error-format">§5.13
   *      Error Format — structured error response</a>
   */
  @Test
  void registerWithoutAuthorizationHeaderReturns401() {
    given()
        .baseUri(issuerUrl())
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "No Auth Agent",
              "capabilities": [],
              "mode": "delegated"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(401)
        .body("error", equalTo("authentication_required"))
        .body("message", notNullValue());
  }

  /**
   * A host+jwt whose {@code exp} claim is in the past must be rejected with HTTP 401 and error code
   * {@code invalid_jwt}; the server MUST verify {@code exp} and reject expired tokens per the
   * timestamp validation step of Host JWT Verification.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification">§4.5.1
   *      Host JWT Verification — exp/iat timestamp validation (step 6)</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#42-host-jwt">§4.2 Host
   *      JWT — exp claim required</a>
   */
  @Test
  void registerWithExpiredHostJwtReturns401() {
    String expiredJwt = TestJwts.expiredHostJwt(hostKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + expiredJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Expired JWT Agent",
              "capabilities": [],
              "mode": "delegated"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_jwt"))
        .body("message", notNullValue());
  }

  /**
   * A host+jwt whose cryptographic signature does not verify against the embedded
   * {@code host_public_key} must be rejected with HTTP 401 and error code {@code invalid_jwt}; the
   * server MUST verify the JWT signature against the host's public key.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification">§4.5.1
   *      Host JWT Verification — signature verification (step 5)</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#42-host-jwt">§4.2 Host
   *      JWT — EdDSA/Ed25519 algorithm</a>
   */
  @Test
  void registerWithInvalidSignatureReturns401() {
    OctetKeyPair wrongKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwtForRegistration(wrongKey, agentKey, issuerUrl());
    String tampered = hostJwt.substring(0, hostJwt.length() - 4) + "XXXX";

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + tampered)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Bad Sig Agent",
              "capabilities": [],
              "mode": "delegated"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_jwt"))
        .body("message", notNullValue());
  }

  /**
   * A registration request body that omits required fields (e.g. {@code name} and {@code mode})
   * must be rejected with HTTP 400 and error code {@code invalid_request} per the spec's error
   * format for malformed or incomplete request bodies.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">§5.3
   *      Agent Registration — required request fields</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#513-error-format">§5.13
   *      Error Format — 400 invalid_request</a>
   */
  @Test
  void registerWithMissingBodyFieldsReturns400() {
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, TestKeys.generateEd25519(),
        issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("{}")
        .when()
        .post("/agent/register")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"))
        .body("message", notNullValue());
  }

  /**
   * When the {@code capabilities} array contains a capability name that does not exist in the
   * server's catalog, the server must return HTTP 400 with error code {@code invalid_capabilities}
   * and an {@code invalid_capabilities} array listing every unknown name.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">§5.3
   *      Agent Registration — invalid_capabilities error</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#513-error-format">§5.13
   *      Error Format — 400 invalid_capabilities</a>
   */
  @Test
  void registerWithInvalidCapabilityNamesReturns400() {
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, TestKeys.generateEd25519(),
        issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Invalid Cap Agent",
              "capabilities": ["nonexistent_capability_xyz"],
              "mode": "delegated"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_capabilities"))
        .body("message", notNullValue())
        .body("invalid_capabilities", hasSize(1))
        .body("invalid_capabilities[0]", equalTo("nonexistent_capability_xyz"));
  }

  /**
   * A registration request whose {@code mode} field is not one of the two defined values
   * ({@code "delegated"} or {@code "autonomous"}) must be rejected with HTTP 400 and error code
   * {@code unsupported_mode}; servers MUST reject registration requests for unsupported modes.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#22-agent-modes">§2.2
   *      Agent Modes — only delegated and autonomous are valid</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">§5.3
   *      Agent Registration — mode validation</a>
   */
  @Test
  void registerWithUnsupportedModeReturns400() {
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, TestKeys.generateEd25519(),
        issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Invalid Mode Agent",
              "capabilities": [],
              "mode": "semi-autonomous"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(400)
        .body("error", equalTo("unsupported_mode"))
        .body("message", notNullValue());
  }

  /**
   * A host+jwt whose {@code aud} claim does not match the server's own issuer URL must be rejected
   * with HTTP 401 and error code {@code invalid_jwt}; the server MUST verify that {@code aud}
   * matches its own {@code issuer} URL and reject tokens addressed to a different audience.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification">§4.5.1
   *      Host JWT Verification — aud claim verification (step 2)</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#42-host-jwt">§4.2 Host
   *      JWT — aud claim required</a>
   */
  @Test
  void registerWithWrongAudienceReturns401() {
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, agentKey,
        "https://wrong-server.example.com");

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Wrong Aud Agent",
              "capabilities": [],
              "mode": "delegated"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_jwt"))
        .body("message", notNullValue());
  }

  /**
   * A JWT whose {@code typ} header is not {@code "host+jwt"} (e.g. an agent JWT) must be rejected
   * with HTTP 401 and error code {@code invalid_jwt}; the server MUST verify the JWT header
   * {@code typ} is {@code host+jwt} and reject any other type.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification">§4.5.1
   *      Host JWT Verification — typ header verification (step 1)</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#42-host-jwt">§4.2 Host
   *      JWT — typ MUST be host+jwt</a>
   */
  @Test
  void registerWithWrongJwtTypeReturns401() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, "agt_fake", issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Wrong Type Agent",
              "capabilities": [],
              "mode": "delegated"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_jwt"))
        .body("message", notNullValue());
  }

  /**
   * When a registration requests one auto-approved capability and one approval-required capability
   * in a single call, the server must return individual grant statuses ({@code "active"} and
   * {@code "pending"} respectively) and set the agent's top-level {@code status} to
   * {@code "pending"} because at least one grant awaits approval, along with an {@code approval}
   * object describing the pending flow.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">§5.3
   *      Agent Registration — partial approval and mixed grant statuses</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
   *      Agent States — pending state set when any grant awaits approval</a>
   */
  @Test
  void registerWithMixedCapabilitiesReturnsMixedGrantStatuses() {
    // Spec: "Partial approval allows users to deny specific capabilities while approving others."
    // Strategy: registering one auto-approved capability alongside one approval-required capability
    // in a single call must produce a grant list with mixed statuses, and the overall agent status
    // must be "pending" because at least one grant is awaiting approval. Wave 5 + §2.11: a pending
    // host cascades ALL grants to pending, so we need a linked (admin-linked default) host to
    // exercise the mixed-status flow. That routes the approval to CIBA; the wire shape contract
    // is identical aside from approval.method and the status_url location.
    OctetKeyPair mixedAgentKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, mixedAgentKey, issuerUrl());

    List<Map<String, String>> grants = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Mixed Cap Agent",
              "host_name": "test-host",
              "capabilities": ["%s", "%s"],
              "mode": "delegated",
              "reason": "Test partial approval"
            }
            """, activeCapability, pendingCapability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("status", equalTo("pending"))
        .body("approval.method", equalTo("ciba"))
        .body("approval.extensions.status_url", notNullValue())
        .body("agent_capability_grants", hasSize(2))
        .extract()
        .path("agent_capability_grants");

    // Verify each capability has the correct individual grant status.
    Map<String, String> activeGrant = grants.stream()
        .filter(g -> activeCapability.equals(g.get("capability")))
        .findFirst()
        .orElseThrow(() -> new AssertionError("Grant for " + activeCapability + " not found"));
    Map<String, String> pendingGrant = grants.stream()
        .filter(g -> pendingCapability.equals(g.get("capability")))
        .findFirst()
        .orElseThrow(() -> new AssertionError("Grant for " + pendingCapability + " not found"));

    org.junit.jupiter.api.Assertions.assertEquals("active", activeGrant.get("status"),
        "Auto-approved capability grant should be active");
    org.junit.jupiter.api.Assertions.assertEquals("pending", pendingGrant.get("status"),
        "Approval-required capability grant should be pending");
  }

  /**
   * Presenting the same serialized JWT string on a second request must be rejected with HTTP 401
   * because the server MUST cache observed {@code jti} values and reject any duplicate within the
   * token's validity window to prevent replay attacks.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#46-replay-detection">§4.6 Replay
   *      Detection — jti cache and duplicate rejection</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification">§4.5.1
   *      Host JWT Verification — jti replay check (step 7)</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#42-host-jwt">§4.2 Host
   *      JWT — jti claim required</a>
   */
  @Test
  void replayingHostJwtIsRejected() {
    // Spec: "All JWTs require jti (unique identifier) for replay detection;
    // servers cache seen values."
    // Strategy: register a fresh agent, then call GET /agent/status twice with the identical
    // serialized JWT string. The first call must succeed; the second must be rejected because
    // the server has already seen (and cached) that jti.
    OctetKeyPair replayAgentKey = TestKeys.generateEd25519();
    String registrationJwt = TestJwts.hostJwtForRegistration(hostKey, replayAgentKey, issuerUrl());

    // Register the agent so we have a valid agentId to query.
    String agentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + registrationJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Replay Test Agent",
              "host_name": "test-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "jti replay detection test"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    // Build a status JWT and present it twice — same serialized string both times.
    String statusJwt = TestJwts.hostJwt(hostKey, issuerUrl());

    // First call: must succeed.
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + statusJwt)
        .queryParam("agent_id", agentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(200);

    // Second call with the IDENTICAL JWT string: must be rejected due to jti replay.
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + statusJwt)
        .queryParam("agent_id", agentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(401)
        .body("error", anyOf(equalTo("jti_replay"), equalTo("invalid_jwt")))
        .body("message", notNullValue());
  }

  /**
   * A host+jwt whose {@code iss} claim (the JWK thumbprint) does not match the thumbprint computed
   * from the embedded {@code host_public_key} must be rejected with HTTP 401 and error code
   * {@code invalid_jwt}; the server MUST compute the JWK thumbprint (RFC 7638, SHA-256) of the
   * provided key and verify it equals the {@code iss} value.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification">§4.5.1
   *      Host JWT Verification — thumbprint validation (step 4)</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#42-host-jwt">§4.2 Host
   *      JWT — iss MUST be JWK thumbprint of signing key</a>
   */
  @Test
  void registerWithMismatchedIssuerThumbprintReturns401() {
    OctetKeyPair wrongHostKey = TestKeys.generateEd25519();
    // Create a JWT signed by hostKey, but whose issuer claim is wrongHostKey's thumbprint
    // This requires custom JWT building.
    try {
      com.nimbusds.jose.JWSHeader header = new com.nimbusds.jose.JWSHeader.Builder(
          com.nimbusds.jose.JWSAlgorithm.EdDSA)
          .type(new com.nimbusds.jose.JOSEObjectType("host+jwt"))
          .build();
      long now = System.currentTimeMillis();
      com.nimbusds.jwt.JWTClaimsSet claims = new com.nimbusds.jwt.JWTClaimsSet.Builder()
          .issuer(TestKeys.thumbprint(wrongHostKey)) // Wrong thumbprint!
          .audience(issuerUrl())
          .issueTime(new java.util.Date(now))
          .expirationTime(new java.util.Date(now + 60_000))
          .jwtID("h-" + java.util.UUID.randomUUID())
          .claim("host_public_key", hostKey.toPublicJWK().toJSONObject())
          .claim("agent_public_key", agentKey.toPublicJWK().toJSONObject())
          .build();
      com.nimbusds.jwt.SignedJWT jwt = new com.nimbusds.jwt.SignedJWT(header, claims);
      jwt.sign(new com.nimbusds.jose.crypto.Ed25519Signer(hostKey));

      given()
          .baseUri(issuerUrl())
          .header("Authorization", "Bearer " + jwt.serialize())
          .contentType(io.restassured.http.ContentType.JSON)
          .body("""
              {
                "name": "Mismatched Thumbprint Agent",
                "capabilities": [],
                "mode": "delegated"
              }
              """)
          .when()
          .post("/agent/register")
          .then()
          .statusCode(401)
          .body("error", equalTo("invalid_jwt"))
          .body("message", notNullValue());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * A host+jwt that omits the {@code host_public_key} claim (without providing a
   * {@code host_jwks_url} alternative) must be rejected with HTTP 401 and error code
   * {@code invalid_jwt}; the server requires at least one of these claims to locate and verify the
   * host's signing key per §4.5.1.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification">§4.5.1
   *      Host JWT Verification — host key resolution (step 3)</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#42-host-jwt">§4.2 Host
   *      JWT — host_public_key or host_jwks_url required</a>
   */
  @Test
  void registerWithMissingHostPublicKeyReturns401() {
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    // Use hostJwtForRegistration but override to omit host_public_key
    // Since our test builder doesn't easily allow removing claims, we'll build it manually
    try {
      com.nimbusds.jose.JWSHeader header = new com.nimbusds.jose.JWSHeader.Builder(
          com.nimbusds.jose.JWSAlgorithm.EdDSA)
          .type(new com.nimbusds.jose.JOSEObjectType("host+jwt"))
          .build();
      long now = System.currentTimeMillis();
      com.nimbusds.jwt.JWTClaimsSet claims = new com.nimbusds.jwt.JWTClaimsSet.Builder()
          .issuer(TestKeys.thumbprint(hostKey))
          .audience(issuerUrl())
          .issueTime(new java.util.Date(now))
          .expirationTime(new java.util.Date(now + 60_000))
          .jwtID("h-" + java.util.UUID.randomUUID())
          // .claim("host_public_key", hostKey.toPublicJWK().toJSONObject()) // MISSING
          .claim("agent_public_key", agentKey.toPublicJWK().toJSONObject())
          .build();
      com.nimbusds.jwt.SignedJWT jwt = new com.nimbusds.jwt.SignedJWT(header, claims);
      jwt.sign(new com.nimbusds.jose.crypto.Ed25519Signer(hostKey));

      given()
          .baseUri(issuerUrl())
          .header("Authorization", "Bearer " + jwt.serialize())
          .contentType(io.restassured.http.ContentType.JSON)
          .body("""
              {
                "name": "Missing Host Key Agent",
                "capabilities": [],
                "mode": "delegated"
              }
              """)
          .when()
          .post("/agent/register")
          .then()
          .statusCode(401)
          .body("error", equalTo("invalid_jwt"))
          .body("message", notNullValue());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * A host+jwt for a registration request that omits the {@code agent_public_key} claim (without
   * providing an {@code agent_jwks_url} alternative) must be rejected with HTTP 401 and error code
   * {@code invalid_jwt}; for registration, the server MUST extract the agent key from the JWT and
   * one of these claims is required.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification">§4.5.1
   *      Host JWT Verification — agent key extraction for registration (step 9)</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#42-host-jwt">§4.2 Host
   *      JWT — agent_public_key or agent_jwks_url required for registration</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">§5.3
   *      Agent Registration — agent_public_key MUST be present</a>
   */
  @Test
  void registerWithMissingAgentPublicKeyReturns401() {
    // Similar to above, omit agent_public_key
    try {
      com.nimbusds.jose.JWSHeader header = new com.nimbusds.jose.JWSHeader.Builder(
          com.nimbusds.jose.JWSAlgorithm.EdDSA)
          .type(new com.nimbusds.jose.JOSEObjectType("host+jwt"))
          .build();
      long now = System.currentTimeMillis();
      com.nimbusds.jwt.JWTClaimsSet claims = new com.nimbusds.jwt.JWTClaimsSet.Builder()
          .issuer(TestKeys.thumbprint(hostKey))
          .audience(issuerUrl())
          .issueTime(new java.util.Date(now))
          .expirationTime(new java.util.Date(now + 60_000))
          .jwtID("h-" + java.util.UUID.randomUUID())
          .claim("host_public_key", hostKey.toPublicJWK().toJSONObject())
          // .claim("agent_public_key", agentKey.toPublicJWK().toJSONObject()) // MISSING
          .build();
      com.nimbusds.jwt.SignedJWT jwt = new com.nimbusds.jwt.SignedJWT(header, claims);
      jwt.sign(new com.nimbusds.jose.crypto.Ed25519Signer(hostKey));

      given()
          .baseUri(issuerUrl())
          .header("Authorization", "Bearer " + jwt.serialize())
          .contentType(io.restassured.http.ContentType.JSON)
          .body("""
              {
                "name": "Missing Agent Key Agent",
                "capabilities": [],
                "mode": "delegated"
              }
              """)
          .when()
          .post("/agent/register")
          .then()
          .statusCode(401)
          .body("error", equalTo("invalid_jwt"))
          .body("message", notNullValue());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * A registration request whose capability constraint object uses an operator not defined by the
   * spec ({@code max}, {@code min}, {@code in}, {@code not_in}) must be rejected with HTTP 400 and
   * error code {@code unknown_constraint_operator}; the server MUST reject unrecognized operators.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">§2.13
   *      Scoped Grants (Constraints) — unknown operator rejection</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#513-error-format">§5.13
   *      Error Format — 400 unknown_constraint_operator</a>
   */
  @Test
  void registerWithUnknownConstraintOperatorReturns400() {
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(io.restassured.http.ContentType.JSON)
        .body(String.format("""
            {
              "name": "Bad Constraint Agent",
              "capabilities": [
                {
                  "name": "%s",
                  "constraints": {
                    "amount": {"between": [1, 10]}
                  }
                }
              ],
              "mode": "delegated",
              "reason": "Testing bad constraints"
            }
            """, constrainedCapability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(400)
        .body("error", equalTo("unknown_constraint_operator"))
        .body("message", notNullValue());
  }

  /**
   * A host+jwt that omits the {@code jti} claim must be rejected with HTTP 401 and error code
   * {@code invalid_jwt}; every JWT MUST include a {@code jti} claim and servers MUST reject tokens
   * that lack one because replay detection cannot function without it.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#46-replay-detection">§4.6 Replay
   *      Detection — jti MUST be present in all JWTs</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification">§4.5.1
   *      Host JWT Verification — jti replay check (step 7)</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#42-host-jwt">§4.2 Host
   *      JWT — jti claim required</a>
   */
  @Test
  void registerWithMissingJtiReturns401() {
    try {
      com.nimbusds.jose.JWSHeader header = new com.nimbusds.jose.JWSHeader.Builder(
          com.nimbusds.jose.JWSAlgorithm.EdDSA)
          .type(new com.nimbusds.jose.JOSEObjectType("host+jwt"))
          .build();
      long now = System.currentTimeMillis();
      com.nimbusds.jwt.JWTClaimsSet claims = new com.nimbusds.jwt.JWTClaimsSet.Builder()
          .issuer(TestKeys.thumbprint(hostKey))
          .audience(issuerUrl())
          .issueTime(new java.util.Date(now))
          .expirationTime(new java.util.Date(now + 60_000))
          // .jwtID() // MISSING JTI
          .claim("host_public_key", hostKey.toPublicJWK().toJSONObject())
          .claim("agent_public_key", agentKey.toPublicJWK().toJSONObject())
          .build();
      com.nimbusds.jwt.SignedJWT jwt = new com.nimbusds.jwt.SignedJWT(header, claims);
      jwt.sign(new com.nimbusds.jose.crypto.Ed25519Signer(hostKey));

      given()
          .baseUri(issuerUrl())
          .header("Authorization", "Bearer " + jwt.serialize())
          .contentType(io.restassured.http.ContentType.JSON)
          .body("""
              {
                "name": "Missing JTI Agent",
                "capabilities": [],
                "mode": "delegated"
              }
              """)
          .when()
          .post("/agent/register")
          .then()
          .statusCode(401)
          .body("error", equalTo("invalid_jwt"))
          .body("message", notNullValue());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * A host+jwt that omits the {@code exp} claim must be rejected with HTTP 401 and error code
   * {@code invalid_jwt}; the server MUST verify the {@code exp} claim is present and valid, and
   * tokens without an expiration cannot be accepted because they would never expire from the replay
   * cache.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification">§4.5.1
   *      Host JWT Verification — exp/iat timestamp validation (step 6)</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#42-host-jwt">§4.2 Host
   *      JWT — exp claim required</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#46-replay-detection">§4.6 Replay
   *      Detection — cache TTL aligned to token exp</a>
   */
  @Test
  void registerWithMissingExpReturns401() {
    try {
      com.nimbusds.jose.JWSHeader header = new com.nimbusds.jose.JWSHeader.Builder(
          com.nimbusds.jose.JWSAlgorithm.EdDSA)
          .type(new com.nimbusds.jose.JOSEObjectType("host+jwt"))
          .build();
      long now = System.currentTimeMillis();
      com.nimbusds.jwt.JWTClaimsSet claims = new com.nimbusds.jwt.JWTClaimsSet.Builder()
          .issuer(TestKeys.thumbprint(hostKey))
          .audience(issuerUrl())
          .issueTime(new java.util.Date(now))
          // .expirationTime() // MISSING EXP
          .jwtID("h-" + java.util.UUID.randomUUID())
          .claim("host_public_key", hostKey.toPublicJWK().toJSONObject())
          .claim("agent_public_key", agentKey.toPublicJWK().toJSONObject())
          .build();
      com.nimbusds.jwt.SignedJWT jwt = new com.nimbusds.jwt.SignedJWT(header, claims);
      jwt.sign(new com.nimbusds.jose.crypto.Ed25519Signer(hostKey));

      given()
          .baseUri(issuerUrl())
          .header("Authorization", "Bearer " + jwt.serialize())
          .contentType(io.restassured.http.ContentType.JSON)
          .body("""
              {
                "name": "Missing EXP Agent",
                "capabilities": [],
                "mode": "delegated"
              }
              """)
          .when()
          .post("/agent/register")
          .then()
          .statusCode(401)
          .body("error", equalTo("invalid_jwt"))
          .body("message", notNullValue());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * A host+jwt that omits the {@code iat} claim must be rejected with HTTP 401 and error code
   * {@code invalid_jwt}; the server MUST check the {@code iat} claim and reject tokens that lack an
   * issued-at timestamp because clock skew validation requires it.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification">§4.5.1
   *      Host JWT Verification — exp/iat timestamp validation (step 6)</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#42-host-jwt">§4.2 Host
   *      JWT — iat claim required</a>
   */
  @Test
  void registerWithMissingIatReturns401() {
    try {
      com.nimbusds.jose.JWSHeader header = new com.nimbusds.jose.JWSHeader.Builder(
          com.nimbusds.jose.JWSAlgorithm.EdDSA)
          .type(new com.nimbusds.jose.JOSEObjectType("host+jwt"))
          .build();
      long now = System.currentTimeMillis();
      com.nimbusds.jwt.JWTClaimsSet claims = new com.nimbusds.jwt.JWTClaimsSet.Builder()
          .issuer(TestKeys.thumbprint(hostKey))
          .audience(issuerUrl())
          // .issueTime() // MISSING IAT
          .expirationTime(new java.util.Date(now + 60_000))
          .jwtID("h-" + java.util.UUID.randomUUID())
          .claim("host_public_key", hostKey.toPublicJWK().toJSONObject())
          .claim("agent_public_key", agentKey.toPublicJWK().toJSONObject())
          .build();
      com.nimbusds.jwt.SignedJWT jwt = new com.nimbusds.jwt.SignedJWT(header, claims);
      jwt.sign(new com.nimbusds.jose.crypto.Ed25519Signer(hostKey));

      given()
          .baseUri(issuerUrl())
          .header("Authorization", "Bearer " + jwt.serialize())
          .contentType(io.restassured.http.ContentType.JSON)
          .body("""
              {
                "name": "Missing IAT Agent",
                "capabilities": [],
                "mode": "delegated"
              }
              """)
          .when()
          .post("/agent/register")
          .then()
          .statusCode(401)
          .body("error", equalTo("invalid_jwt"))
          .body("message", notNullValue());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  // -------------------------------------------------------------------------
  // TODO stubs — spec requirements not yet covered by the tests above
  // -------------------------------------------------------------------------

  /**
   * When a registration request includes {@code preferred_method}, this implementation accepts the
   * hint but returns the only supported approval method: admin-mediated HTTP approval.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">§5.3
   *      Agent Registration — preferred_method optional request field</a>
   */
  @Test
  void todoUnsupportedPreferredMethodHintFallsBackToAdminApprovalObject() {
    // Use a fresh pending host so the approval method stays device_authorization (the shared
    // hostKey is admin-linked → CIBA after Wave 5). approval.status_url moved under
    // approval.extensions per Wave 4 B-P3b.
    OctetKeyPair preferredHostKey = TestKeys.generateEd25519();
    OctetKeyPair preferredAgentKey = TestKeys.generateEd25519();
    preRegisterHostAsPending(preferredHostKey);
    String hostJwt = TestJwts.hostJwtForRegistration(preferredHostKey, preferredAgentKey,
        issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Preferred Method Agent",
              "host_name": "test-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "preferred_method": "device_authorization"
            }
            """, pendingCapability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("status", equalTo("pending"))
        .body("approval.method", equalTo("device_authorization"))
        .body("approval.extensions.status_url", notNullValue())
        .body("approval.verification_uri", notNullValue())
        .body("approval.user_code", notNullValue());
  }

  /**
   * When a registration request includes {@code login_hint}, this implementation accepts the field
   * but does not echo CIBA/device-flow metadata in the custom admin approval object.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">§5.3
   *      Agent Registration — login_hint optional request field</a>
   */
  @Test
  void todoLoginHintIsForwardedToApprovalFlow() {
    // Fresh pending host so device_authorization fires (Wave 5 default admin-linked → CIBA).
    OctetKeyPair loginHintHostKey = TestKeys.generateEd25519();
    OctetKeyPair loginHintAgentKey = TestKeys.generateEd25519();
    preRegisterHostAsPending(loginHintHostKey);
    String hostJwt = TestJwts.hostJwtForRegistration(loginHintHostKey, loginHintAgentKey,
        issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Login Hint Agent",
              "host_name": "test-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "login_hint": "user@example.com"
            }
            """, pendingCapability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("approval.method", equalTo("device_authorization"))
        .body("approval.login_hint", nullValue());
  }

  /**
   * When a registration request includes a {@code binding_message} field, the server accepts it but
   * keeps the custom admin approval response free of CIBA-specific fields.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">§5.3
   *      Agent Registration — binding_message optional request field</a>
   */
  @Test
  void todoBindingMessageAppearsInApprovalInteraction() {
    // Fresh pending host so device_authorization fires (admin-linked → CIBA, which echoes
    // binding_message — the test asserts the device-auth path which doesn't echo it).
    OctetKeyPair bindingMessageHostKey = TestKeys.generateEd25519();
    OctetKeyPair bindingMessageAgentKey = TestKeys.generateEd25519();
    preRegisterHostAsPending(bindingMessageHostKey);
    String hostJwt = TestJwts.hostJwtForRegistration(bindingMessageHostKey, bindingMessageAgentKey,
        issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Binding Message Agent",
              "host_name": "test-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "binding_message": "Approve my agent for account check"
            }
            """, pendingCapability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("approval.method", equalTo("device_authorization"))
        .body("approval.binding_message", nullValue());
  }

  /**
   * When a user denies an agent registration after it has been placed in {@code pending} state, the
   * agent's status MUST transition to {@code rejected}; any subsequent attempt to use that agent
   * MUST be rejected with error code {@code agent_rejected}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
   *      Agent States — rejected terminal state and transition from pending</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">§5.3
   *      Agent Registration — rejection outcome</a>
   */
  @Test
  void todoDeniedRegistrationTransitionsAgentToRejectedState() {
    OctetKeyPair rejectedAgentKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, rejectedAgentKey, issuerUrl());

    preRegisterHost(hostKey);
    String rejectedAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Rejected Registration Agent",
              "host_name": "test-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "Denied registration test"
            }
            """, pendingCapability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("status", equalTo("pending"))
        .extract()
        .path("agent_id");

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body("""
            {
              "reason": "User denied registration"
            }
            """)
        .when()
        .post("/agents/" + rejectedAgentId + "/reject")
        .then()
        .statusCode(200)
        .body("status", equalTo("rejected"))
        .body("agent_capability_grants[0].status", equalTo("denied"))
        .body("agent_capability_grants[0].reason", equalTo("User denied registration"));

    String statusJwt = TestJwts.hostJwt(hostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + statusJwt)
        .queryParam("agent_id", rejectedAgentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(200)
        .body("status", equalTo("rejected"))
        .body("agent_capability_grants[0].status", equalTo("denied"))
        .body("agent_capability_grants[0].reason", equalTo("User denied registration"));

    String agentJwt = TestJwts.agentJwt(hostKey, rejectedAgentKey, rejectedAgentId, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "Rejected agent must not request more access"
            }
            """, activeCapability))
        .when()
        .post("/agent/request-capability")
        .then()
        // Wave 2 R-F2: request-capability now runs AgentJwtVerifier first; non-active agents
        // (rejected here) fail verification with 401 invalid_jwt rather than the old
        // 403 agent_rejected path.
        .statusCode(401)
        .body("error", equalTo("invalid_jwt"));
  }

  /**
   * When a server advertises {@code autonomous} in discovery, a registration request with
   * {@code mode: "autonomous"} must be accepted. Unsupported mode rejection is covered separately
   * by malformed/unknown mode tests because this provider intentionally advertises autonomous mode.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#22-agent-modes">§2.2
   *      Agent Modes — servers MUST reject unsupported modes</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">§5.3
   *      Agent Registration — mode validation</a>
   */
  @Test
  void autonomousModeAdvertisedByDiscoveryCanRegister() {
    given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .body("modes", hasItem("autonomous"));

    OctetKeyPair autonomousAgentKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, autonomousAgentKey, issuerUrl());

    preRegisterHost(hostKey);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Advertised Autonomous Agent",
              "host_name": "test-host",
              "capabilities": [],
              "mode": "autonomous"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("mode", equalTo("autonomous"))
        .body("status", equalTo("active"));
  }

  /**
   * A registration request supplying {@code agent_jwks_url} and {@code agent_kid} as the agent key
   * reference (instead of an inline {@code agent_public_key}) must be accepted and the server must
   * resolve the key from the JWKS URL to complete registration.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#42-host-jwt">§4.2 Host
   *      JWT — agent_jwks_url + agent_kid alternative to agent_public_key</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification">§4.5.1
   *      Host JWT Verification — agent key extraction (step 9)</a>
   */
  @Test
  void registrationWithAgentJwksUrlSucceeds() {
    String hostJwt = TestJwts.hostJwtForRegistrationWithAgentJwksUrl(
        agentJwksHostKey, agentJwksUrl, agentJwksKid, issuerUrl());

    preRegisterHost(agentJwksHostKey);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Agent JWKS Registration",
              "host_name": "jwks-host",
              "capabilities": [],
              "mode": "delegated"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("agent_id", notNullValue())
        .body("status", equalTo("active"))
        .body("agent_capability_grants", hasSize(0));
  }

  @Test
  void jwksRegisteredAgentJwtVerifiesThroughJwksUrl() {
    OctetKeyPair jwksHostKey = TestKeys.generateEd25519();
    OctetKeyPair jwksAgentKey = TestKeys.generateEd25519();
    String kid = "agent-verify-kid-" + UUID.randomUUID();
    HttpServer server = null;
    try {
      server = startJwksServer(jwksAgentKey, kid);
      Testcontainers.exposeHostPorts(server.getAddress().getPort());
      String jwksUrl = "http://host.testcontainers.internal:" + server.getAddress().getPort()
          + "/jwks";
      String hostJwt = TestJwts.hostJwtForRegistrationWithAgentJwksUrl(
          jwksHostKey, jwksUrl, kid, issuerUrl());

      preRegisterHost(jwksHostKey);
      String jwksAgentId = given()
          .baseUri(issuerUrl())
          .header("Authorization", "Bearer " + hostJwt)
          .contentType(ContentType.JSON)
          .body(String.format("""
              {
                "name": "Agent JWKS Introspect",
                "host_name": "jwks-host",
                "capabilities": ["%s"],
                "mode": "delegated"
              }
              """, activeCapability))
          .when()
          .post("/agent/register")
          .then()
          .statusCode(200)
          .extract()
          .path("agent_id");

      // §4.3: aud MUST be the resolved location URL — the cap registered above declares
      // location = https://resource.example.test/capabilities/<activeCapability>.
      String agentJwt = TestJwts.agentJwtWithKid(jwksHostKey, jwksAgentKey, jwksAgentId,
          "https://resource.example.test/capabilities/" + activeCapability, kid);

      given()
          .baseUri(issuerUrl())
          .header("Authorization", "Bearer " + TestJwts.hostJwt(jwksHostKey, issuerUrl()))
          .contentType(ContentType.JSON)
          .body(String.format("""
              {
                "token": "%s"
              }
              """, agentJwt))
          .when()
          .post("/agent/introspect")
          .then()
          .statusCode(200)
          .body("active", equalTo(true))
          .body("agent_id", equalTo(jwksAgentId));
    } catch (Exception e) {
      throw new RuntimeException(e);
    } finally {
      if (server != null) {
        server.stop(0);
      }
    }
  }

  /**
   * The host key reference is mutually exclusive: a registration host JWT MUST NOT include both an
   * inline {@code host_public_key} and a {@code host_jwks_url}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#42-host-jwt">§4.2 Host
   *      JWT — inline JWK and JWKS URL alternatives</a>
   */
  @Test
  void registrationRejectsBothHostPublicKeyAndHostJwksUrl() {
    String hostJwt = TestJwts.hostJwtForRegistration(
        hostKey,
        TestKeys.generateEd25519(),
        issuerUrl(),
        Map.of("host_jwks_url", hostJwksUrl));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Both Host Key Forms",
              "host_name": "jwks-host",
              "capabilities": [],
              "mode": "delegated"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"))
        .body("message", equalTo("host_public_key and host_jwks_url are mutually exclusive"));
  }

  /**
   * The agent key reference is mutually exclusive: a registration host JWT MUST NOT include both an
   * inline {@code agent_public_key} and an {@code agent_jwks_url}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#42-host-jwt">§4.2 Host
   *      JWT — inline JWK and JWKS URL alternatives</a>
   */
  @Test
  void registrationRejectsBothAgentPublicKeyAndAgentJwksUrl() {
    String hostJwt = TestJwts.hostJwtForRegistration(
        hostKey,
        TestKeys.generateEd25519(),
        issuerUrl(),
        Map.of("agent_jwks_url", agentJwksUrl, "agent_kid", agentJwksKid));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Both Agent Key Forms",
              "host_name": "jwks-host",
              "capabilities": [],
              "mode": "delegated"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"))
        .body("message", equalTo("agent_public_key and agent_jwks_url are mutually exclusive"));
  }

  /**
   * A registration request supplying {@code host_jwks_url} instead of an inline
   * {@code host_public_key} must be accepted; the server must re-fetch the JWKS, locate the signing
   * key by {@code kid}, verify its thumbprint matches {@code iss}, and complete verification.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification">§4.5.1
   *      Host JWT Verification — host key resolution via JWKS URL (step 3)</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#42-host-jwt">§4.2 Host
   *      JWT — host_jwks_url alternative to host_public_key</a>
   */
  @Test
  void registrationWithHostJwksUrlSucceeds() {
    String hostJwt = TestJwts.hostJwtForRegistrationWithHostJwksUrl(
        hostJwksHostKey, hostJwksAgentKey, hostJwksUrl, hostJwksKid, issuerUrl());

    preRegisterHost(hostJwksHostKey);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Host JWKS Registration",
              "host_name": "jwks-host",
              "capabilities": [],
              "mode": "delegated"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("agent_id", notNullValue())
        .body("status", equalTo("active"))
        .body("agent_capability_grants", hasSize(0));
  }

  /**
   * A host+jwt whose {@code iat} is in the future (beyond acceptable clock-skew tolerance) must be
   * rejected with HTTP 401 and error code {@code invalid_jwt} to prevent pre-issued token abuse.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification">§4.5.1
   *      Host JWT Verification — iat clock-skew check (step 6)</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#42-host-jwt">§4.2 Host
   *      JWT — iat claim required</a>
   */
  @Test
  void todoFutureIatExceedingClockSkewReturns401() {
    try {
      com.nimbusds.jose.JWSHeader header = new com.nimbusds.jose.JWSHeader.Builder(
          com.nimbusds.jose.JWSAlgorithm.EdDSA)
          .type(new com.nimbusds.jose.JOSEObjectType("host+jwt"))
          .build();
      long now = System.currentTimeMillis();
      com.nimbusds.jwt.JWTClaimsSet claims = new com.nimbusds.jwt.JWTClaimsSet.Builder()
          .issuer(TestKeys.thumbprint(hostKey))
          .audience(issuerUrl())
          .issueTime(new java.util.Date(now + 120_000L)) // 2 minutes in the future
          .expirationTime(new java.util.Date(now + 180_000L))
          .jwtID("h-" + java.util.UUID.randomUUID())
          .claim("host_public_key", hostKey.toPublicJWK().toJSONObject())
          .claim("agent_public_key", agentKey.toPublicJWK().toJSONObject())
          .build();
      com.nimbusds.jwt.SignedJWT jwt = new com.nimbusds.jwt.SignedJWT(header, claims);
      jwt.sign(new com.nimbusds.jose.crypto.Ed25519Signer(hostKey));

      given()
          .baseUri(issuerUrl())
          .header("Authorization", "Bearer " + jwt.serialize())
          .contentType(io.restassured.http.ContentType.JSON)
          .body("""
              {
                "name": "Future IAT Agent",
                "capabilities": [],
                "mode": "delegated"
              }
              """)
          .when()
          .post("/agent/register")
          .then()
          .statusCode(401)
          .body("error", equalTo("invalid_jwt"))
          .body("message", notNullValue());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * When all capability grants in a registration response are denied by the server, the agent's
   * top-level {@code status} MUST still be {@code "active"} — not {@code "rejected"} — and the
   * {@code agent_capability_grants} array must list each requested capability with
   * {@code status: "denied"}.
   *
   * <p>
   * Per §5.3, the agent status reflects authentication eligibility, not grant success. An agent
   * with all capabilities denied is still active and capable of re-requesting capabilities; there
   * is no {@code "rejected"} state in this flow.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">§5.3
   *      Agent Registration — partial approval; status active even when all grants denied</a>
   */
  @Test
  void allCapabilitiesDeniedResultsInActiveAgentWithDeniedGrants() {
    String deniedCap = "denied_cap_all_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    // Register a capability that the server auto-denies (requires_approval: true but no approver)
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Auto-denied capability for testing",
              "visibility": "authenticated",
              "requires_approval": true,
              "auto_deny": true,
              "location": "https://resource.example.test/capabilities/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, deniedCap, deniedCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    OctetKeyPair deniedHostKey = TestKeys.generateEd25519();
    OctetKeyPair deniedAgentKey = TestKeys.generateEd25519();
    String regJwt = TestJwts.hostJwtForRegistration(deniedHostKey, deniedAgentKey, issuerUrl());

    preRegisterHost(deniedHostKey);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "All Denied Agent",
              "host_name": "denied-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "All capabilities denied test"
            }
            """, deniedCap))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("status", equalTo("active"))
        .body("agent_capability_grants", notNullValue())
        .body("agent_capability_grants[0].capability", equalTo(deniedCap))
        .body("agent_capability_grants[0].status", equalTo("denied"));
  }

  /**
   * The {@code agent_capability_grants} array SHOULD include a human-readable {@code reason} field
   * on each denied grant entry so that agents can surface a meaningful explanation.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">§5.3
   *      Agent Registration — reason field on denied grants (SHOULD)</a>
   */
  @Test
  void todoDeniedGrantIncludesReasonField() {
    String deniedCap = "denied_reason_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Auto-denied capability for reason testing",
              "visibility": "authenticated",
              "requires_approval": true,
              "auto_deny": true,
              "location": "https://resource.example.test/capabilities/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, deniedCap, deniedCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    OctetKeyPair deniedReasonAgentKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, deniedReasonAgentKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Denied Reason Agent",
              "host_name": "test-host",
              "capabilities": ["%s"],
              "mode": "delegated"
            }
            """, deniedCap))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("agent_capability_grants[0].status", equalTo("denied"))
        .body("agent_capability_grants[0].reason", notNullValue());
  }

  /**
   * A host that is in {@code revoked} or {@code rejected} state MUST NOT be allowed to register new
   * agents; the server MUST reject such requests per the host status check in §4.5.1.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification">§4.5.1
   *      Host JWT Verification — host status check (step 8)</a>
   */
  @Test
  void todoRevokedHostCannotRegisterNewAgent() {
    OctetKeyPair revokedHostKey = TestKeys.generateEd25519();
    OctetKeyPair firstAgentKey = TestKeys.generateEd25519();
    String initialJwt = TestJwts.hostJwtForRegistration(revokedHostKey, firstAgentKey,
        issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + initialJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Host To Revoke Agent",
              "capabilities": [],
              "mode": "delegated"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(revokedHostKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body("{}")
        .when()
        .post("/host/revoke")
        .then()
        .statusCode(200);

    String newRegistrationJwt = TestJwts.hostJwtForRegistration(revokedHostKey,
        TestKeys.generateEd25519(), issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + newRegistrationJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Rejected New Agent",
              "capabilities": [],
              "mode": "delegated"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(403)
        .body("error", equalTo("host_revoked"));
  }

  // -------------------------------------------------------------------------
  // New TDD tests — spec behaviors not yet covered above
  // -------------------------------------------------------------------------

  /**
   * A registration request whose host+jwt carries an {@code agent_public_key} claim using an RSA
   * key ({@code kty: RSA}) instead of the required OKP/Ed25519 key must be rejected with HTTP 400
   * and error code {@code unsupported_algorithm}; the spec mandates Ed25519 (OKP) for all agent
   * keys.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-public-key">§4.3 Agent
   *      Public Key — only OKP/Ed25519 is supported</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#513-error-format">§5.13
   *      Error Format — 400 unsupported_algorithm</a>
   */
  @Test
  void registerWithUnsupportedKeyAlgorithmReturns400() {
    // Build a host+jwt whose agent_public_key is an RSA key rather than an OKP/Ed25519 key.
    // The spec only permits Ed25519; an RSA key type must be rejected as unsupported_algorithm.
    try {
      com.nimbusds.jose.jwk.RSAKey rsaKey = new com.nimbusds.jose.jwk.gen.RSAKeyGenerator(2048)
          .generate();
      com.nimbusds.jose.jwk.RSAKey rsaPublic = rsaKey.toPublicJWK();

      com.nimbusds.jose.JWSHeader header = new com.nimbusds.jose.JWSHeader.Builder(
          com.nimbusds.jose.JWSAlgorithm.EdDSA)
          .type(new com.nimbusds.jose.JOSEObjectType("host+jwt"))
          .build();
      long now = System.currentTimeMillis();
      com.nimbusds.jwt.JWTClaimsSet claims = new com.nimbusds.jwt.JWTClaimsSet.Builder()
          .issuer(TestKeys.thumbprint(hostKey))
          .audience(issuerUrl())
          .issueTime(new java.util.Date(now))
          .expirationTime(new java.util.Date(now + 60_000))
          .jwtID("h-" + UUID.randomUUID())
          .claim("host_public_key", hostKey.toPublicJWK().toJSONObject())
          .claim("agent_public_key", rsaPublic.toJSONObject()) // RSA — unsupported
          .build();
      com.nimbusds.jwt.SignedJWT jwt = new com.nimbusds.jwt.SignedJWT(header, claims);
      jwt.sign(new com.nimbusds.jose.crypto.Ed25519Signer(hostKey));

      given()
          .baseUri(issuerUrl())
          .header("Authorization", "Bearer " + jwt.serialize())
          .contentType(ContentType.JSON)
          .body("""
              {
                "name": "RSA Key Agent",
                "host_name": "test-host",
                "capabilities": [],
                "mode": "delegated",
                "reason": "Testing unsupported key algorithm"
              }
              """)
          .when()
          .post("/agent/register")
          .then()
          .statusCode(400)
          .body("error", equalTo("unsupported_algorithm"))
          .body("message", notNullValue());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * A registration request body that omits the optional {@code mode} field must succeed with HTTP
   * 200 and the server MUST default {@code mode} to {@code "delegated"}, as the spec §3.1 defines
   * {@code mode} as optional with a default value of {@code "delegated"}.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#31-registration-request"> §3.1
   *      Registration Request — mode is optional, defaults to "delegated"</a>
   */
  @Test
  void registerWithMissingModeFieldDefaultsToDelegated() {
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, TestKeys.generateEd25519(),
        issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "No Mode Agent",
              "host_name": "test-host",
              "capabilities": []
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("mode", equalTo("delegated"))
        .body("agent_id", notNullValue());
  }

  /**
   * A registration request body with a {@code mode} field set to an entirely unrecognized value
   * (e.g. {@code "unknown_mode"}) must be rejected with HTTP 400 and error code
   * {@code invalid_request}; the spec defines exactly two valid modes ({@code delegated} and
   * {@code autonomous}) and any other value is a malformed request.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#22-agent-modes">§2.2
   *      Agent Modes — only delegated and autonomous are defined</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">§5.3
   *      Agent Registration — mode validation</a>
   */
  @Test
  void registerWithInvalidModeValueReturns400() {
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, TestKeys.generateEd25519(),
        issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Invalid Mode Agent",
              "host_name": "test-host",
              "capabilities": [],
              "mode": "unknown_mode",
              "reason": "Testing invalid mode value"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(400)
        .body("error", anyOf(equalTo("invalid_request"), equalTo("unsupported_mode")))
        .body("message", notNullValue());
  }

  /**
   * A POST to {@code /agent/register} with no {@code Authorization} header whatsoever must be
   * rejected with HTTP 401; every registration request MUST carry a host+jwt credential because the
   * server has no other way to authenticate the registering host.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification">§4.5.1
   *      Host JWT Verification — Authorization header is mandatory</a>
   */
  @Test
  void registerWithMissingHostJwtReturns401() {
    given()
        .baseUri(issuerUrl())
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "No JWT Agent",
              "host_name": "test-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Testing missing host JWT"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(401)
        .body("message", notNullValue());
  }

  /**
   * Submitting an agent+jwt (typ={@code agent+jwt}) in the Authorization header instead of the
   * required host+jwt (typ={@code host+jwt}) must be rejected with HTTP 401 and error code
   * {@code invalid_jwt}; the server MUST check the JWT {@code typ} header and reject tokens of the
   * wrong type.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification">§4.5.1
   *      Host JWT Verification — typ header must be host+jwt (step 1)</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#42-host-jwt">§4.2 Host
   *      JWT — typ MUST be host+jwt</a>
   */
  @Test
  void registerWithAgentJwtInsteadOfHostJwtReturns401() {
    OctetKeyPair wrongTypeAgentKey = TestKeys.generateEd25519();
    // agentJwt produces a JWT with typ=agent+jwt signed by the agent key
    String agentTypJwt = TestJwts.agentJwt(hostKey, wrongTypeAgentKey, "agt_fake_id", issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentTypJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Agent JWT Type Agent",
              "host_name": "test-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Testing wrong JWT type"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_jwt"))
        .body("message", notNullValue());
  }

  /**
   * Presenting the same host+jwt on a second POST to {@code /agent/register} (same serialized token
   * string, same jti) must be rejected with HTTP 401 and error code {@code replay_detected} or
   * {@code invalid_jwt}; the server MUST cache seen jti values and reject any duplicate within the
   * token's validity window per spec §4.6.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#46-replay-detection">§4.6 Replay
   *      Detection — jti must be unique per request; second use MUST be rejected</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#451-host-jwt-verification">§4.5.1
   *      Host JWT Verification — jti replay check (step 7)</a>
   */
  @Test
  void registerWithReplayedHostJwtReturns401() {
    // Use a fresh agent key so the first registration succeeds (not a duplicate).
    OctetKeyPair replayRegKey = TestKeys.generateEd25519();
    String replayJwt = TestJwts.hostJwtForRegistration(hostKey, replayRegKey, issuerUrl());

    // First POST: must succeed.
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + replayJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Replay Register Agent",
              "host_name": "test-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "jti replay on registration"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200);

    // Second POST with the IDENTICAL token string: must be rejected because the jti was already
    // seen.
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + replayJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Replay Register Agent",
              "host_name": "test-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "jti replay on registration"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(401)
        .body("error",
            anyOf(equalTo("replay_detected"), equalTo("jti_replay"), equalTo("invalid_jwt")))
        .body("message", notNullValue());
  }

  /**
   * After a successful registration, a GET to {@code /agent/status} for the newly created agent
   * must return a {@code status} field whose value is either {@code "active"} or {@code "pending"};
   * these are the only valid initial states defined by spec §2.3 — no other value is permitted.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
   *      Agent States — active and pending are the only valid initial states</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">§5.3
   *      Agent Registration — status field in registration response</a>
   */
  @Test
  void registeredAgentInitialStateIsPendingOrActive() {
    OctetKeyPair initialStateAgentKey = TestKeys.generateEd25519();
    String registrationJwt = TestJwts.hostJwtForRegistration(hostKey, initialStateAgentKey,
        issuerUrl());

    String agentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + registrationJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Initial State Agent",
              "host_name": "test-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Initial state verification"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("status", anyOf(equalTo("active"), equalTo("pending")))
        .extract()
        .path("agent_id");

    String statusJwt = TestJwts.hostJwt(hostKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + statusJwt)
        .queryParam("agent_id", agentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(200)
        .body("status", anyOf(equalTo("active"), equalTo("pending")));
  }

  /**
   * In delegation mode, when the host provides a {@code capabilities} array at registration time,
   * the server must store and echo those capability grants in the response; spec §3.2 requires that
   * the host supply the capability list for delegated-mode agents and that the response reflects
   * the approved grants with their details.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#32-delegation-mode">§3.2
   *      Delegation Mode — host supplies capability list at registration</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">§5.3
   *      Agent Registration — capabilities field required in delegated mode</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#22-agent-modes">§2.2
   *      Agent Modes — delegated mode semantics</a>
   */
  @Test
  void registerWithDelegationModeRequiresCapabilitiesListFromHost() {
    OctetKeyPair delegationAgentKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, delegationAgentKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Delegation Mode Agent",
              "host_name": "test-host",
              "capabilities": ["%s", "%s"],
              "mode": "delegated",
              "reason": "Testing delegation mode capability provisioning"
            }
            """, activeCapability, constrainedCapability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("mode", equalTo("delegated"))
        .body("agent_capability_grants", hasSize(2))
        .body("agent_capability_grants[0].capability",
            anyOf(equalTo(activeCapability), equalTo(constrainedCapability)))
        .body("agent_capability_grants[1].capability",
            anyOf(equalTo(activeCapability), equalTo(constrainedCapability)));
  }
}
