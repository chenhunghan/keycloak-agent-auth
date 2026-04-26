package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.notNullValue;

import com.github.chh.keycloak.agentauth.support.BaseKeycloakIT;
import com.github.chh.keycloak.agentauth.support.TestJwts;
import com.github.chh.keycloak.agentauth.support.TestKeys;
import com.nimbusds.jose.jwk.OctetKeyPair;
import io.restassured.http.ContentType;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * Integration tests for agent and host lifecycle operations.
 *
 * <p>
 * Tests are ordered because lifecycle operations depend on prior state (register → check status →
 * rotate keys → revoke).
 *
 * <p>
 * Spec sections covered by this file:
 * <ul>
 * <li>§5.5 Status — {@code GET /agent/status} {@link <a href=
 * "https://agent-auth-protocol.com/specification/v1.0-draft#55-status">§5.5</a>}</li>
 * <li>§5.6 Reactivate — {@code POST /agent/reactivate} {@link <a href=
 * "https://agent-auth-protocol.com/specification/v1.0-draft#56-reactivate">§5.6</a>}</li>
 * <li>§5.7 Revoke — {@code POST /agent/revoke} {@link <a href=
 * "https://agent-auth-protocol.com/specification/v1.0-draft#57-revoke">§5.7</a>}</li>
 * <li>§5.8 Key Rotation — {@code POST /agent/rotate-key} {@link <a href=
 * "https://agent-auth-protocol.com/specification/v1.0-draft#58-key-rotation">§5.8</a>}</li>
 * <li>§5.9 Rotate Host Key — {@code POST /host/rotate-key} {@link <a href=
 * "https://agent-auth-protocol.com/specification/v1.0-draft#59-rotate-host-key">§5.9</a>}</li>
 * <li>§5.10 Revoke Host — {@code POST /host/revoke} {@link <a href=
 * "https://agent-auth-protocol.com/specification/v1.0-draft#510-revoke-host">§5.10</a>}</li>
 * <li>§2.3 Agent States — pending, active, expired, revoked, rejected, claimed {@link <a href=
 * "https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3</a>}</li>
 * <li>§2.4 Lifetime Clocks — session TTL, max lifetime, absolute lifetime {@link <a href=
 * "https://agent-auth-protocol.com/specification/v1.0-draft#24-lifetime-clocks">§2.4</a>}</li>
 * <li>§2.5 Reactivation — capability decay and clock reset rules {@link <a href=
 * "https://agent-auth-protocol.com/specification/v1.0-draft#25-reactivation">§2.5</a>}</li>
 * <li>§2.6 Revocation — permanent revocation and who may initiate it {@link <a href=
 * "https://agent-auth-protocol.com/specification/v1.0-draft#26-revocation">§2.6</a>}</li>
 * </ul>
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AgentAuthLifecycleIT extends BaseKeycloakIT {

  private static OctetKeyPair currentHostKey;
  private static OctetKeyPair previousHostKey;
  private static OctetKeyPair initialAgentKey;
  private static OctetKeyPair rotatedAgentKey;
  private static String agentId;
  private static String lifecycleCap;

  /**
   * §4.3 resolved location URL of {@link #lifecycleCap} — the agent+jwt's {@code aud} claim MUST be
   * set to this URL for execution-token introspection to succeed.
   */
  private static String lifecycleCapLocation() {
    return "https://resource.example.test/lifecycle/" + lifecycleCap;
  }

  @BeforeAll
  static void generateKeys() {
    currentHostKey = TestKeys.generateEd25519();
    initialAgentKey = TestKeys.generateEd25519();
    lifecycleCap = "lifecycle_cap_" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Lifecycle test capability (auto-approved)",
              "visibility": "authenticated",
              "requires_approval": false,
              "location": "https://resource.example.test/lifecycle/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, lifecycleCap, lifecycleCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);
  }

  /**
   * Registers an agent as a prerequisite for all subsequent lifecycle tests.
   *
   * <p>
   * The registration endpoint returns {@code agent_id} which is used by every later test in this
   * ordered sequence.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#55-status">§5.5
   *      Status</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
   *      Agent States</a>
   */
  @Test
  @Order(1)
  void registerAgentForLifecycleTests() {
    String hostJwt = TestJwts.hostJwtForRegistration(currentHostKey, initialAgentKey, issuerUrl());
    preRegisterHost(currentHostKey);

    agentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Lifecycle Test Agent",
              "host_name": "lifecycle-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "Lifecycle integration tests"
            }
            """, lifecycleCap))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");
  }

  /**
   * Verifies that {@code GET /agent/status} returns full agent metadata including {@code agent_id},
   * {@code host_id}, {@code name}, {@code mode}, {@code status}, and
   * {@code agent_capability_grants} for an active agent.
   *
   * <p>
   * Per §5.5, the status endpoint must return comprehensive lifecycle metadata and all capability
   * grants; it is the only endpoint guaranteed to return all grant metadata including
   * {@code granted_by}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#55-status">§5.5
   *      Status</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
   *      Agent States</a>
   */
  @Test
  @Order(2)
  void getAgentStatusReturnsAgentDetails() {
    String hostJwt = TestJwts.hostJwt(currentHostKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .queryParam("agent_id", agentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(200)
        .body("agent_id", equalTo(agentId))
        .body("host_id", notNullValue())
        .body("name", equalTo("Lifecycle Test Agent"))
        .body("mode", equalTo("delegated"))
        .body("status", equalTo("active"))
        .body("agent_capability_grants", notNullValue());
  }

  /**
   * Verifies that {@code GET /agent/status} without an {@code Authorization} header returns
   * {@code 401 authentication_required}.
   *
   * <p>
   * Per §5.5, a valid host JWT is required; absent credentials must be rejected before any agent
   * lookup is performed.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#55-status">§5.5
   *      Status</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes –
   *      authentication_required</a>
   */
  @Test
  @Order(3)
  void getAgentStatusWithoutAuthReturns401() {
    given()
        .baseUri(issuerUrl())
        .queryParam("agent_id", agentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(401)
        .body("error", equalTo("authentication_required"))
        .body("message", notNullValue());
  }

  /**
   * Verifies that {@code GET /agent/status} for an unknown {@code agent_id} returns
   * {@code 404 agent_not_found}.
   *
   * <p>
   * Per §5.5, when the requested agent does not exist under the calling host the server must
   * respond with a 404 error.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#55-status">§5.5
   *      Status</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes – agent_not_found</a>
   */
  @Test
  @Order(4)
  void getAgentStatusForNonexistentAgentReturns404() {
    String hostJwt = TestJwts.hostJwt(currentHostKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .queryParam("agent_id", "agt_nonexistent_999")
        .when()
        .get("/agent/status")
        .then()
        .statusCode(404)
        .body("error", equalTo("agent_not_found"))
        .body("message", notNullValue());
  }

  /**
   * Verifies that a host cannot query status for an agent registered under a different host,
   * receiving {@code 403 unauthorized}.
   *
   * <p>
   * Per §5.5, the server must verify the agent belongs to the requesting host before returning any
   * data; cross-host access must be denied.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#55-status">§5.5
   *      Status</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes – unauthorized</a>
   */
  @Test
  @Order(5)
  void getAgentStatusFromDifferentHostReturns403() {
    OctetKeyPair otherHostKey = TestKeys.generateEd25519();
    String otherHostJwt = TestJwts.hostJwt(otherHostKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + otherHostJwt)
        .queryParam("agent_id", agentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(403)
        .body("error", equalTo("unauthorized"))
        .body("message", notNullValue());
  }

  /**
   * Verifies that calling {@code POST /agent/reactivate} on an already-active agent is a no-op that
   * returns {@code 200} with {@code status: "active"}.
   *
   * <p>
   * Per §5.6 step 1, if the agent is already {@code active} the server must return the current
   * status without performing any state change.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#56-reactivate">§5.6
   *      Reactivate</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
   *      Agent States</a>
   */
  @Test
  @Order(6)
  void reactivateActiveAgentReturnsCurrentStatusAsNoOp() {
    String hostJwt = TestJwts.hostJwt(currentHostKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s"
            }
            """, agentId))
        .when()
        .post("/agent/reactivate")
        .then()
        .statusCode(200)
        .body("agent_id", equalTo(agentId))
        .body("status", equalTo("active"));
  }

  /**
   * Verifies that {@code POST /agent/rotate-key} successfully replaces an agent's public key,
   * returning {@code 200} with {@code status: "active"}.
   *
   * <p>
   * Per §5.8, the host may rotate the agent's key at any time; the request must supply the new
   * Ed25519 public key in JWK format alongside the {@code agent_id}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#58-key-rotation">§5.8
   *      Key Rotation</a>
   */
  @Test
  @Order(7)
  void rotateAgentKeySucceeds() {
    String hostJwt = TestJwts.hostJwt(currentHostKey, issuerUrl());
    rotatedAgentKey = TestKeys.generateEd25519();

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s",
              "public_key": %s
            }
            """, agentId, rotatedAgentKey.toPublicJWK().toJSONString()))
        .when()
        .post("/agent/rotate-key")
        .then()
        .statusCode(200)
        .body("agent_id", equalTo(agentId))
        .body("status", equalTo("active"));
  }

  /**
   * Verifies that the previous agent key is immediately invalid for introspection after a key
   * rotation, returning {@code active: false}.
   *
   * <p>
   * Per §5.8, "the old key stops working immediately" upon successful rotation; any token signed
   * with the superseded key must be treated as inactive.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#58-key-rotation">§5.8
   *      Key Rotation</a>
   */
  @Test
  @Order(8)
  void oldAgentKeyStopsWorkingImmediatelyAfterRotation() {
    String oldAgentJwt = TestJwts.agentJwt(currentHostKey, initialAgentKey, agentId,
        lifecycleCapLocation());

    given()
        .baseUri(issuerUrl())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "token": "%s"
            }
            """, oldAgentJwt))
        .when()
        .post("/agent/introspect")
        .then()
        .statusCode(200)
        .body("active", equalTo(false));
  }

  /**
   * Verifies that the newly rotated agent key is immediately valid for introspection after a key
   * rotation, returning {@code active: true}.
   *
   * <p>
   * Per §5.8, the new key is operational as soon as rotation completes; agents can continue
   * authenticating without interruption using the new key.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#58-key-rotation">§5.8
   *      Key Rotation</a>
   */
  @Test
  @Order(9)
  void newAgentKeyWorksImmediatelyAfterRotation() {
    String newAgentJwt = TestJwts.agentJwt(currentHostKey, rotatedAgentKey, agentId,
        lifecycleCapLocation());

    given()
        .baseUri(issuerUrl())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "token": "%s"
            }
            """, newAgentJwt))
        .when()
        .post("/agent/introspect")
        .then()
        .statusCode(200)
        .body("active", equalTo(true))
        .body("agent_id", equalTo(agentId));
  }

  /**
   * Verifies that {@code POST /host/rotate-key} succeeds, returning the {@code host_id} and
   * {@code status: "active"}, and that agents under the host remain accessible via the new host key
   * immediately after rotation.
   *
   * <p>
   * Per §5.9, all agents, grants, and user linkage under the host are preserved when the host key
   * is rotated; only the authentication credential changes.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#59-rotate-host-key">§5.9
   *      Rotate Host Key</a>
   */
  @Test
  @Order(10)
  void rotateHostKeySucceeds() {
    OctetKeyPair newHostKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwt(currentHostKey, issuerUrl());

    String hostId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "public_key": %s
            }
            """, newHostKey.toPublicJWK().toJSONString()))
        .when()
        .post("/host/rotate-key")
        .then()
        .statusCode(200)
        .body("host_id", notNullValue())
        .body("status", equalTo("active"))
        .extract()
        .path("host_id");

    previousHostKey = currentHostKey;
    currentHostKey = newHostKey;

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(currentHostKey, issuerUrl()))
        .queryParam("agent_id", agentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(200)
        .body("host_id", equalTo(hostId))
        .body("agent_id", equalTo(agentId));
  }

  /**
   * Verifies that a token signed with the previous host key is immediately rejected with
   * {@code 401 invalid_jwt} after a host key rotation.
   *
   * <p>
   * Per §5.9, "the old key stops working immediately" once host key rotation completes; any request
   * bearing the superseded host JWT must be denied.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#59-rotate-host-key">§5.9
   *      Rotate Host Key</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes – invalid_jwt</a>
   */
  @Test
  @Order(11)
  void oldHostKeyStopsWorkingImmediatelyAfterRotation() {
    String staleJwt = TestJwts.hostJwt(previousHostKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + staleJwt)
        .queryParam("agent_id", agentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_jwt"))
        .body("message", notNullValue());
  }

  /**
   * Verifies that {@code POST /agent/revoke} permanently revokes an agent, returning {@code 200}
   * with {@code status: "revoked"}.
   *
   * <p>
   * Per §5.7, the host may revoke any of its own agents; the operation is irreversible and the
   * response must always carry {@code status: "revoked"}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#57-revoke">§5.7
   *      Revoke</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#26-revocation">§2.6
   *      Revocation</a>
   */
  @Test
  @Order(12)
  void revokeAgentSucceeds() {
    String hostJwt = TestJwts.hostJwt(currentHostKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s"
            }
            """, agentId))
        .when()
        .post("/agent/revoke")
        .then()
        .statusCode(200)
        .body("agent_id", equalTo(agentId))
        .body("status", equalTo("revoked"));
  }

  /**
   * Verifies that {@code GET /agent/status} for a revoked agent returns {@code 200} with
   * {@code status: "revoked"}.
   *
   * <p>
   * Per §5.5, agents in any terminal state — including {@code revoked} — must still be queryable
   * via the status endpoint.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#55-status">§5.5
   *      Status</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
   *      Agent States</a>
   */
  @Test
  @Order(13)
  void revokedAgentStatusShowsRevoked() {
    String hostJwt = TestJwts.hostJwt(currentHostKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .queryParam("agent_id", agentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(200)
        .body("status", equalTo("revoked"));
  }

  /**
   * Verifies that attempting to reactivate a revoked agent returns {@code 403 agent_revoked},
   * because revocation is permanent.
   *
   * <p>
   * Per §5.6 step 1 and §2.6, revoked agents cannot be reactivated; a new agent identity must be
   * created to resume operations.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#56-reactivate">§5.6
   *      Reactivate</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#26-revocation">§2.6
   *      Revocation</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes – agent_revoked</a>
   */
  @Test
  @Order(14)
  void revokedAgentCannotBeReactivated() {
    String hostJwt = TestJwts.hostJwt(currentHostKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s"
            }
            """, agentId))
        .when()
        .post("/agent/reactivate")
        .then()
        .statusCode(403)
        .body("error", equalTo("agent_revoked"))
        .body("message", notNullValue());
  }

  /**
   * Verifies that {@code POST /agent/reactivate} with an unknown {@code agent_id} returns
   * {@code 404 agent_not_found}.
   *
   * <p>
   * Per §5.6, the server must locate the agent before validating its state; a non-existent agent
   * must produce a 404 response.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#56-reactivate">§5.6
   *      Reactivate</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes – agent_not_found</a>
   */
  @Test
  @Order(15)
  void reactivateMissingAgentReturns404() {
    String hostJwt = TestJwts.hostJwt(currentHostKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "agent_id": "agt_missing_reactivate"
            }
            """)
        .when()
        .post("/agent/reactivate")
        .then()
        .statusCode(404)
        .body("error", equalTo("agent_not_found"))
        .body("message", notNullValue());
  }

  /**
   * Verifies that {@code POST /agent/reactivate} without an {@code Authorization} header returns
   * {@code 401 authentication_required}.
   *
   * <p>
   * Per §5.6, a valid host JWT is required to reactivate an agent; missing credentials must be
   * rejected before any agent lookup occurs.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#56-reactivate">§5.6
   *      Reactivate</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes –
   *      authentication_required</a>
   */
  @Test
  @Order(16)
  void reactivateWithoutAuthReturns401() {
    given()
        .baseUri(issuerUrl())
        .contentType(ContentType.JSON)
        .body("""
            {
              "agent_id": "any_id"
            }
            """)
        .when()
        .post("/agent/reactivate")
        .then()
        .statusCode(401)
        .body("error", equalTo("authentication_required"))
        .body("message", notNullValue());
  }

  /**
   * Verifies that a host cannot reactivate an agent that belongs to a different host, receiving
   * {@code 403} or {@code 404}.
   *
   * <p>
   * Per §5.6, the server must verify the agent belongs to the requesting host; cross-host
   * reactivation must be denied (403 unauthorized) or hidden (404).
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#56-reactivate">§5.6
   *      Reactivate</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes – unauthorized</a>
   */
  @Test
  @Order(17)
  void reactivateAgentFromDifferentHostReturns403() {
    OctetKeyPair otherHostKey = TestKeys.generateEd25519();
    String otherHostJwt = TestJwts.hostJwt(otherHostKey, issuerUrl());

    // agentId was revoked in @Order(12) and belongs to currentHostKey's host;
    // a different host should see 403 (unauthorized) or 404 (agent hidden from other hosts)
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + otherHostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s"
            }
            """, agentId))
        .when()
        .post("/agent/reactivate")
        .then()
        .statusCode(anyOf(equalTo(403), equalTo(404)));
  }

  /**
   * Verifies that {@code POST /agent/revoke} without an {@code Authorization} header returns
   * {@code 401 authentication_required}.
   *
   * <p>
   * Per §5.7, a valid host JWT is required to revoke an agent; missing credentials must be rejected
   * before any agent lookup occurs.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#57-revoke">§5.7
   *      Revoke</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes –
   *      authentication_required</a>
   */
  @Test
  @Order(18)
  void revokeWithoutAuthReturns401() {
    given()
        .baseUri(issuerUrl())
        .contentType(ContentType.JSON)
        .body("""
            {
              "agent_id": "any_id"
            }
            """)
        .when()
        .post("/agent/revoke")
        .then()
        .statusCode(401)
        .body("error", equalTo("authentication_required"))
        .body("message", notNullValue());
  }

  /**
   * Verifies that {@code POST /agent/revoke} for an unknown {@code agent_id} returns
   * {@code 404 agent_not_found}.
   *
   * <p>
   * Per §5.7, the server must locate the agent under the calling host before processing revocation;
   * a non-existent agent must produce a 404 response.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#57-revoke">§5.7
   *      Revoke</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes – agent_not_found</a>
   */
  @Test
  @Order(19)
  void revokeNonexistentAgentReturns404() {
    String hostJwt = TestJwts.hostJwt(currentHostKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "agent_id": "agt_totally_nonexistent_xyz"
            }
            """)
        .when()
        .post("/agent/revoke")
        .then()
        .statusCode(404)
        .body("error", equalTo("agent_not_found"))
        .body("message", notNullValue());
  }

  /**
   * Verifies that {@code POST /host/revoke} cascades revocation to all agents registered under that
   * host, returning {@code agents_revoked > 0}, and that subsequent introspection of any former
   * agent returns {@code active: false}.
   *
   * <p>
   * Per §5.10 and §8.5 (revocation cascade), revoking a host must atomically transition all
   * subordinate agents to {@code revoked}; subsequent status queries by the revoked host must
   * return {@code 403 host_revoked}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#510-revoke-host">§5.10
   *      Revoke Host</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
   *      Agent States</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes – host_revoked</a>
   */
  @Test
  @Order(20)
  void revokeHostCascadesToAllAgents() {
    OctetKeyPair cascadeHostKey = TestKeys.generateEd25519();
    OctetKeyPair cascadeAgentKey1 = TestKeys.generateEd25519();
    OctetKeyPair cascadeAgentKey2 = TestKeys.generateEd25519();

    String regJwt1 = TestJwts.hostJwtForRegistration(cascadeHostKey, cascadeAgentKey1, issuerUrl());
    preRegisterHost(cascadeHostKey);
    String firstAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt1)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Cascade Agent 1",
              "host_name": "cascade-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Cascade test"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    String regJwt2 = TestJwts.hostJwtForRegistration(cascadeHostKey, cascadeAgentKey2, issuerUrl());
    preRegisterHost(cascadeHostKey);
    String secondAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt2)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Cascade Agent 2",
              "host_name": "cascade-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Cascade test"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    String hostJwt = TestJwts.hostJwt(cascadeHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .when()
        .post("/host/revoke")
        .then()
        .statusCode(200)
        .body("host_id", notNullValue())
        .body("status", equalTo("revoked"))
        .body("agents_revoked", greaterThan(0));

    String firstAgentJwt = TestJwts.agentJwt(cascadeHostKey, cascadeAgentKey1, firstAgentId,
        issuerUrl());
    String secondAgentJwt = TestJwts.agentJwt(cascadeHostKey, cascadeAgentKey2, secondAgentId,
        issuerUrl());

    given()
        .baseUri(issuerUrl())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "token": "%s"
            }
            """, firstAgentJwt))
        .when()
        .post("/agent/introspect")
        .then()
        .statusCode(200)
        .body("active", equalTo(false));

    given()
        .baseUri(issuerUrl())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "token": "%s"
            }
            """, secondAgentJwt))
        .when()
        .post("/agent/introspect")
        .then()
        .statusCode(200)
        .body("active", equalTo(false));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .queryParam("agent_id", firstAgentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(403)
        .body("error", equalTo("host_revoked"))
        .body("message", notNullValue());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .queryParam("agent_id", secondAgentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(403)
        .body("error", equalTo("host_revoked"))
        .body("message", notNullValue());
  }

  /**
   * Verifies that calling {@code POST /host/revoke} on an already-revoked host returns {@code 409}
   * with error {@code already_revoked} or {@code host_revoked}.
   *
   * <p>
   * Per §5.10, host revocation is a terminal operation; a second revocation attempt on the same
   * host must be rejected with a conflict response.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#510-revoke-host">§5.10
   *      Revoke Host</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes – host_revoked /
   *      already_revoked</a>
   */
  @Test
  @Order(22)
  void revokeAlreadyRevokedHostReturns409() {
    OctetKeyPair revokeHostKey = TestKeys.generateEd25519();
    OctetKeyPair revokeAgentKey = TestKeys.generateEd25519();

    String regJwt = TestJwts.hostJwtForRegistration(revokeHostKey, revokeAgentKey, issuerUrl());
    preRegisterHost(revokeHostKey);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Double Revoke Host Agent",
              "host_name": "double-revoke-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Double host revoke test"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200);

    String hostJwt1 = TestJwts.hostJwt(revokeHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt1)
        .contentType(ContentType.JSON)
        .when()
        .post("/host/revoke")
        .then()
        .statusCode(200);

    String hostJwt2 = TestJwts.hostJwt(revokeHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt2)
        .contentType(ContentType.JSON)
        .when()
        .post("/host/revoke")
        .then()
        .statusCode(409)
        .body("error", anyOf(equalTo("already_revoked"), equalTo("host_revoked")));
  }

  // ---------------------------------------------------------------------------
  // Helper: force-expire an agent via the admin API.
  // ---------------------------------------------------------------------------

  private static void forceExpireAgent(String agentId) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body("{}")
        .when()
        .post("/agents/" + agentId + "/expire")
        .then()
        .statusCode(200);
  }

  // ---------------------------------------------------------------------------
  // @Order(30) — existing test kept in place below this block
  // ---------------------------------------------------------------------------

  /**
   * Verifies that {@code GET /agent/status} for a {@code pending} agent returns
   * {@code status: "pending"} and that each capability grant also carries
   * {@code status: "pending"}.
   *
   * <p>
   * Per §5.5, capability grants reflect current server state with per-grant status tracking;
   * pending grants should show minimal data while awaiting approval. Per §2.3, an agent enters
   * {@code pending} when at least one requested capability requires user approval.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#55-status">§5.5
   *      Status</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
   *      Agent States</a>
   */
  @Test
  @Order(30)
  void statusOfPendingAgentShowsPendingState() {
    OctetKeyPair pendingHostKey = TestKeys.generateEd25519();
    OctetKeyPair pendingAgentKey = TestKeys.generateEd25519();
    String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    String capabilityName = "lifecycle_approval_cap_" + suffix;

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Approval required",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "https://resource.example.test/lifecycle",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, capabilityName))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    String regJwt = TestJwts.hostJwtForRegistration(pendingHostKey, pendingAgentKey, issuerUrl());
    preRegisterHost(pendingHostKey);
    String pendingAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Pending Lifecycle Agent",
              "host_name": "pending-lifecycle-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "Pending state lifecycle test"
            }
            """, capabilityName))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("status", equalTo("pending"))
        .extract()
        .path("agent_id");

    String hostJwt = TestJwts.hostJwt(pendingHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .queryParam("agent_id", pendingAgentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(200)
        .body("status", equalTo("pending"))
        .body("agent_capability_grants[0].status", equalTo("pending"));
  }

  // ---------------------------------------------------------------------------
  // @Order(40-43) — expired agent state and reactivation
  // ---------------------------------------------------------------------------

  /**
   * Verifies that {@code GET /agent/status} for a force-expired agent returns {@code 200} with
   * {@code status: "expired"}.
   *
   * <p>
   * Per §2.3, an agent transitions to {@code expired} when the session TTL or max lifetime elapses;
   * the status endpoint must still serve the record and reflect the terminal state accurately.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#55-status">§5.5
   *      Status</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
   *      Agent States</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#24-lifetime-clocks">§2.4
   *      Lifetime Clocks</a>
   */
  @Test
  @Order(40)
  void expiredAgentStatusShowsExpiredState() {
    OctetKeyPair expHostKey = TestKeys.generateEd25519();
    OctetKeyPair expAgentKey = TestKeys.generateEd25519();
    String regJwt = TestJwts.hostJwtForRegistration(expHostKey, expAgentKey, issuerUrl());
    preRegisterHost(expHostKey);

    String expiredAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Expire Status Agent",
              "host_name": "expire-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Expired state test"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    forceExpireAgent(expiredAgentId);

    String hostJwt = TestJwts.hostJwt(expHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .queryParam("agent_id", expiredAgentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(200)
        .body("status", equalTo("expired"));
  }

  /**
   * Verifies that {@code POST /agent/reactivate} on an expired agent succeeds, returning
   * {@code 200} with {@code status: "active"}.
   *
   * <p>
   * Per §5.6 and §2.5, an expired agent may be reactivated as long as its absolute lifetime has not
   * elapsed; the session TTL and max lifetime clocks are reset but the absolute lifetime clock is
   * not.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#56-reactivate">§5.6
   *      Reactivate</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#25-reactivation">§2.5
   *      Reactivation</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#24-lifetime-clocks">§2.4
   *      Lifetime Clocks</a>
   */
  @Test
  @Order(41)
  void reactivateExpiredAgentSucceeds() {
    OctetKeyPair expHostKey = TestKeys.generateEd25519();
    OctetKeyPair expAgentKey = TestKeys.generateEd25519();
    String regJwt = TestJwts.hostJwtForRegistration(expHostKey, expAgentKey, issuerUrl());
    preRegisterHost(expHostKey);

    String expiredAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Reactivate Expired Agent",
              "host_name": "expire-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Reactivation after expiry test"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    forceExpireAgent(expiredAgentId);

    String hostJwt = TestJwts.hostJwt(expHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s"
            }
            """, expiredAgentId))
        .when()
        .post("/agent/reactivate")
        .then()
        .statusCode(200)
        .body("agent_id", equalTo(expiredAgentId))
        .body("status", equalTo("active"))
        .body("activated_at", notNullValue())
        .body("expires_at", notNullValue());
  }

  /**
   * Verifies that an agent successfully reactivated from {@code expired} state can immediately
   * authenticate, returning {@code active: true} on introspection.
   *
   * <p>
   * Per §5.6, a successfully reactivated agent transitions to {@code active} and must be
   * immediately usable for authentication without any additional steps.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#56-reactivate">§5.6
   *      Reactivate</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#25-reactivation">§2.5
   *      Reactivation</a>
   */
  @Test
  @Order(42)
  void reactivatedAgentCanBeIntrospected() {
    OctetKeyPair expHostKey = TestKeys.generateEd25519();
    OctetKeyPair expAgentKey = TestKeys.generateEd25519();
    String regJwt = TestJwts.hostJwtForRegistration(expHostKey, expAgentKey, issuerUrl());

    // Dynamic register populates host.default_capability_grants from the agent's caps; under
    // §2.11 the host comes up `pending`, so the per-grant + agent statuses are pending too.
    // Admin grant-approve flips the host to active, appends the cap to host.default_capabilities,
    // and activates the agent — the post-link state reactivation needs to rebuild grants from.
    String expiredAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Reactivated Introspect Agent",
              "host_name": "expire-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "Reactivate then introspect test"
            }
            """, lifecycleCap))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .post("/agents/" + expiredAgentId + "/capabilities/" + lifecycleCap + "/approve")
        .then()
        .statusCode(200);

    forceExpireAgent(expiredAgentId);

    String hostJwt = TestJwts.hostJwt(expHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s"
            }
            """, expiredAgentId))
        .when()
        .post("/agent/reactivate")
        .then()
        .statusCode(200);

    String agentJwt = TestJwts.agentJwt(expHostKey, expAgentKey, expiredAgentId,
        lifecycleCapLocation());
    given()
        .baseUri(issuerUrl())
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
        .body("active", equalTo(true));
  }

  /**
   * Verifies that an agent JWT presented for an expired agent returns {@code active: false} on
   * introspection before reactivation.
   *
   * <p>
   * Per §2.3 and §2.4, an expired agent may not authenticate; its tokens must be treated as
   * inactive until the agent is successfully reactivated via §5.6.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
   *      Agent States</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#24-lifetime-clocks">§2.4
   *      Lifetime Clocks</a>
   */
  @Test
  @Order(43)
  void expiredAgentJwtIsInactiveOnIntrospect() {
    OctetKeyPair expHostKey = TestKeys.generateEd25519();
    OctetKeyPair expAgentKey = TestKeys.generateEd25519();
    String regJwt = TestJwts.hostJwtForRegistration(expHostKey, expAgentKey, issuerUrl());
    preRegisterHost(expHostKey);

    String expiredAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Expired Introspect Agent",
              "host_name": "expire-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Expired agent introspect test"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    forceExpireAgent(expiredAgentId);

    String agentJwt = TestJwts.agentJwt(expHostKey, expAgentKey, expiredAgentId, issuerUrl());
    given()
        .baseUri(issuerUrl())
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
        .body("active", equalTo(false));
  }

  // ---------------------------------------------------------------------------
  // @Order(50-51) — revoke error cases
  // ---------------------------------------------------------------------------

  /**
   * Verifies that a host cannot revoke an agent belonging to a different host, receiving
   * {@code 403 unauthorized}.
   *
   * <p>
   * Per §5.7, the server must verify the agent is registered under the requesting host before
   * processing the revocation; cross-host revocation must be denied.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#57-revoke">§5.7
   *      Revoke</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes – unauthorized</a>
   */
  @Test
  @Order(50)
  void revokeAgentFromDifferentHostReturns403() {
    OctetKeyPair hostKeyA = TestKeys.generateEd25519();
    OctetKeyPair hostKeyB = TestKeys.generateEd25519();
    OctetKeyPair agentKeyA = TestKeys.generateEd25519();

    String regJwt = TestJwts.hostJwtForRegistration(hostKeyA, agentKeyA, issuerUrl());
    preRegisterHost(hostKeyA);
    String targetAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Cross-Host Revoke Agent",
              "host_name": "host-a",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Cross-host revoke test"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    String hostBJwt = TestJwts.hostJwt(hostKeyB, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostBJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s"
            }
            """, targetAgentId))
        .when()
        .post("/agent/revoke")
        .then()
        .statusCode(403)
        .body("error", equalTo("unauthorized"));
  }

  /**
   * Verifies that revoking an already-revoked agent is idempotent, returning {@code 200} with
   * {@code status: "revoked"} on the second call.
   *
   * <p>
   * Per §5.7, the spec indicates that attempting to revoke an already-revoked agent should be
   * handled gracefully; the server must not produce an error for this idempotent operation.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#57-revoke">§5.7
   *      Revoke</a>
   */
  @Test
  @Order(51)
  void revokeAlreadyRevokedAgentReturns200() {
    OctetKeyPair revokeHostKey = TestKeys.generateEd25519();
    OctetKeyPair revokeAgentKey = TestKeys.generateEd25519();
    String regJwt = TestJwts.hostJwtForRegistration(revokeHostKey, revokeAgentKey, issuerUrl());
    preRegisterHost(revokeHostKey);

    String doubleRevokeAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Double Revoke Agent",
              "host_name": "revoke-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Double revoke test"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    String hostJwt1 = TestJwts.hostJwt(revokeHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt1)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s"
            }
            """, doubleRevokeAgentId))
        .when()
        .post("/agent/revoke")
        .then()
        .statusCode(200);

    String hostJwt2 = TestJwts.hostJwt(revokeHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt2)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s"
            }
            """, doubleRevokeAgentId))
        .when()
        .post("/agent/revoke")
        .then()
        .statusCode(200)
        .body("status", equalTo("revoked"));
  }

  /**
   * Verifies that {@code POST /agent/revoke} with a body missing the required {@code agent_id}
   * field returns {@code 400 invalid_request}.
   *
   * <p>
   * Per §5.7 and the common error codes, missing required fields in the request body must produce
   * an {@code invalid_request} error.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#57-revoke">§5.7
   *      Revoke</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes – invalid_request</a>
   */
  @Test
  @Order(52)
  void revokeWithMissingAgentIdReturns400() {
    OctetKeyPair freshHostKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwt(freshHostKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("{}")
        .when()
        .post("/agent/revoke")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  // ---------------------------------------------------------------------------
  // @Order(60-63) — rotate-key error cases
  // ---------------------------------------------------------------------------

  /**
   * Verifies that {@code POST /agent/rotate-key} without an {@code Authorization} header returns
   * {@code 401 authentication_required}.
   *
   * <p>
   * Per §5.8, a valid host JWT is required to rotate an agent key; missing credentials must be
   * rejected before any agent lookup occurs.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#58-key-rotation">§5.8
   *      Key Rotation</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes –
   *      authentication_required</a>
   */
  @Test
  @Order(60)
  void rotateAgentKeyWithoutAuthReturns401() {
    OctetKeyPair newKey = TestKeys.generateEd25519();

    given()
        .baseUri(issuerUrl())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "anything",
              "public_key": %s
            }
            """, newKey.toPublicJWK().toJSONString()))
        .when()
        .post("/agent/rotate-key")
        .then()
        .statusCode(401)
        .body("error", equalTo("authentication_required"));
  }

  /**
   * Verifies that {@code POST /agent/rotate-key} for an unknown {@code agent_id} returns
   * {@code 404 agent_not_found}.
   *
   * <p>
   * Per §5.8, the server must locate the agent under the calling host before applying the key
   * rotation; a non-existent agent must produce a 404 response.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#58-key-rotation">§5.8
   *      Key Rotation</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes – agent_not_found</a>
   */
  @Test
  @Order(61)
  void rotateAgentKeyForNonexistentAgentReturns404() {
    OctetKeyPair rotateHostKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwt(rotateHostKey, issuerUrl());
    OctetKeyPair newKey = TestKeys.generateEd25519();

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "agt_nonexistent_rotate_xyz",
              "public_key": %s
            }
            """, newKey.toPublicJWK().toJSONString()))
        .when()
        .post("/agent/rotate-key")
        .then()
        .statusCode(404)
        .body("error", equalTo("agent_not_found"));
  }

  /**
   * Verifies that a host cannot rotate the key for an agent belonging to a different host,
   * receiving {@code 403 unauthorized}.
   *
   * <p>
   * Per §5.8, the server must verify the agent is registered under the requesting host before
   * accepting the key rotation; cross-host rotation must be denied.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#58-key-rotation">§5.8
   *      Key Rotation</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes – unauthorized</a>
   */
  @Test
  @Order(62)
  void rotateAgentKeyFromDifferentHostReturns403() {
    OctetKeyPair hostKeyA = TestKeys.generateEd25519();
    OctetKeyPair hostKeyB = TestKeys.generateEd25519();
    OctetKeyPair agentKeyA = TestKeys.generateEd25519();

    String regJwt = TestJwts.hostJwtForRegistration(hostKeyA, agentKeyA, issuerUrl());
    preRegisterHost(hostKeyA);
    String rotateTargetAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Cross-Host Rotate Agent",
              "host_name": "host-a",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Cross-host rotate-key test"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    OctetKeyPair newKey = TestKeys.generateEd25519();
    String hostBJwt = TestJwts.hostJwt(hostKeyB, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostBJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s",
              "public_key": %s
            }
            """, rotateTargetAgentId, newKey.toPublicJWK().toJSONString()))
        .when()
        .post("/agent/rotate-key")
        .then()
        .statusCode(403)
        .body("error", equalTo("unauthorized"));
  }

  /**
   * Verifies that {@code POST /agent/rotate-key} with a malformed (non-JWK) {@code public_key}
   * value returns {@code 400 invalid_request}.
   *
   * <p>
   * Per §5.8, the new public key must be a valid Ed25519 JWK; the server must reject malformed key
   * material with an {@code invalid_request} error.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#58-key-rotation">§5.8
   *      Key Rotation</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes – invalid_request</a>
   */
  @Test
  @Order(63)
  void rotateAgentKeyWithMalformedPublicKeyReturns400() {
    OctetKeyPair rotateHostKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwt(rotateHostKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "agent_id": "agt_any",
              "public_key": "not-a-jwk"
            }
            """)
        .when()
        .post("/agent/rotate-key")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  /**
   * Verifies that {@code POST /agent/rotate-key} on a revoked agent returns
   * {@code 403 agent_revoked}, because key rotation is not permitted on terminal-state agents.
   *
   * <p>
   * Per §5.8, key rotation is intended for active agents; the endpoint must enforce state
   * constraints and reject requests for revoked agents.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#58-key-rotation">§5.8
   *      Key Rotation</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
   *      Agent States</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes – agent_revoked</a>
   */
  @Test
  @Order(64)
  void rotateAgentKeyForRevokedAgentReturns403() {
    OctetKeyPair revokedHostKey = TestKeys.generateEd25519();
    OctetKeyPair revokedAgentKey = TestKeys.generateEd25519();

    String regJwt = TestJwts.hostJwtForRegistration(revokedHostKey, revokedAgentKey, issuerUrl());
    preRegisterHost(revokedHostKey);
    String revokedAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Revoked Rotate Agent",
              "host_name": "revoked-rotate-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Rotate key on revoked agent test"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    String hostJwt = TestJwts.hostJwt(revokedHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s"
            }
            """, revokedAgentId))
        .when()
        .post("/agent/revoke")
        .then()
        .statusCode(200);

    OctetKeyPair newKey = TestKeys.generateEd25519();
    String hostJwt2 = TestJwts.hostJwt(revokedHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt2)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s",
              "public_key": %s
            }
            """, revokedAgentId, newKey.toPublicJWK().toJSONString()))
        .when()
        .post("/agent/rotate-key")
        .then()
        .statusCode(403)
        .body("error", equalTo("agent_revoked"));
  }

  /**
   * Verifies that {@code POST /agent/rotate-key} on an expired agent returns either {@code 400} or
   * {@code 403}, since key rotation is not permitted on agents that are not in an active state.
   *
   * <p>
   * Per §5.8, key rotation is intended for active agents; the endpoint should enforce state
   * constraints. The spec does not mandate a specific error code for expired agents, so either
   * {@code 400} (invalid state for operation) or {@code 403} (agent_expired) is acceptable.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#58-key-rotation">§5.8
   *      Key Rotation</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
   *      Agent States</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes – agent_expired</a>
   */
  @Test
  @Order(65)
  void rotateAgentKeyForExpiredAgentReturns400Or403() {
    OctetKeyPair expiredHostKey = TestKeys.generateEd25519();
    OctetKeyPair expiredAgentKey = TestKeys.generateEd25519();

    String regJwt = TestJwts.hostJwtForRegistration(expiredHostKey, expiredAgentKey, issuerUrl());
    preRegisterHost(expiredHostKey);
    String expiredAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Expired Rotate Agent",
              "host_name": "expired-rotate-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Rotate key on expired agent test"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    forceExpireAgent(expiredAgentId);

    OctetKeyPair newKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwt(expiredHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s",
              "public_key": %s
            }
            """, expiredAgentId, newKey.toPublicJWK().toJSONString()))
        .when()
        .post("/agent/rotate-key")
        .then()
        .statusCode(anyOf(equalTo(400), equalTo(403)));
  }

  // ---------------------------------------------------------------------------
  // @Order(70-71) — rotate-host-key error cases
  // ---------------------------------------------------------------------------

  /**
   * Verifies that {@code POST /host/rotate-key} without an {@code Authorization} header returns
   * {@code 401 authentication_required}.
   *
   * <p>
   * Per §5.9, a valid host JWT signed with the current key is required; missing credentials must be
   * rejected before any key rotation is attempted.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#59-rotate-host-key">§5.9
   *      Rotate Host Key</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes –
   *      authentication_required</a>
   */
  @Test
  @Order(70)
  void rotateHostKeyWithoutAuthReturns401() {
    given()
        .baseUri(issuerUrl())
        .contentType(ContentType.JSON)
        .body("""
            {
              "public_key": "not-a-jwk"
            }
            """)
        .when()
        .post("/host/rotate-key")
        .then()
        .statusCode(401)
        .body("error", equalTo("authentication_required"));
  }

  /**
   * Verifies that {@code POST /host/rotate-key} with a malformed (non-JWK) {@code public_key} value
   * returns {@code 400 invalid_request}.
   *
   * <p>
   * Per §5.9, the new public key must be a valid Ed25519 JWK; the server must reject malformed key
   * material with an {@code invalid_request} error.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#59-rotate-host-key">§5.9
   *      Rotate Host Key</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes – invalid_request</a>
   */
  @Test
  @Order(71)
  void rotateHostKeyWithMalformedPublicKeyReturns400() {
    OctetKeyPair rotateHostKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwt(rotateHostKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "public_key": "not-a-jwk"
            }
            """)
        .when()
        .post("/host/rotate-key")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  /**
   * Verifies that {@code POST /host/rotate-key} for a revoked host returns
   * {@code 403 host_revoked}, because host key rotation is not permitted after the host has been
   * permanently revoked.
   *
   * <p>
   * Per §5.9, key rotation preserves the host in {@code active} state; a revoked host is in a
   * terminal state and must not be allowed to rotate its key.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#59-rotate-host-key">§5.9
   *      Rotate Host Key</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#510-revoke-host">§5.10
   *      Revoke Host</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes – host_revoked</a>
   */
  @Test
  @Order(72)
  void rotateHostKeyForRevokedHostReturns403() {
    OctetKeyPair revokedHostKey = TestKeys.generateEd25519();
    OctetKeyPair revokedAgentKey = TestKeys.generateEd25519();

    String regJwt = TestJwts.hostJwtForRegistration(revokedHostKey, revokedAgentKey, issuerUrl());
    preRegisterHost(revokedHostKey);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Revoked Host Rotate Agent",
              "host_name": "revoked-host-rotate",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Rotate host key after revocation test"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200);

    String hostJwt = TestJwts.hostJwt(revokedHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .when()
        .post("/host/revoke")
        .then()
        .statusCode(200);

    OctetKeyPair newHostKey = TestKeys.generateEd25519();
    String hostJwt2 = TestJwts.hostJwt(revokedHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt2)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "public_key": %s
            }
            """, newHostKey.toPublicJWK().toJSONString()))
        .when()
        .post("/host/rotate-key")
        .then()
        .statusCode(403)
        .body("error", equalTo("host_revoked"));
  }

  // ---------------------------------------------------------------------------
  // @Order(80) — host revoke error cases
  // ---------------------------------------------------------------------------

  /**
   * Verifies that {@code POST /host/revoke} without an {@code Authorization} header returns
   * {@code 401 authentication_required}.
   *
   * <p>
   * Per §5.10, a valid host JWT is required to revoke the calling host; missing credentials must be
   * rejected without any state changes.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#510-revoke-host">§5.10
   *      Revoke Host</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes –
   *      authentication_required</a>
   */
  @Test
  @Order(80)
  void revokeHostWithoutAuthReturns401() {
    given()
        .baseUri(issuerUrl())
        .contentType(ContentType.JSON)
        .when()
        .post("/host/revoke")
        .then()
        .statusCode(401)
        .body("error", equalTo("authentication_required"));
  }

  // ---------------------------------------------------------------------------
  // @Order(90) — reactivate input validation
  // ---------------------------------------------------------------------------

  /**
   * Verifies that {@code POST /agent/reactivate} with a body missing the required {@code agent_id}
   * field returns {@code 400 invalid_request}.
   *
   * <p>
   * Per §5.6, {@code agent_id} is a required request field; missing it must produce an
   * {@code invalid_request} error before any state lookup occurs.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#56-reactivate">§5.6
   *      Reactivate</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes – invalid_request</a>
   */
  @Test
  @Order(90)
  void reactivateWithMissingAgentIdReturns400() {
    OctetKeyPair reactivateHostKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwt(reactivateHostKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("{}")
        .when()
        .post("/agent/reactivate")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  /**
   * Verifies that attempting to reactivate a pending agent returns {@code 403 agent_pending}.
   *
   * <p>
   * Per §5.6 step 1, if the agent is in {@code pending} state the server must reject the
   * reactivation request with {@code 403 agent_pending}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#56-reactivate">§5.6
   *      Reactivate</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
   *      Agent States</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes – agent_pending</a>
   */
  @Test
  @Order(91)
  void reactivatePendingAgentReturnsError() {
    OctetKeyPair pendingHostKey = TestKeys.generateEd25519();
    OctetKeyPair pendingAgentKey = TestKeys.generateEd25519();
    String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    String capabilityName = "lifecycle_reactivate_pending_cap_" + suffix;

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Approval required for pending reactivate test",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "https://resource.example.test/pending-reactivate",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, capabilityName))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    String regJwt = TestJwts.hostJwtForRegistration(pendingHostKey, pendingAgentKey, issuerUrl());
    preRegisterHost(pendingHostKey);
    String pendingAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Pending Reactivate Agent",
              "host_name": "pending-reactivate-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "Reactivate pending agent test"
            }
            """, capabilityName))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("status", equalTo("pending"))
        .extract()
        .path("agent_id");

    String hostJwt = TestJwts.hostJwt(pendingHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s"
            }
            """, pendingAgentId))
        .when()
        .post("/agent/reactivate")
        .then()
        .statusCode(403)
        .body("error", equalTo("agent_pending"))
        .body("message", notNullValue());
  }

  // ---------------------------------------------------------------------------
  // @Order(101) — status input validation
  // ---------------------------------------------------------------------------

  /**
   * Verifies that {@code GET /agent/status} without the required {@code agent_id} query parameter
   * returns {@code 400 invalid_request}.
   *
   * <p>
   * Per §5.5, {@code agent_id} is a required query parameter; omitting it must produce an
   * {@code invalid_request} error before any database lookup occurs.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#55-status">§5.5
   *      Status</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes – invalid_request</a>
   */
  @Test
  @Order(101)
  void getAgentStatusWithMissingAgentIdReturns400() {
    OctetKeyPair freshHostKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwt(freshHostKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  // ---------------------------------------------------------------------------
  // TODO stubs — spec requirements not yet covered
  // ---------------------------------------------------------------------------

  /**
   * TODO: Verifies that reactivating an agent whose absolute lifetime has elapsed transitions the
   * agent to {@code revoked} and returns {@code 403 absolute_lifetime_exceeded}.
   *
   * <p>
   * Per §5.6 step 2, if the absolute lifetime has elapsed since the agent was created the server
   * must transition the agent to {@code revoked} and MUST NOT allow reactivation. Per §2.4, the
   * absolute lifetime clock cannot be reset.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#56-reactivate">§5.6
   *      Reactivate</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#24-lifetime-clocks">§2.4
   *      Lifetime Clocks</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes –
   *      absolute_lifetime_exceeded</a>
   */
  @Test
  void todoReactivateWhenAbsoluteLifetimeExceededReturns403() {
    OctetKeyPair absHostKey = TestKeys.generateEd25519();
    OctetKeyPair absAgentKey = TestKeys.generateEd25519();
    String regJwt = TestJwts.hostJwtForRegistration(absHostKey, absAgentKey, issuerUrl());
    preRegisterHost(absHostKey);

    String absAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Absolute Lifetime Agent",
              "host_name": "abs-lifetime-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Absolute lifetime exceeded test"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    // Force the agent to exceed its absolute lifetime via the admin API
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body("{\"exceed_absolute_lifetime\": true}")
        .when()
        .post("/agents/" + absAgentId + "/expire")
        .then()
        .statusCode(200);

    String hostJwt = TestJwts.hostJwt(absHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s"
            }
            """, absAgentId))
        .when()
        .post("/agent/reactivate")
        .then()
        .statusCode(403)
        .body("error", equalTo("absolute_lifetime_exceeded"))
        .body("message", notNullValue());
  }

  /**
   * TODO: Verifies that after reactivation the agent's capability grants are reset to the host's
   * current default capability set (capability decay).
   *
   * <p>
   * Per §5.6 steps 3–4 and §2.5, reactivation revokes all existing capability grants and re-grants
   * only the host's current defaults; any previously escalated capabilities must not be carried
   * forward.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#56-reactivate">§5.6
   *      Reactivate</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#25-reactivation">§2.5
   *      Reactivation</a>
   */
  @Test
  void todoReactivationResetsCapabilitiesToHostDefaults() {
    // Register a capability to request during registration
    String decayCap = "decay_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Capability for decay test",
              "visibility": "authenticated",
              "requires_approval": false,
              "location": "https://resource.example.test/capabilities/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, decayCap, decayCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    OctetKeyPair decayHostKey = TestKeys.generateEd25519();
    OctetKeyPair decayAgentKey = TestKeys.generateEd25519();
    String regJwt = TestJwts.hostJwtForRegistration(decayHostKey, decayAgentKey, issuerUrl());

    // Dynamic register populates host.default_capability_grants from the agent's caps; under
    // §2.11 the host comes up `pending`. Admin grant-approve flips the host to active and
    // appends decayCap to host.default_capabilities, the post-link state reactivation rebuilds
    // grants from.
    String decayAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Capability Decay Agent",
              "host_name": "decay-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "Capability decay reactivation test"
            }
            """, decayCap))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .post("/agents/" + decayAgentId + "/capabilities/" + decayCap + "/approve")
        .then()
        .statusCode(200);

    // Record the initial set of granted capability names
    String hostJwt0 = TestJwts.hostJwt(decayHostKey, issuerUrl());
    io.restassured.response.Response initialStatus = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt0)
        .queryParam("agent_id", decayAgentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(200)
        .extract()
        .response();
    java.util.List<String> initialCapabilities = initialStatus.jsonPath()
        .getList("agent_capability_grants.capability");

    // Expire the agent
    forceExpireAgent(decayAgentId);

    // Reactivate
    String hostJwt = TestJwts.hostJwt(decayHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s"
            }
            """, decayAgentId))
        .when()
        .post("/agent/reactivate")
        .then()
        .statusCode(200)
        .body("status", equalTo("active"));

    // After reactivation, grants must match exactly the host defaults (no more, no less)
    String hostJwt2 = TestJwts.hostJwt(decayHostKey, issuerUrl());
    io.restassured.response.Response postStatus = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt2)
        .queryParam("agent_id", decayAgentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(200)
        .extract()
        .response();
    java.util.List<String> postCapabilities = postStatus.jsonPath()
        .getList("agent_capability_grants.capability");

    // The post-reactivation capability set must equal the initial registered set (host defaults)
    org.junit.jupiter.api.Assertions.assertEquals(
        initialCapabilities == null ? java.util.Collections.emptyList() : initialCapabilities,
        postCapabilities == null ? java.util.Collections.emptyList() : postCapabilities,
        "Post-reactivation grants must reset to host defaults — no additional grants carried over");
  }

  /**
   * TODO: Verifies that reactivation resets {@code expires_at} (session TTL) and does not reset the
   * absolute lifetime.
   *
   * <p>
   * Per §5.6 step 5 and §2.4, the session TTL and max lifetime clocks are reset on reactivation,
   * but the absolute lifetime clock (measured from creation) is never reset.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#56-reactivate">§5.6
   *      Reactivate</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#24-lifetime-clocks">§2.4
   *      Lifetime Clocks</a>
   */
  @Test
  void todoReactivationResetsSessionTtlButNotAbsoluteLifetime() {
    OctetKeyPair ttlHostKey = TestKeys.generateEd25519();
    OctetKeyPair ttlAgentKey = TestKeys.generateEd25519();
    String regJwt = TestJwts.hostJwtForRegistration(ttlHostKey, ttlAgentKey, issuerUrl());
    preRegisterHost(ttlHostKey);

    String ttlAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "TTL Reset Agent",
              "host_name": "ttl-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "TTL reset reactivation test"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    // Record initial expires_at
    String hostJwt0 = TestJwts.hostJwt(ttlHostKey, issuerUrl());
    String initialExpiresAt = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt0)
        .queryParam("agent_id", ttlAgentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(200)
        .extract()
        .path("expires_at");

    // Force expire the agent
    forceExpireAgent(ttlAgentId);

    // Brief pause so wall-clock advances
    try {
      Thread.sleep(1100);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }

    // Reactivate
    String hostJwt = TestJwts.hostJwt(ttlHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s"
            }
            """, ttlAgentId))
        .when()
        .post("/agent/reactivate")
        .then()
        .statusCode(200)
        .body("status", equalTo("active"));

    // expires_at after reactivation must be later than the pre-expiry expires_at
    String hostJwt2 = TestJwts.hostJwt(ttlHostKey, issuerUrl());
    String newExpiresAt = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt2)
        .queryParam("agent_id", ttlAgentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(200)
        .body("expires_at", notNullValue())
        .extract()
        .path("expires_at");

    org.junit.jupiter.api.Assertions.assertNotNull(newExpiresAt,
        "expires_at must be present after reactivation");
    if (initialExpiresAt != null) {
      java.time.Instant before = java.time.Instant.parse(initialExpiresAt);
      java.time.Instant after = java.time.Instant.parse(newExpiresAt);
      org.junit.jupiter.api.Assertions.assertTrue(after.isAfter(before),
          "expires_at must advance after reactivation — session TTL must be reset");
    }
  }

  /**
   * TODO: Verifies that attempting to reactivate a {@code rejected} agent returns
   * {@code 403 agent_rejected}.
   *
   * <p>
   * Per §5.6 step 1, if the agent is in the terminal {@code rejected} state the server must return
   * {@code 403 agent_rejected}; the {@code rejected} state is not recoverable via reactivation.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#56-reactivate">§5.6
   *      Reactivate</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
   *      Agent States</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes – agent_rejected
   *      (agent_revoked family)</a>
   */
  @Test
  void todoReactivateRejectedAgentReturns403() {
    String rejectedCap = "rejected_reactivate_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Requires approval before rejection",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "https://resource.example.test/capabilities/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, rejectedCap, rejectedCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    OctetKeyPair rejectedHostKey = TestKeys.generateEd25519();
    OctetKeyPair rejectedAgentKey = TestKeys.generateEd25519();
    String regJwt = TestJwts.hostJwtForRegistration(rejectedHostKey, rejectedAgentKey,
        issuerUrl());
    preRegisterHost(rejectedHostKey);

    String rejectedAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Rejected Agent",
              "host_name": "rejected-host",
              "capabilities": ["%s"],
              "mode": "delegated"
            }
            """, rejectedCap))
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
        .body("{\"reason\":\"User denied approval\"}")
        .when()
        .post("/agents/" + rejectedAgentId + "/reject")
        .then()
        .statusCode(200)
        .body("status", equalTo("rejected"));

    String hostJwt = TestJwts.hostJwt(rejectedHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s"
            }
            """, rejectedAgentId))
        .when()
        .post("/agent/reactivate")
        .then()
        .statusCode(403)
        .body("error", equalTo("agent_rejected"));
  }

  /**
   * TODO: Verifies that the status response includes {@code activated_at} and {@code expires_at}
   * timestamps for an active agent.
   *
   * <p>
   * Per §5.5, the response must include conditional fields {@code activated_at} and
   * {@code expires_at} when the agent is active, in ISO 8601 format.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#55-status">§5.5
   *      Status</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#24-lifetime-clocks">§2.4
   *      Lifetime Clocks</a>
   */
  @Test
  void todoStatusResponseIncludesLifetimeTimestamps() {
    OctetKeyPair tsHostKey = TestKeys.generateEd25519();
    OctetKeyPair tsAgentKey = TestKeys.generateEd25519();
    String regJwt = TestJwts.hostJwtForRegistration(tsHostKey, tsAgentKey, issuerUrl());
    preRegisterHost(tsHostKey);

    String tsAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Timestamp Agent",
              "host_name": "ts-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "Lifetime timestamp test"
            }
            """, lifecycleCap))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    // Perform an introspect call so the server records a last_used_at timestamp
    String agentJwt = TestJwts.agentJwt(tsHostKey, tsAgentKey, tsAgentId, lifecycleCapLocation());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(tsHostKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "token": "%s"
            }
            """, agentJwt))
        .when()
        .post("/agent/introspect")
        .then()
        .statusCode(200);

    String hostJwt = TestJwts.hostJwt(tsHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .queryParam("agent_id", tsAgentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(200)
        .body("created_at", notNullValue())
        .body("activated_at", notNullValue())
        .body("expires_at", notNullValue())
        .body("last_used_at", notNullValue());
  }

  /**
   * TODO: Verifies that active capability grants in the status response include the full capability
   * schema (input/output) while denied grants include only the capability name, status, and
   * human-readable reason.
   *
   * <p>
   * Per §5.5, active grants include complete capability schemas; denied grants include only
   * capability name, status, and reason.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#55-status">§5.5
   *      Status</a>
   */
  @Test
  void todoStatusResponseGrantsIncludeFullSchemaForActiveAndReasonForDenied() {
    String approvedCap = "status_schema_approved_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    String deniedCap = "status_schema_denied_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    // Register an auto-approved capability with full input/output schemas
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Approved capability with schema",
              "visibility": "authenticated",
              "requires_approval": false,
              "location": "https://resource.example.test/capabilities/%s",
              "input": {"type": "object", "properties": {"amount": {"type": "number"}}},
              "output": {"type": "object"}
            }
            """, approvedCap, approvedCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    // Register an auto-denied capability
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Auto-denied capability",
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

    OctetKeyPair schemaHostKey = TestKeys.generateEd25519();
    OctetKeyPair schemaAgentKey = TestKeys.generateEd25519();
    String regJwt = TestJwts.hostJwtForRegistration(schemaHostKey, schemaAgentKey, issuerUrl());
    preRegisterHost(schemaHostKey);

    String schemaAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Schema Status Agent",
              "host_name": "schema-host",
              "capabilities": ["%s", "%s"],
              "mode": "delegated",
              "reason": "Status schema test"
            }
            """, approvedCap, deniedCap))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    String hostJwt = TestJwts.hostJwt(schemaHostKey, issuerUrl());
    io.restassured.response.Response resp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .queryParam("agent_id", schemaAgentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(200)
        .extract()
        .response();

    // Active grant must carry description, input, output, and granted_by
    java.util.List<java.util.Map<String, Object>> grants = resp.jsonPath()
        .getList("agent_capability_grants");
    java.util.Map<String, Object> activeGrant = grants.stream()
        .filter(g -> approvedCap.equals(g.get("capability")))
        .findFirst()
        .orElseThrow(() -> new AssertionError("Active grant not found"));
    org.junit.jupiter.api.Assertions.assertEquals("active", activeGrant.get("status"),
        "Expected active grant status");
    org.junit.jupiter.api.Assertions.assertNotNull(activeGrant.get("description"),
        "Active grant must include description");
    org.junit.jupiter.api.Assertions.assertNotNull(activeGrant.get("input"),
        "Active grant must include input schema");
    org.junit.jupiter.api.Assertions.assertNotNull(activeGrant.get("output"),
        "Active grant must include output schema");
    org.junit.jupiter.api.Assertions.assertNotNull(activeGrant.get("granted_by"),
        "Active grant must include granted_by");

    // Denied grant must carry only capability, status, and reason
    java.util.Map<String, Object> deniedGrant = grants.stream()
        .filter(g -> deniedCap.equals(g.get("capability")))
        .findFirst()
        .orElseThrow(() -> new AssertionError("Denied grant not found"));
    org.junit.jupiter.api.Assertions.assertEquals("denied", deniedGrant.get("status"),
        "Expected denied grant status");
    org.junit.jupiter.api.Assertions.assertNotNull(deniedGrant.get("reason"),
        "Denied grant must include reason");
    org.junit.jupiter.api.Assertions.assertNull(deniedGrant.get("input"),
        "Denied grant must NOT include input schema");
    org.junit.jupiter.api.Assertions.assertNull(deniedGrant.get("output"),
        "Denied grant must NOT include output schema");
  }

  /**
   * Verifies that {@code POST /agent/rotate-key} rejects an unsupported algorithm (non-Ed25519)
   * with {@code 400 unsupported_algorithm}.
   *
   * <p>
   * Per §5.8 and the error code catalogue, if the supplied JWK uses an algorithm other than Ed25519
   * the server must return {@code 400 unsupported_algorithm}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#58-key-rotation">§5.8
   *      Key Rotation</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes –
   *      unsupported_algorithm</a>
   */
  @Test
  @Order(66)
  void todoRotateAgentKeyWithUnsupportedAlgorithmReturns400() {
    OctetKeyPair uaHostKey = TestKeys.generateEd25519();
    OctetKeyPair uaAgentKey = TestKeys.generateEd25519();
    String regJwt = TestJwts.hostJwtForRegistration(uaHostKey, uaAgentKey, issuerUrl());
    preRegisterHost(uaHostKey);

    String uaAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Unsupported Algo Agent",
              "host_name": "ua-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Unsupported algorithm rotate-key test"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    // X25519 OKP key — valid OctetKeyPair but not Ed25519
    String x25519Jwk = "{\"kty\":\"OKP\",\"crv\":\"X25519\","
        + "\"x\":\"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo\"}";

    String hostJwt = TestJwts.hostJwt(uaHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s",
              "public_key": %s
            }
            """, uaAgentId, x25519Jwk))
        .when()
        .post("/agent/rotate-key")
        .then()
        .statusCode(400)
        .body("error", equalTo("unsupported_algorithm"));
  }

  /**
   * Verifies that {@code POST /host/rotate-key} rejects an unsupported algorithm (non-Ed25519) with
   * {@code 400 unsupported_algorithm}.
   *
   * <p>
   * Per §5.9 and the error code catalogue, if the supplied JWK uses an algorithm other than Ed25519
   * the server must return {@code 400 unsupported_algorithm}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#59-rotate-host-key">§5.9
   *      Rotate Host Key</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Codes –
   *      unsupported_algorithm</a>
   */
  @Test
  @Order(73)
  void todoRotateHostKeyWithUnsupportedAlgorithmReturns400() {
    OctetKeyPair uaHostKey = TestKeys.generateEd25519();
    OctetKeyPair uaAgentKey = TestKeys.generateEd25519();
    String regJwt = TestJwts.hostJwtForRegistration(uaHostKey, uaAgentKey, issuerUrl());
    preRegisterHost(uaHostKey);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Unsupported Algo Host Agent",
              "host_name": "ua-host-rotate",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Unsupported algorithm rotate-host-key test"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200);

    // X25519 OKP key — valid OctetKeyPair but not Ed25519
    String x25519Jwk = "{\"kty\":\"OKP\",\"crv\":\"X25519\","
        + "\"x\":\"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo\"}";

    String hostJwt = TestJwts.hostJwt(uaHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "public_key": %s
            }
            """, x25519Jwk))
        .when()
        .post("/host/rotate-key")
        .then()
        .statusCode(400)
        .body("error", equalTo("unsupported_algorithm"));
  }

  /**
   * TODO: Verifies that when a reactivated agent transitions to {@code pending} (because a default
   * capability requires approval), the response includes the {@code approval} object and clients
   * must poll {@code GET /agent/status}.
   *
   * <p>
   * Per §5.6 step 6, if default capability grants require approval the agent returns to
   * {@code pending} and the response must include the {@code approval} polling object as defined in
   * §7.5.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#56-reactivate">§5.6
   *      Reactivate</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
   *      Agent States</a>
   */
  @Test
  void todoReactivationResultingInPendingIncludesApprovalObject() {
    // Register a capability that requires approval (host default)
    String approvalCap = "reactivate_approval_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Requires approval for reactivation pending test",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "https://resource.example.test/capabilities/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, approvalCap, approvalCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    OctetKeyPair pendingReactHostKey = TestKeys.generateEd25519();
    OctetKeyPair pendingReactAgentKey = TestKeys.generateEd25519();
    String regJwt = TestJwts.hostJwtForRegistration(pendingReactHostKey, pendingReactAgentKey,
        issuerUrl());

    // Dynamic-register the agent against a fresh (unknown) host so the host is created with
    // host.default_capability_grants populated from the request — that's the rich list
    // buildReactivationGrants iterates on §5.6. We pair the approval-required cap with the
    // auto-grant lifecycleCap so admin grant-approve on lifecycleCap activates the host
    // (§2.11) and links it without sweeping approvalCap into host.default_capabilities. On
    // reactivate, approvalCap stays !inHostDefaults → pending, exercising the path under test.
    String pendingReactAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Reactivate Pending Agent",
              "host_name": "reactivate-pending-host",
              "capabilities": ["%s", "%s"],
              "mode": "delegated",
              "reason": "Reactivation pending approval test"
            }
            """, lifecycleCap, approvalCap))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .post("/agents/" + pendingReactAgentId + "/capabilities/" + lifecycleCap + "/approve")
        .then()
        .statusCode(200);

    // Expire the agent
    forceExpireAgent(pendingReactAgentId);

    // Reactivate — since the capability requires approval, the agent must return to pending
    // and the response must include a non-null approval object
    String hostJwt = TestJwts.hostJwt(pendingReactHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s"
            }
            """, pendingReactAgentId))
        .when()
        .post("/agent/reactivate")
        .then()
        .statusCode(200)
        .body("status", equalTo("pending"))
        .body("approval", notNullValue());
  }
}
