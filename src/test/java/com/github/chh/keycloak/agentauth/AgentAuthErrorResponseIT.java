package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.notNullValue;

import com.github.chh.keycloak.agentauth.support.BaseKeycloakIT;
import com.github.chh.keycloak.agentauth.support.TestJwts;
import com.github.chh.keycloak.agentauth.support.TestKeys;
import com.nimbusds.jose.jwk.OctetKeyPair;
import io.restassured.http.ContentType;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Integration tests that validate every error response produced by the Agent Auth Protocol
 * extension conforms to the spec error catalogue shape.
 *
 * <p>
 * Per the Agent Auth Protocol spec, ALL error responses must:
 * <ul>
 * <li>Return {@code Content-Type: application/json}</li>
 * <li>Carry a machine-readable {@code error} field (string)</li>
 * <li>Carry a human-readable {@code message} field (string)</li>
 * <li>Use an appropriate HTTP status code (400, 401, 404, 409, …)</li>
 * </ul>
 *
 * <p>
 * Spec sections covered:
 * <ul>
 * <li>§6 Error Catalogue — unified error shape:
 * <a href="https://agent-auth-protocol.com/docs/errors">Error Catalogue</a></li>
 * <li>§5.1 Register Agent — {@code authentication_required} on missing auth:
 * <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-register-agent">§5.1</a>
 * </li>
 * <li>§5.3 Agent Status — {@code agent_not_found} for unknown agent:
 * <a href="https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-status">§5.3</a></li>
 * <li>§5.6 Describe Capability — {@code capability_not_found} / {@code invalid_request}: <a href=
 * "https://agent-auth-protocol.com/specification/v1.0-draft#56-describe-capability">§5.6</a></li>
 * <li>§5.11 Execute Capability — {@code authentication_required}, {@code capability_not_found}:
 * <a href=
 * "https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">§5.11</a></li>
 * <li>§5.7 Introspect Token — {@code invalid_request} on missing token: <a href=
 * "https://agent-auth-protocol.com/specification/v1.0-draft#57-introspect-token">§5.7</a></li>
 * <li>§5.5 Revoke Agent — {@code authentication_required} on missing auth:
 * <a href="https://agent-auth-protocol.com/specification/v1.0-draft#55-revoke-agent">§5.5</a></li>
 * <li>§2.12 Capabilities — {@code capability_exists} on duplicate name: <a href=
 * "https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities">§2.12</a></li>
 * </ul>
 */
class AgentAuthErrorResponseIT extends BaseKeycloakIT {

  // -------------------------------------------------------------------------
  // §5.1 Register Agent
  // -------------------------------------------------------------------------

  /**
   * Verifies that {@code POST /agent/register} without any Authorization header responds with HTTP
   * 401 and a well-formed error body ({@code error} + {@code message}).
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-register-agent">§5.1
   *      Register Agent</a>
   */
  @Test
  void registrationWithMissingAuthReturnsWellFormedError() {
    given()
        .baseUri(realmUrl())
        .contentType(ContentType.JSON)
        .body("{}")
        .when()
        .post("/agent-auth/agent/register")
        .then()
        .statusCode(401)
        .body("error", notNullValue())
        .body("error", instanceOf(String.class))
        .body("message", notNullValue())
        .body("message", instanceOf(String.class));
  }

  // -------------------------------------------------------------------------
  // §5.3 Agent Status
  // -------------------------------------------------------------------------

  /**
   * Verifies that {@code GET /agent/status} for a nonexistent agent responds with HTTP 404 and a
   * well-formed error body.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-status">§5.3
   *      Agent Status</a>
   */
  @Test
  void agentStatusForUnknownAgentReturnsWellFormedError() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwt(hostKey, issuerUrl());

    given()
        .baseUri(realmUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .queryParam("agent_id", "nonexistent-agent-" + UUID.randomUUID())
        .when()
        .get("/agent-auth/agent/status")
        .then()
        .statusCode(404)
        .body("error", notNullValue())
        .body("error", instanceOf(String.class))
        .body("message", notNullValue())
        .body("message", instanceOf(String.class));
  }

  // -------------------------------------------------------------------------
  // §5.6 Describe Capability
  // -------------------------------------------------------------------------

  /**
   * Verifies that {@code GET /capability/describe} for an unknown capability name responds with
   * HTTP 404 and a well-formed error body.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#56-describe-capability">§5.6
   *      Describe Capability</a>
   */
  @Test
  void capabilityDescribeForUnknownCapabilityReturnsWellFormedError() {
    given()
        .baseUri(realmUrl())
        .queryParam("name", "nonexistent_capability_" + UUID.randomUUID().toString()
            .replace("-", "").substring(0, 8))
        .when()
        .get("/agent-auth/capability/describe")
        .then()
        .statusCode(404)
        .body("error", notNullValue())
        .body("error", instanceOf(String.class))
        .body("message", notNullValue())
        .body("message", instanceOf(String.class));
  }

  /**
   * Verifies that {@code GET /capability/describe} without the required {@code name} query
   * parameter responds with HTTP 400 and a well-formed error body.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#56-describe-capability">§5.6
   *      Describe Capability</a>
   */
  @Test
  void capabilityDescribeWithMissingNameParamReturnsWellFormedError() {
    given()
        .baseUri(realmUrl())
        .when()
        .get("/agent-auth/capability/describe")
        .then()
        .statusCode(400)
        .body("error", notNullValue())
        .body("error", instanceOf(String.class))
        .body("message", notNullValue())
        .body("message", instanceOf(String.class));
  }

  // -------------------------------------------------------------------------
  // §5.11 Execute Capability
  // -------------------------------------------------------------------------

  /**
   * Verifies that {@code POST /capability/execute} without any Authorization header responds with
   * HTTP 401 and a well-formed error body.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">§5.11
   *      Execute Capability</a>
   */
  @Test
  void executeWithoutAuthReturnsWellFormedError() {
    given()
        .baseUri(realmUrl())
        .contentType(ContentType.JSON)
        .body("{\"name\": \"some_capability\", \"input\": {}}")
        .when()
        .post("/agent-auth/capability/execute")
        .then()
        .statusCode(401)
        .body("error", notNullValue())
        .body("error", instanceOf(String.class))
        .body("message", notNullValue())
        .body("message", instanceOf(String.class));
  }

  /**
   * Verifies that {@code POST /capability/execute} with a valid agent JWT but an unknown capability
   * name responds with HTTP 404 and a well-formed error body.
   *
   * <p>
   * This test registers a fresh agent inline so that the agent JWT is verifiable by the server; the
   * capability name supplied does not exist in the registry.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">§5.11
   *      Execute Capability</a>
   */
  @Test
  void executeForUnknownCapabilityReturnsWellFormedError() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl());
    preRegisterHost(hostKey);

    String agentId = given()
        .baseUri(realmUrl())
        .contentType(ContentType.JSON)
        .header("Authorization", "Bearer " + hostJwt)
        .body("""
            {
              "name": "Error Response Agent",
              "host_name": "error-response-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Error response test"
            }
            """)
        .when()
        .post("/agent-auth/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    // The cap is unknown so cap-not-found fires before the aud check; aud value here is
    // immaterial. Keep it set to default_location for shape parity with §4.3.
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        issuerUrl() + "/capability/execute");

    given()
        .baseUri(realmUrl())
        .contentType(ContentType.JSON)
        .header("Authorization", "Bearer " + agentJwt)
        .body("{\"name\": \"nonexistent_capability_xyz\", \"input\": {}}")
        .when()
        .post("/agent-auth/capability/execute")
        .then()
        .statusCode(404)
        .body("error", notNullValue())
        .body("error", instanceOf(String.class))
        .body("message", notNullValue())
        .body("message", instanceOf(String.class));
  }

  // -------------------------------------------------------------------------
  // §5.7 Introspect Token
  // -------------------------------------------------------------------------

  /**
   * Verifies that {@code POST /agent/introspect} without a {@code token} field in the request body
   * responds with HTTP 400 and a well-formed error body.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#57-introspect-token">§5.7
   *      Introspect Token</a>
   */
  @Test
  void introspectWithMissingTokenReturnsWellFormedError() {
    given()
        .baseUri(realmUrl())
        .contentType(ContentType.JSON)
        .body("{}")
        .when()
        .post("/agent-auth/agent/introspect")
        .then()
        .statusCode(400)
        .body("error", notNullValue())
        .body("error", instanceOf(String.class))
        .body("message", notNullValue())
        .body("message", instanceOf(String.class));
  }

  // -------------------------------------------------------------------------
  // §5.5 Revoke Agent
  // -------------------------------------------------------------------------

  /**
   * Verifies that {@code POST /agent/revoke} without any Authorization header responds with HTTP
   * 401 and a well-formed error body.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#55-revoke-agent">§5.5
   *      Revoke Agent</a>
   */
  @Test
  void revokeAgentWithoutAuthReturnsWellFormedError() {
    given()
        .baseUri(realmUrl())
        .contentType(ContentType.JSON)
        .body("{\"agent_id\": \"some-agent-id\"}")
        .when()
        .post("/agent-auth/agent/revoke")
        .then()
        .statusCode(401)
        .body("error", notNullValue())
        .body("error", instanceOf(String.class))
        .body("message", notNullValue())
        .body("message", instanceOf(String.class));
  }

  // -------------------------------------------------------------------------
  // §2.12 Capabilities — duplicate name via admin API
  // -------------------------------------------------------------------------

  /**
   * Verifies that registering the same capability {@code name} twice via the admin API returns HTTP
   * 409 with {@code error: "capability_exists"} and a human-readable {@code message}.
   *
   * <p>
   * Per §2.12 the {@code name} is a stable, unique identifier within the realm.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities">§2.12
   *      Capabilities</a>
   */
  @Test
  void registerCapabilityWithDuplicateNameReturnsWellFormedError() {
    String name = "dup_err_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    String token = adminAccessToken();
    String body = String.format("""
        {
          "name": "%s",
          "description": "Duplicate error shape test",
          "visibility": "public",
          "requires_approval": false
        }
        """, name);

    // First registration must succeed.
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(body)
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    // Second registration with the identical name must fail with the spec-mandated shape.
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(body)
        .when()
        .post("/capabilities")
        .then()
        .statusCode(409)
        .body("error", equalTo("capability_exists"))
        .body("message", notNullValue())
        .body("message", instanceOf(String.class));
  }

  // -------------------------------------------------------------------------
  // Cross-cutting: Content-Type header on error responses
  // -------------------------------------------------------------------------

  /**
   * Verifies that error responses from at least three distinct endpoints all carry
   * {@code Content-Type: application/json}.
   *
   * <p>
   * The spec requires every response — including error responses — to use JSON as the wire format.
   *
   * @see <a href="https://agent-auth-protocol.com/docs/errors">Error Catalogue</a>
   */
  @Test
  void errorResponseContentTypeIsJson() {
    // Endpoint 1: POST /agent/register without auth → 401
    given()
        .baseUri(realmUrl())
        .contentType(ContentType.JSON)
        .body("{}")
        .when()
        .post("/agent-auth/agent/register")
        .then()
        .statusCode(401)
        .contentType(containsString("application/json"));

    // Endpoint 2: GET /capability/describe without name param → 400
    given()
        .baseUri(realmUrl())
        .when()
        .get("/agent-auth/capability/describe")
        .then()
        .statusCode(400)
        .contentType(containsString("application/json"));

    // Endpoint 3: POST /capability/execute without auth → 401
    given()
        .baseUri(realmUrl())
        .contentType(ContentType.JSON)
        .body("{\"name\": \"some_capability\", \"input\": {}}")
        .when()
        .post("/agent-auth/capability/execute")
        .then()
        .statusCode(401)
        .contentType(containsString("application/json"));
  }

  // -------------------------------------------------------------------------
  // §5.14 Resource Server Challenge (Optional)
  // -------------------------------------------------------------------------

  /**
   * Verifies that a {@code 401} response from {@code POST /capability/execute} (when called without
   * any Authorization header) includes a {@code WWW-Authenticate} header using the
   * {@code AgentAuth} scheme pointing to the discovery endpoint, per §5.14.
   *
   * <p>
   * Per §5.14, resource servers that support Agent Auth MAY include a
   * {@code WWW-Authenticate: AgentAuth discovery="<url>"} header on {@code 401} responses so that
   * agent-aware clients can locate the authorization server without prior knowledge of the issuer.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#514-resource-server-challenge-optional">§5.14
   *      Resource Server Challenge (Optional)</a>
   */
  @Test
  void unauthorizedExecuteResponseIncludesAgentAuthWwwAuthenticateChallenge() {
    given()
        .baseUri(realmUrl())
        .contentType(ContentType.JSON)
        .body("{\"capability\": \"some_capability\", \"arguments\": {}}")
        .when()
        .post("/agent-auth/capability/execute")
        .then()
        .statusCode(401)
        .header("WWW-Authenticate", containsString("AgentAuth"))
        .header("WWW-Authenticate", containsString("discovery="));
  }
}
