package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import com.github.chh.keycloak.agentauth.support.BaseKeycloakIT;
import com.github.chh.keycloak.agentauth.support.TestJwts;
import com.github.chh.keycloak.agentauth.support.TestKeys;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.restassured.http.ContentType;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Integration tests for {@code POST /agent/introspect} (§5.12).
 *
 * <p>
 * The introspect endpoint validates an agent JWT and returns agent status and granted capabilities
 * following the RFC 7662 model: active tokens return full agent data, inactive tokens return
 * {@code {"active": false}}. A token is active only after the full verification flow defined in
 * §4.5 passes, including §4.6 replay detection.
 *
 * <p>
 * <strong>Spec sections covered by this file:</strong>
 * <ul>
 * <li>§5.12 Introspect — response fields, compact grant format, inactive conditions</li>
 * <li>§4.3 Agent JWT — required claims ({@code typ}, {@code aud}, {@code sub}, {@code jti},
 * {@code iat}, {@code exp}), EdDSA/Ed25519 signing</li>
 * <li>§4.5 Verification — full verification sequence, typ-header check, aud check, agent status
 * check, signature verification</li>
 * <li>§4.6 Replay Detection — {@code jti} uniqueness, server-side seen-jti cache, duplicate
 * rejection within the JWT's max-age window</li>
 * <li>§2.3 Agent States — active, pending, revoked states and their effect on token validity</li>
 * <li>§2.13 Scoped Grants (Constraints) — constraint fields present in introspect response, schema
 * fields ({@code description}, {@code input}, {@code output}) omitted</li>
 * <li>Error codes — {@code invalid_request} (400) for missing required fields</li>
 * </ul>
 *
 * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect">§5.12
 *      Introspect</a>
 * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt">§4.3 Agent
 *      JWT</a>
 * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#45-verification">§4.5
 *      Verification</a>
 * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#46-replay-detection">§4.6
 *      Replay Detection</a>
 * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
 *      Agent States</a>
 * @see <a href=
 *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">§2.13
 *      Scoped Grants (Constraints)</a>
 * @see <a href="https://agent-auth-protocol.com/docs/errors#common-error-codes">Error Codes</a>
 */
class AgentAuthIntrospectIT extends BaseKeycloakIT {

  private static OctetKeyPair hostKey;
  private static OctetKeyPair agentKey;
  private static String agentId;
  private static String grantedCapability;

  /**
   * §4.3 resolved location URL for capabilities registered via {@link #registerCapability(String)}
   * — the agent+jwt's {@code aud} claim MUST be set to this URL (not the issuer URL) for
   * execution-token introspection to succeed.
   */
  private static String capLocation(String name) {
    return "https://resource.example.test/capabilities/" + name;
  }

  @BeforeAll
  static void registerAgent() {
    hostKey = TestKeys.generateEd25519();
    agentKey = TestKeys.generateEd25519();

    grantedCapability = "check_balance_introspect_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    registerCapability(grantedCapability);

    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl());
    preRegisterHost(hostKey);

    agentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Introspect Test Agent",
              "host_name": "introspect-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "Introspect integration test"
            }
            """, grantedCapability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");
  }

  private static void registerCapability(String name) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Check account balance",
              "visibility": "authenticated",
              "requires_approval": false,
              "location": "https://resource.example.test/capabilities/%s",
              "input": {
                "type": "object",
                "properties": {
                  "account_id": {"type": "string"}
                }
              },
              "output": {
                "type": "object"
              }
            }
            """, name, name))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);
  }

  private static void forceExpireAgent(String id) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .post("/agents/" + id + "/expire")
        .then()
        .statusCode(200);
  }

  /**
   * A valid, unexpired agent JWT signed by the registered agent key MUST return {@code active:
   * true} together with the full set of standard response fields ({@code agent_id},
   * {@code host_id}, {@code mode}, {@code expires_at}) and a compact capability grant array after
   * the server completes the full §4.5 verification flow.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect">§5.12
   *      Introspect — active-token response fields</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#45-verification">§4.5
   *      Verification — full verification flow</a>
   */
  @Test
  void introspectValidAgentJwtReturnsActive() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, capLocation(grantedCapability));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
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
        .body("agent_id", equalTo(agentId))
        .body("host_id", notNullValue())
        .body("mode", equalTo("delegated"))
        .body("expires_at", notNullValue())
        .body("agent_capability_grants", hasSize(1))
        .body("agent_capability_grants[0].capability", equalTo(grantedCapability))
        .body("agent_capability_grants[0].status", equalTo("active"));
  }

  /**
   * The introspect endpoint MUST return capability grants in compact format — only {@code
   * capability} and {@code status} fields — explicitly omitting {@code description}, {@code input},
   * {@code output}, and {@code constraints} schema fields that are present in other endpoints.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect">§5.12
   *      Introspect — compact grant objects</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">§2.13
   *      Scoped Grants — introspect compact format</a>
   */
  @Test
  void introspectReturnsCompactCapabilityGrantsOnly() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, capLocation(grantedCapability));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
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
        .body("agent_capability_grants[0].description", nullValue())
        .body("agent_capability_grants[0].input", nullValue())
        .body("agent_capability_grants[0].output", nullValue())
        .body("agent_capability_grants[0].constraints", nullValue());
  }

  /**
   * When the agent JWT contains a {@code capabilities} claim, the server MUST intersect that claim
   * with the agent's registered grants and return only capabilities present in both sets, enforcing
   * the per-request scope restriction defined in §4.3.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt">§4.3 Agent
   *      JWT — {@code capabilities} claim scoping</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#45-verification">§4.5
   *      Verification — capability intersection step</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect">§5.12
   *      Introspect — restricted grant list</a>
   */
  @Test
  void introspectRestrictsReturnedGrantsToCapabilitiesClaim() {
    String agentJwt = TestJwts.agentJwt(
        hostKey,
        agentKey,
        agentId,
        capLocation(grantedCapability),
        Map.of("capabilities", List.of(grantedCapability)));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
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
        .body("agent_capability_grants", hasSize(1))
        .body("agent_capability_grants[0].capability", equalTo(grantedCapability));
  }

  /**
   * An agent JWT whose {@code exp} claim is in the past MUST be treated as inactive; the server
   * MUST return {@code {"active": false}} with no additional fields, as required by §4.3 and the
   * §4.5 standard-claims check.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt">§4.3 Agent
   *      JWT — {@code exp} claim (SHOULD expire within 60 s)</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#45-verification">§4.5
   *      Verification — step 8: check {@code exp}</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect">§5.12
   *      Introspect — inactive-token response</a>
   */
  @Test
  void introspectExpiredAgentJwtReturnsInactive() {
    String expiredJwt = TestJwts.expiredAgentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "token": "%s"
            }
            """, expiredJwt))
        .when()
        .post("/agent/introspect")
        .then()
        .statusCode(200)
        .body("active", equalTo(false));
  }

  /**
   * A token that cannot be parsed as a valid JWT at all MUST result in {@code {"active": false}};
   * malformed input must never cause a server error and must be treated as an inactive token per
   * §5.12.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect">§5.12
   *      Introspect — inactive-token response for unparseable input</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#45-verification">§4.5
   *      Verification — reject on any verification failure</a>
   */
  @Test
  void introspectGarbageTokenReturnsInactive() {
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body("""
            {
              "token": "not.a.valid.jwt"
            }
            """)
        .when()
        .post("/agent/introspect")
        .then()
        .statusCode(200)
        .body("active", equalTo(false));
  }

  /**
   * Per §4.3 the agent+jwt's {@code aud} MUST be the resolved location URL — the capability's
   * {@code location} if set, else the server's {@code default_location}. A JWT whose audience is
   * any other URL (here a third-party host that isn't a registered cap location) MUST be rejected
   * and return {@code {"active": false}}, preventing cross-server token reuse.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt">§4.3 Agent
   *      JWT — {@code aud} MUST be the resolved location URL</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#45-verification">§4.5
   *      Verification — step 3: audience verification</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect">§5.12
   *      Introspect — inactive-token response</a>
   */
  @Test
  void introspectAgentJwtWithWrongAudienceReturnsInactive() {
    String wrongAudJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, "https://wrong.example.com");

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "token": "%s"
            }
            """, wrongAudJwt))
        .when()
        .post("/agent/introspect")
        .then()
        .statusCode(200)
        .body("active", equalTo(false));
  }

  /**
   * Per §4.3 the agent+jwt's {@code aud} for a capability that does not declare its own
   * {@code location} MUST be the server's {@code default_location} (advertised in §5.1 discovery).
   * A JWT minted with {@code aud = default_location} for an agent whose grant points at a
   * location-less cap MUST introspect as active. This pins the §5.11 gateway-as-default fallback
   * path.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt">§4.3 Agent
   *      JWT — {@code aud} fallback to {@code default_location}</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">§5.11
   *      Execute — server's execute endpoint as default location</a>
   */
  @Test
  void introspectAgentJwtWithDefaultLocationAudReturnsActive() {
    String locationlessCap = "locationless_introspect_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Location-less cap (falls back to default_location)",
              "visibility": "authenticated",
              "requires_approval": false,
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, locationlessCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    OctetKeyPair llHostKey = TestKeys.generateEd25519();
    OctetKeyPair llAgentKey = TestKeys.generateEd25519();
    String regJwt = TestJwts.hostJwtForRegistration(llHostKey, llAgentKey, issuerUrl());
    preRegisterHost(llHostKey);
    String llAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Locationless Cap Agent",
              "host_name": "locationless-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "default_location aud test"
            }
            """, locationlessCap))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    String defaultLocation = issuerUrl() + "/capability/execute";
    String agentJwt = TestJwts.agentJwt(llHostKey, llAgentKey, llAgentId, defaultLocation);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(llHostKey, issuerUrl()))
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
        .body("agent_capability_grants", hasSize(1))
        .body("agent_capability_grants[0].capability", equalTo(locationlessCap));
  }

  /**
   * Per §4.3 the agent+jwt's {@code aud} MUST address the resolved location URL of a capability the
   * agent actually holds an active grant for. A token minted with {@code aud} pointing at the
   * location of a capability the agent was never granted MUST introspect as inactive — even if that
   * location is otherwise a valid registered cap on the server. This prevents an agent from passing
   * off tokens that target capabilities outside its grant set.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt">§4.3 Agent
   *      JWT — {@code aud} MUST match a granted cap's resolved location</a>
   */
  @Test
  void introspectAgentJwtWithUngrantedCapLocationAudReturnsInactive() {
    String otherCap = "other_cap_aud_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    registerCapability(otherCap);

    String wrongCapAudJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, capLocation(otherCap));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "token": "%s"
            }
            """, wrongCapAudJwt))
        .when()
        .post("/agent/introspect")
        .then()
        .statusCode(200)
        .body("active", equalTo(false));
  }

  /**
   * An agent whose registration state has been set to {@code revoked} MUST not authenticate;
   * introspecting a cryptographically-valid JWT for a revoked agent MUST return {@code {"active":
   * false}}, as §4.5 step 6 requires rejecting tokens for revoked agents.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
   *      Agent States — revoked: permanent, cannot be reactivated</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#45-verification">§4.5
   *      Verification — step 6: reject if revoked</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect">§5.12
   *      Introspect — inactive-token conditions</a>
   */
  @Test
  void introspectTokenForRevokedAgentReturnsInactive() {
    OctetKeyPair revokeAgentKey = TestKeys.generateEd25519();
    String regJwt = TestJwts.hostJwtForRegistration(hostKey, revokeAgentKey, issuerUrl());
    preRegisterHost(hostKey);

    String revokedAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Revoked Introspect Agent",
              "host_name": "introspect-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Revoke + introspect test"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    String revokeJwt = TestJwts.hostJwt(hostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + revokeJwt)
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

    String agentJwt = TestJwts.agentJwt(hostKey, revokeAgentKey, revokedAgentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
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

  /**
   * Omitting the required {@code token} field from the request body MUST cause the server to return
   * HTTP 400 with {@code error: "invalid_request"}, as the field is mandatory per §5.12 and its
   * absence constitutes a malformed request per the error codes specification.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect">§5.12
   *      Introspect — request requires {@code token} field</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors#common-error-codes">Error Codes —
   *      {@code invalid_request} (400): missing required fields</a>
   */
  @Test
  void introspectWithMissingTokenFieldReturns400() {
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body("{}")
        .when()
        .post("/agent/introspect")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"))
        .body("message", notNullValue());
  }

  /**
   * The server MUST cache every {@code jti} value it has seen and reject any JWT whose {@code jti}
   * was already processed within the token's max-age window; the second call with an identical JWT
   * string (same {@code jti}) MUST return {@code {"active": false}}.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#46-replay-detection">§4.6 Replay
   *      Detection — server MUST cache seen {@code jti} values and reject duplicates</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt">§4.3 Agent
   *      JWT — {@code jti} is required for replay detection</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#45-verification">§4.5
   *      Verification — step 8: {@code jti} replay check</a>
   */
  @Test
  void introspectReplayedAgentJwtReturnsInactive() {
    // Serialize once — both calls use the IDENTICAL string (same jti)
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, capLocation(grantedCapability));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
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

    // Same JWT string again — jti was already seen
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
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

  /**
   * A host JWT (whose {@code typ} header is not {@code agent+jwt}) submitted as the introspect
   * {@code token} value MUST return {@code {"active": false}}; §4.5 step 1 requires rejecting any
   * JWT whose {@code typ} is not {@code agent+jwt} to prevent token-type confusion.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt">§4.3 Agent
   *      JWT — {@code typ} MUST be {@code agent+jwt}</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#45-verification">§4.5
   *      Verification — step 1: reject if {@code typ} is not {@code agent+jwt}</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect">§5.12
   *      Introspect — inactive-token response</a>
   */
  @Test
  void introspectHostJwtReturnsInactive() {
    String hostJwt = TestJwts.hostJwt(hostKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "token": "%s"
            }
            """, hostJwt))
        .when()
        .post("/agent/introspect")
        .then()
        .statusCode(200)
        .body("active", equalTo(false));
  }

  /**
   * An agent in the {@code pending} state (awaiting user approval) MUST NOT authenticate; a
   * cryptographically-valid JWT for a pending agent MUST return {@code {"active": false}} because
   * §2.3 defines pending as "Cannot authenticate" and §4.5 step 6 explicitly rejects pending
   * agents.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
   *      Agent States — pending: awaiting user approval, cannot authenticate</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#45-verification">§4.5
   *      Verification — step 6: reject if pending</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect">§5.12
   *      Introspect — inactive-token conditions</a>
   */
  @Test
  void introspectPendingAgentJwtReturnsInactive() {
    // Register a separate capability requiring approval
    String pendingCap = "pending_introspect_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Requires approval",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, pendingCap, pendingCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    OctetKeyPair pendingHostKey = TestKeys.generateEd25519();
    OctetKeyPair pendingAgentKey = TestKeys.generateEd25519();
    String regJwt = TestJwts.hostJwtForRegistration(pendingHostKey, pendingAgentKey, issuerUrl());
    preRegisterHost(pendingHostKey);

    String pendingAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Pending Introspect Agent",
              "host_name": "pending-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "Pending introspect test"
            }
            """, pendingCap))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("status", equalTo("pending"))
        .extract()
        .path("agent_id");

    String pendingAgentJwt = TestJwts.agentJwt(pendingHostKey, pendingAgentKey, pendingAgentId,
        issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "token": "%s"
            }
            """, pendingAgentJwt))
        .when()
        .post("/agent/introspect")
        .then()
        .statusCode(200)
        .body("active", equalTo(false));
  }

  /**
   * When a capability grant carries constraints, the introspect response MUST include the
   * {@code constraints} object on the grant entry but MUST still omit the capability's schema
   * fields ({@code description}, {@code input}, {@code output}), preserving the compact-but-
   * enforceable format required by §5.12 and §2.13.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">§2.13
   *      Scoped Grants — constraints present in introspect response; schema fields excluded</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect">§5.12
   *      Introspect — compact grant format with constraints</a>
   */
  @Test
  void introspectConstrainedGrantReturnsCompactGrantOnly() {
    // Register a capability for this test
    String constrainedCap = "constrained_introspect_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Transfer funds",
              "visibility": "authenticated",
              "requires_approval": false,
              "location": "https://resource.example.test/capabilities/%s",
              "input": {
                "type": "object",
                "properties": {
                  "amount": {"type": "number"}
                }
              },
              "output": {
                "type": "object"
              }
            }
            """, constrainedCap, constrainedCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    // Register a new agent requesting that capability with constraints
    OctetKeyPair agentKey2 = TestKeys.generateEd25519();
    String regJwt2 = TestJwts.hostJwtForRegistration(hostKey, agentKey2, issuerUrl());
    preRegisterHost(hostKey);

    String constrainedAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt2)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Constrained Introspect Agent",
              "host_name": "constrained-host",
              "capabilities": [
                {
                  "name": "%s",
                  "constraints": {
                    "amount": {"max": 500}
                  }
                }
              ],
              "mode": "delegated",
              "reason": "Constrained introspect test"
            }
            """, constrainedCap))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    String constrainedAgentJwt = TestJwts.agentJwt(hostKey, agentKey2, constrainedAgentId,
        capLocation(constrainedCap));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "token": "%s"
            }
            """, constrainedAgentJwt))
        .when()
        .post("/agent/introspect")
        .then()
        .statusCode(200)
        .body("active", equalTo(true))
        .body("agent_capability_grants[0].constraints", nullValue())
        .body("agent_capability_grants[0].description", nullValue())
        .body("agent_capability_grants[0].input", nullValue())
        .body("agent_capability_grants[0].output", nullValue());

    String validArgsJwt = TestJwts.agentJwt(hostKey, agentKey2, constrainedAgentId,
        capLocation(constrainedCap));
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "token": "%s",
              "capability": "%s",
              "arguments": {"amount": 100}
            }
            """, validArgsJwt, constrainedCap))
        .when()
        .post("/agent/introspect")
        .then()
        .statusCode(200)
        .body("active", equalTo(true))
        .body("capability", equalTo(constrainedCap))
        .body("grant_status", equalTo("active"))
        .body("constraints.amount.max", equalTo(500))
        .body("violations", hasSize(0));

    String violatingArgsJwt = TestJwts.agentJwt(hostKey, agentKey2, constrainedAgentId,
        capLocation(constrainedCap));
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "token": "%s",
              "capability": "%s",
              "arguments": {"amount": 600}
            }
            """, violatingArgsJwt, constrainedCap))
        .when()
        .post("/agent/introspect")
        .then()
        .statusCode(200)
        .body("active", equalTo(true))
        .body("violations", hasSize(1))
        .body("violations[0].field", equalTo("amount"));
  }

  /**
   * A JWT signed by a key that does not match the agent's registered public key MUST fail §4.5 step
   * 7 (signature verification) and the server MUST return {@code {"active": false}}; this prevents
   * forged tokens from appearing valid even when all other claims are correct.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#45-verification">§4.5
   *      Verification — step 7: verify JWT signature against agent's registered public key</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt">§4.3 Agent
   *      JWT — EdDSA/Ed25519 key binding</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect">§5.12
   *      Introspect — inactive-token conditions</a>
   */
  @Test
  void introspectJwtSignedByWrongKeyReturnsInactive() {
    OctetKeyPair wrongKey = TestKeys.generateEd25519();
    String wrongKeyJwt = TestJwts.agentJwt(hostKey, wrongKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "token": "%s"
            }
            """, wrongKeyJwt))
        .when()
        .post("/agent/introspect")
        .then()
        .statusCode(200)
        .body("active", equalTo(false));
  }

  /**
   * When a JWT's {@code capabilities} claim lists a capability the agent was never granted, the
   * server MUST intersect the claim against the agent's actual grants and silently omit the
   * ungranted capability from the response; the token remains active for its legitimately granted
   * capabilities (§4.3 capability intersection rule).
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt">§4.3 Agent
   *      JWT — servers MUST reject requests for capabilities not in granted set</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#45-verification">§4.5
   *      Verification — step 11: intersect {@code capabilities} claim with granted set</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect">§5.12
   *      Introspect — response reflects intersected grant list</a>
   */
  @Test
  void introspectJwtClaimingUngrantedCapabilityOmitsIt() {
    // Register a second capability that the agent will NOT be granted
    String ungrantedCap = "ungrantedForOverclaim_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Ungranted capability",
              "visibility": "authenticated",
              "requires_approval": false,
              "location": "https://resource.example.test/capabilities/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, ungrantedCap, ungrantedCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    // Build an agent JWT for the existing agentId that over-claims by including ungrantedCap
    String overclaimJwt = TestJwts.agentJwt(
        hostKey,
        agentKey,
        agentId,
        capLocation(grantedCapability),
        Map.of("capabilities", List.of(grantedCapability, ungrantedCap)));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "token": "%s"
            }
            """, overclaimJwt))
        .when()
        .post("/agent/introspect")
        .then()
        .statusCode(200)
        .body("active", equalTo(true))
        .body("agent_capability_grants", hasSize(1))
        .body("agent_capability_grants[0].capability", equalTo(grantedCapability));
  }

  // -------------------------------------------------------------------------
  // TODO stubs — spec requirements not yet covered by the tests above
  // -------------------------------------------------------------------------

  /**
   * TODO: An agent in the {@code expired} state (session TTL or max lifetime elapsed) MUST NOT
   * authenticate; a cryptographically-valid JWT for an expired agent MUST return {@code {"active":
   * false}} because §2.3 defines expired as "re-approval required" and §4.5 step 6 rejects tokens
   * for expired agents.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states">§2.3
   *      Agent States — expired: session TTL elapsed, re-approval required</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#45-verification">§4.5
   *      Verification — step 6: reject if expired</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect">§5.12
   *      Introspect — inactive-token conditions</a>
   */
  @Test
  void introspectExpiredAgentStateReturnsInactive() {
    forceExpireAgent(agentId);

    String expiredAgentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "token": "%s"
            }
            """, expiredAgentJwt))
        .when()
        .post("/agent/introspect")
        .then()
        .statusCode(200)
        .body("active", equalTo(false));
  }

  /**
   * TODO: A JWT whose {@code iat} claim is in the future (clock-skew abuse) MUST be rejected as
   * inactive per the §4.5 standard-claims check (step 8), which validates both {@code exp} and
   * {@code iat}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt">§4.3 Agent
   *      JWT — {@code iat} is a required claim</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#45-verification">§4.5
   *      Verification — step 8: check {@code iat}</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect">§5.12
   *      Introspect — inactive-token conditions</a>
   */
  @Test
  void introspectFutureIssuedAtReturnsInactive() {
    try {
      JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
          .type(new JOSEObjectType("agent+jwt"))
          .build();
      long now = System.currentTimeMillis();
      JWTClaimsSet claims = new JWTClaimsSet.Builder()
          .issuer(TestKeys.thumbprint(hostKey))
          .subject(agentId)
          .audience(issuerUrl())
          .issueTime(new Date(now + 120_000L)) // 2 minutes in the future
          .expirationTime(new Date(now + 180_000L))
          .jwtID("a-" + UUID.randomUUID())
          .build();
      SignedJWT jwt = new SignedJWT(header, claims);
      jwt.sign(new Ed25519Signer(agentKey));

      given()
          .baseUri(issuerUrl())
          .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
          .contentType(ContentType.JSON)
          .body(String.format("""
              {
                "token": "%s"
              }
              """, jwt.serialize()))
          .when()
          .post("/agent/introspect")
          .then()
          .statusCode(200)
          .body("active", equalTo(false));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * TODO: A JWT that is missing the required {@code jti} claim MUST be rejected as inactive; §4.3
   * requires {@code jti} to be present in every agent JWT and §4.6 mandates that the server cache
   * and validate it.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt">§4.3 Agent
   *      JWT — {@code jti} is a required claim</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#46-replay-detection">§4.6 Replay
   *      Detection — all JWTs MUST include {@code jti}</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect">§5.12
   *      Introspect — inactive-token conditions</a>
   */
  @Test
  void introspectJwtMissingJtiReturnsInactive() {
    try {
      JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
          .type(new JOSEObjectType("agent+jwt"))
          .build();
      long now = System.currentTimeMillis();
      JWTClaimsSet claims = new JWTClaimsSet.Builder()
          .issuer(TestKeys.thumbprint(hostKey))
          .subject(agentId)
          .audience(issuerUrl())
          .issueTime(new Date(now))
          .expirationTime(new Date(now + 60_000L))
          // no .jwtID() — jti intentionally absent
          .build();
      SignedJWT jwt = new SignedJWT(header, claims);
      jwt.sign(new Ed25519Signer(agentKey));

      given()
          .baseUri(issuerUrl())
          .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
          .contentType(ContentType.JSON)
          .body(String.format("""
              {
                "token": "%s"
              }
              """, jwt.serialize()))
          .when()
          .post("/agent/introspect")
          .then()
          .statusCode(200)
          .body("active", equalTo(false));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * TODO: The introspect endpoint MUST be rate-limited aggressively when exposed without caller
   * authentication; excessive rapid calls MUST eventually return HTTP 429 with
   * {@code error: "rate_limited"} per the §5.12 normative rate-limit requirement.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect">§5.12
   *      Introspect — MUST rate-limit aggressively</a>
   * @see <a href="https://agent-auth-protocol.com/docs/errors#common-error-codes">Error Codes —
   *      {@code rate_limited} (429)</a>
   */
  @Test
  void todoIntrospectRateLimitReturns429() {
    io.restassured.response.Response response = null;
    for (int i = 0; i < 120; i++) {
      response = given()
          .baseUri(issuerUrl())
          .contentType(ContentType.JSON)
          .body("{\"token\":\"not-a-jwt\"}")
          .when()
          .post("/agent/introspect")
          .then()
          .extract()
          .response();
      if (response.statusCode() == 429) {
        break;
      }
    }

    org.junit.jupiter.api.Assertions.assertNotNull(response);
    org.junit.jupiter.api.Assertions.assertEquals(429, response.statusCode());
    response.then()
        .body("error", equalTo("rate_limited"))
        .header("Retry-After", notNullValue());
  }

  /**
   * TODO: A JWT issued for an agent belonging to a host whose registration has been revoked MUST
   * return {@code {"active": false}}; §4.5 step 4 requires the host to be looked up and §5.12 lists
   * "host is unknown, revoked, or pending" as an inactivity condition.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect">§5.12
   *      Introspect — host revoked or unknown → inactive</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#45-verification">§4.5
   *      Verification — step 4: host resolution</a>
   */
  @Test
  void introspectTokenForRevokedHostReturnsInactive() {
    OctetKeyPair revokedHostKey = TestKeys.generateEd25519();
    OctetKeyPair revokedHostAgentKey = TestKeys.generateEd25519();
    String regJwt = TestJwts.hostJwtForRegistration(revokedHostKey, revokedHostAgentKey,
        issuerUrl());
    preRegisterHost(revokedHostKey);

    // Grant the agent a capability so the §4.3 aud check has something to match against —
    // otherwise an aud-less agent would short-circuit to inactive before the host-status check
    // we're trying to exercise.
    String revokedHostCap = "revoked_host_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    registerCapability(revokedHostCap);

    String revokedHostAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Revoked Host Agent",
              "host_name": "revoked-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "Revoked host introspect test"
            }
            """, revokedHostCap))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(revokedHostKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body("{}")
        .when()
        .post("/host/revoke")
        .then()
        .statusCode(200);

    String agentJwt = TestJwts.agentJwt(revokedHostKey, revokedHostAgentKey, revokedHostAgentId,
        capLocation(revokedHostCap));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
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

  /**
   * A JWT that carries a {@code capabilities} claim containing an empty list authorizes zero
   * capabilities and therefore has no resolved location URL it could legitimately address per §4.3
   * — the server MUST treat such a token as inactive. The §4.3 aud rule "MUST be the resolved
   * location URL — the capability's location if set, or the server's default_location" has no
   * satisfiable value when the JWT explicitly authorizes no capabilities, so the server has nothing
   * to introspect against and returns {@code {"active": false}}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt">§4.3 Agent
   *      JWT — {@code capabilities} claim scoping; aud MUST be a resolved location URL</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect">§5.12
   *      Introspect — inactive when no granted cap matches the token</a>
   */
  @Test
  void introspectJwtWithEmptyCapabilitiesClaimReturnsInactive() {
    String agentJwt = TestJwts.agentJwt(
        hostKey,
        agentKey,
        agentId,
        capLocation(grantedCapability),
        Map.of("capabilities", List.of()));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
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

  /**
   * TODO: Constraints using the {@code min} operator MUST be preserved verbatim in the compact
   * grant returned by introspect, proving that all §2.13 operator types round-trip through the
   * introspect response correctly.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">§2.13
   *      Scoped Grants — {@code min}, {@code max}, {@code in}, {@code not_in} operator objects</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect">§5.12
   *      Introspect — constraints in compact grant</a>
   */
  @Test
  void introspectMinConstraintIsNotReturnedInCompactGrant() {
    // Register a capability with a numeric field that supports min constraints
    String minCap = "min_constraint_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Transfer with minimum amount",
              "visibility": "authenticated",
              "requires_approval": false,
              "location": "https://resource.example.test/capabilities/%s",
              "input": {
                "type": "object",
                "properties": {
                  "amount": {"type": "number"}
                }
              },
              "output": {
                "type": "object"
              }
            }
            """, minCap, minCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    // Register a new agent with a min constraint on the amount field
    OctetKeyPair minAgentKey = TestKeys.generateEd25519();
    String minRegJwt = TestJwts.hostJwtForRegistration(hostKey, minAgentKey, issuerUrl());
    preRegisterHost(hostKey);

    String minAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + minRegJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Min Constraint Agent",
              "host_name": "min-constraint-host",
              "capabilities": [
                {
                  "name": "%s",
                  "constraints": {
                    "amount": {"min": 100}
                  }
                }
              ],
              "mode": "delegated",
              "reason": "Min constraint round-trip test"
            }
            """, minCap))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    String minAgentJwt = TestJwts.agentJwt(hostKey, minAgentKey, minAgentId, capLocation(minCap));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "token": "%s"
            }
            """, minAgentJwt))
        .when()
        .post("/agent/introspect")
        .then()
        .statusCode(200)
        .body("active", equalTo(true))
        .body("agent_capability_grants[0].capability", equalTo(minCap))
        .body("agent_capability_grants[0].constraints", nullValue());
  }

  // -------------------------------------------------------------------------
  // Zero-coverage gap tests
  // -------------------------------------------------------------------------

  /**
   * A JWT with no {@code sub} claim MUST return {@code {"active": false}}; §4.3 requires
   * {@code sub} to be present and §4.5 step 5 uses it to look up the agent record.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt">§4.3 Agent
   *      JWT — {@code sub} is a required claim</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#45-verification">§4.5
   *      Verification — step 5: agent lookup by {@code sub}</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect">§5.12
   *      Introspect — inactive-token conditions</a>
   */
  @Test
  void introspectAgentJwtMissingSubReturnsInactive() {
    try {
      JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
          .type(new JOSEObjectType("agent+jwt"))
          .build();
      long now = System.currentTimeMillis();
      JWTClaimsSet claims = new JWTClaimsSet.Builder()
          .issuer(TestKeys.thumbprint(hostKey))
          // no .subject() — sub intentionally absent
          .audience(issuerUrl())
          .issueTime(new Date(now))
          .expirationTime(new Date(now + 60_000L))
          .jwtID("a-" + UUID.randomUUID())
          .build();
      SignedJWT jwt = new SignedJWT(header, claims);
      jwt.sign(new Ed25519Signer(agentKey));

      given()
          .baseUri(issuerUrl())
          .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
          .contentType(ContentType.JSON)
          .body(String.format("""
              {
                "token": "%s"
              }
              """, jwt.serialize()))
          .when()
          .post("/agent/introspect")
          .then()
          .statusCode(200)
          .body("active", equalTo(false));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * A JWT with no {@code iss} claim MUST return {@code {"active": false}}; §4.3 requires
   * {@code iss} to be present and §4.5 step 4 uses it to resolve the host record.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt">§4.3 Agent
   *      JWT — {@code iss} is a required claim</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#45-verification">§4.5
   *      Verification — step 4: host resolution via {@code iss}</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#512-introspect">§5.12
   *      Introspect — inactive-token conditions</a>
   */
  @Test
  void introspectAgentJwtMissingIssReturnsInactive() {
    try {
      JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
          .type(new JOSEObjectType("agent+jwt"))
          .build();
      long now = System.currentTimeMillis();
      JWTClaimsSet claims = new JWTClaimsSet.Builder()
          // no .issuer() — iss intentionally absent
          .subject(agentId)
          .audience(capLocation(grantedCapability))
          .issueTime(new Date(now))
          .expirationTime(new Date(now + 60_000L))
          .jwtID("a-" + UUID.randomUUID())
          .build();
      SignedJWT jwt = new SignedJWT(header, claims);
      jwt.sign(new Ed25519Signer(agentKey));

      given()
          .baseUri(issuerUrl())
          .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
          .contentType(ContentType.JSON)
          .body(String.format("""
              {
                "token": "%s"
              }
              """, jwt.serialize()))
          .when()
          .post("/agent/introspect")
          .then()
          .statusCode(200)
          .body("active", equalTo(false));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
