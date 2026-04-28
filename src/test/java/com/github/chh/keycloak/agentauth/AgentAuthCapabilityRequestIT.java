package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import com.github.chh.keycloak.agentauth.support.BaseKeycloakIT;
import com.github.chh.keycloak.agentauth.support.TestJwts;
import com.github.chh.keycloak.agentauth.support.TestKeys;
import com.nimbusds.jose.jwk.OctetKeyPair;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Integration tests for {@code POST /agent/request-capability} per the Agent Auth Protocol spec.
 *
 * <p>
 * Spec sections covered by this file:
 * <ul>
 * <li>§5.4 Request Capability — endpoint contract, request/response fields, auto-approval, partial
 * approval, approval-pending flow:
 * <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
 * §5.4</a></li>
 * <li>§2.13 Scoped Grants (Constraints) — constraint operators, server narrowing rule:
 * <a href="https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
 * §2.13</a></li>
 * <li>§4.3 Agent JWT — {@code typ:agent+jwt} header, required claims, expiry validation:
 * <a href="https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt"> §4.3</a></li>
 * <li>§2.3 Agent States — only {@code active} agents may call this endpoint; {@code revoked},
 * {@code pending}, and {@code expired} states are rejected:
 * <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states"> §2.3</a></li>
 * <li>Capability Escalation — escalated capabilities always require explicit user consent and are
 * dropped on reactivation:
 * <a href="https://agent-auth-protocol.com/docs/capabilities#capability-escalation"> Capability
 * Escalation</a></li>
 * <li>Error codes for request-capability: <a href=
 * "https://agent-auth-protocol.com/docs/errors#capability-request-post-agentrequest-capability">
 * Error Codes</a></li>
 * </ul>
 */
class AgentAuthCapabilityRequestIT extends BaseKeycloakIT {

  private static OctetKeyPair hostKey;
  private static OctetKeyPair agentKey;
  private static String agentId;
  private static String activeCapability;
  private static String constrainedCapability;

  @BeforeEach
  void registerAgent() {
    hostKey = TestKeys.generateEd25519();
    agentKey = TestKeys.generateEd25519();

    String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    activeCapability = "check_balance_request_" + suffix;
    constrainedCapability = "transfer_money_request_" + suffix;

    registerCapability(activeCapability, "Check account balance");
    registerCapability(constrainedCapability, "Transfer funds");

    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl());
    preRegisterHost(hostKey);

    agentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Capability Request Agent",
              "host_name": "cap-request-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Capability request test"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");
  }

  private static void registerCapability(String name, String description) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "%s",
              "visibility": "authenticated",
              "requires_approval": false,
              "location": "https://resource.example.test/capabilities/%s",
              "input": {
                "type": "object",
                "properties": {
                  "account_id": {"type": "string"},
                  "amount": {"type": "number"}
                }
              },
              "output": {
                "type": "object"
              }
            }
            """, name, description, name))
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
   * §5.4 requires that a successful request for an auto-approved capability returns HTTP 200 with
   * an {@code agent_capability_grants} array whose single entry carries {@code status:"active"} and
   * the full capability details ({@code description}, {@code input}).
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — auto-approval response</a>
   */
  @Test
  void requestAdditionalCapabilityReturnsDetailedGrant() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "User asked to check balance"
            }
            """, activeCapability))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(200)
        .body("agent_capability_grants", hasSize(1))
        .body("agent_capability_grants[0].capability", equalTo(activeCapability))
        .body("agent_capability_grants[0].status", equalTo("active"))
        .body("agent_capability_grants[0].description", equalTo("Check account balance"))
        .body("agent_capability_grants[0].input.type", equalTo("object"));
  }

  /**
   * §2.13 allows the agent to propose scoped constraints on a capability; the server MUST echo back
   * the effective (possibly narrowed) constraints in the grant object. This test verifies that a
   * {@code max} constraint proposed by the agent is reflected in the response grant.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
   *      §2.13 Scoped Grants (Constraints) — agent-proposed constraints</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — constraint handling in response</a>
   */
  @Test
  void requestCapabilityWithConstraintsReturnsEffectiveConstraints() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": [
                {
                  "name": "%s",
                  "constraints": {
                    "amount": {"max": 500}
                  }
                }
              ],
              "reason": "User wants to transfer funds"
            }
            """, constrainedCapability))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(200)
        .body("agent_capability_grants[0].capability", equalTo(constrainedCapability))
        .body("agent_capability_grants[0].constraints.amount.max", equalTo(500));
  }

  /**
   * §5.4 mandates that the endpoint MUST require agent JWT authorization; a request with no
   * {@code Authorization} header MUST be rejected with HTTP 401 and error code
   * {@code authentication_required}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — authorization requirement</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-request-post-agentrequest-capability">
   *      Error Codes — authentication_required</a>
   */
  @Test
  void requestCapabilityWithoutAuthReturns401() {
    given()
        .baseUri(issuerUrl())
        .contentType(ContentType.JSON)
        .body("""
            {
              "capabilities": ["check_balance"],
              "reason": "No auth"
            }
            """)
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(401)
        .body("error", equalTo("authentication_required"))
        .body("message", notNullValue());
  }

  /**
   * §4.3 defines the Agent JWT as having {@code typ:agent+jwt} in its header; the server MUST
   * reject a Host JWT (which carries a different {@code typ}) with HTTP 401 and error code
   * {@code invalid_jwt}, since only agent JWTs are accepted on this endpoint.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt"> §4.3
   *      Agent JWT — typ claim requirement</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — agent JWT required, not host JWT</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-request-post-agentrequest-capability">
   *      Error Codes — invalid_jwt</a>
   */
  @Test
  void requestCapabilityWithHostJwtReturns401() {
    String hostJwt = TestJwts.hostJwt(hostKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "Wrong JWT type"
            }
            """, activeCapability))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_jwt"))
        .body("message", notNullValue());
  }

  /**
   * §5.4 specifies that requesting a capability the agent already holds is an error; the server
   * MUST return HTTP 409 with error code {@code already_granted} on a duplicate request for an
   * active grant.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — duplicate grant detection</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-request-post-agentrequest-capability">
   *      Error Codes — already_granted</a>
   */
  @Test
  void requestAlreadyGrantedCapabilityReturns409() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "Initial request"
            }
            """, activeCapability))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(200);

    String duplicateRequestJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + duplicateRequestJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "Duplicate request"
            }
            """, activeCapability))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(409)
        .body("error", equalTo("already_granted"))
        .body("message", notNullValue());
  }

  /**
   * §5.4 requires the server to verify that every capability name in the request exists; if any
   * name is unknown the server MUST return HTTP 400 with error code {@code invalid_capabilities}
   * and an {@code invalid_capabilities} array listing the unrecognized names.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — capability existence validation</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-request-post-agentrequest-capability">
   *      Error Codes — invalid_capabilities</a>
   */
  @Test
  void requestNonexistentCapabilityReturns400() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "capabilities": ["totally_fake_capability"],
              "reason": "Testing bad capability"
            }
            """)
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_capabilities"))
        .body("message", notNullValue())
        .body("invalid_capabilities[0]", equalTo("totally_fake_capability"));
  }

  /**
   * §2.13 defines the valid constraint operators ({@code max}, {@code min}, {@code in},
   * {@code not_in}); the server MUST reject any request that uses an unrecognized operator with
   * HTTP 400 and error code {@code unknown_constraint_operator}.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
   *      §2.13 Scoped Grants (Constraints) — valid operators</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-request-post-agentrequest-capability">
   *      Error Codes — unknown_constraint_operator</a>
   */
  @Test
  void requestCapabilityWithUnknownConstraintOperatorReturns400() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": [
                {
                  "name": "%s",
                  "constraints": {
                    "amount": {"between": [1, 10]}
                  }
                }
              ],
              "reason": "Bad constraints"
            }
            """, constrainedCapability))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(400)
        .body("error", equalTo("unknown_constraint_operator"))
        .body("message", notNullValue());
  }

  /**
   * §5.4 lists {@code capabilities} as a required request field; a request body that omits it
   * (empty JSON object) MUST be rejected with HTTP 400 and error code {@code invalid_request}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — required request fields</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-request-post-agentrequest-capability">
   *      Error Codes — invalid_request</a>
   */
  @Test
  void requestCapabilityWithMissingBodyReturns400() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body("{}")
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"))
        .body("message", notNullValue());
  }

  /**
   * §4.3 requires the server to validate the {@code exp} claim of the agent JWT; a JWT whose expiry
   * has passed MUST be rejected with HTTP 401 and error code {@code invalid_jwt}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt"> §4.3
   *      Agent JWT — exp claim validation</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-request-post-agentrequest-capability">
   *      Error Codes — invalid_jwt</a>
   */
  @Test
  void requestCapabilityWithExpiredAgentJwtReturns401() {
    String expiredJwt = TestJwts.expiredAgentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + expiredJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "Expired JWT test"
            }
            """, activeCapability))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_jwt"))
        .body("message", notNullValue());
  }

  /**
   * §2.3 defines the {@code revoked} agent state as permanently terminal; §5.4 requires the server
   * to verify agent status before processing the request and MUST return HTTP 403 with error code
   * {@code agent_revoked} when the identified agent is in the {@code revoked} state.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states"> §2.3
   *      Agent States — revoked state</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — agent state pre-condition</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-request-post-agentrequest-capability">
   *      Error Codes — agent_revoked</a>
   */
  @Test
  void requestCapabilityWithRevokedAgentReturns403() {
    OctetKeyPair freshHostKey = TestKeys.generateEd25519();
    OctetKeyPair freshAgentKey = TestKeys.generateEd25519();

    String regJwt = TestJwts.hostJwtForRegistration(freshHostKey, freshAgentKey, issuerUrl());
    preRegisterHost(freshHostKey);
    String revokedAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Revoked Request Agent",
              "host_name": "revoke-request-host",
              "capabilities": [],
              "mode": "delegated",
              "reason": "Revoked agent capability request test"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    String hostJwt = TestJwts.hostJwt(freshHostKey, issuerUrl());
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

    String agentJwt = TestJwts.agentJwt(freshHostKey, freshAgentKey, revokedAgentId, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "Revoked agent requesting capability"
            }
            """, activeCapability))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(403)
        .body("error", equalTo("agent_revoked"))
        .body("message", notNullValue());
  }

  /**
   * §2.3 defines the {@code pending} agent state as one that has not yet received approval from
   * registration; §5.4 requires that only {@code active} agents may request capabilities, so a
   * {@code pending} agent MUST be rejected with HTTP 403 and error code {@code agent_pending}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states"> §2.3
   *      Agent States — pending state</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — active agent pre-condition</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-request-post-agentrequest-capability">
   *      Error Codes — agent_pending</a>
   */
  @Test
  void requestCapabilityWithPendingAgentReturns403() {
    OctetKeyPair pendingHostKey = TestKeys.generateEd25519();
    OctetKeyPair pendingAgentKey = TestKeys.generateEd25519();

    String pendingCapName = "approval_pending_request_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Requires approval for pending agent test",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, pendingCapName, pendingCapName))
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
              "name": "Pending Request Agent",
              "host_name": "pending-request-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "Pending agent capability request test"
            }
            """, pendingCapName))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("status", equalTo("pending"))
        .extract()
        .path("agent_id");

    String agentJwt = TestJwts.agentJwt(pendingHostKey, pendingAgentKey, pendingAgentId,
        issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "Pending agent requesting active capability"
            }
            """, activeCapability))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(403)
        .body("error", equalTo("agent_pending"))
        .body("message", notNullValue());
  }

  /**
   * §5.4 specifies that when a requested capability has {@code requires_approval:true} the server
   * MUST return HTTP 200 with the grant carrying {@code status:"pending"} and an {@code approval}
   * object containing admin-mediated polling instructions. Capability Escalation rules additionally
   * require that escalated capabilities always go through explicit user consent regardless of host
   * trust.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — approval-required response and approval object</a>
   * @see <a href="https://agent-auth-protocol.com/docs/capabilities#capability-escalation">
   *      Capability Escalation — mandatory explicit consent</a>
   */
  @Test
  void requestApprovalRequiredCapabilityReturnsPendingGrant() {
    String approvalCap = "approval_request_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Requires user approval",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, approvalCap, approvalCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "Need approval capability"
            }
            """, approvalCap))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(200)
        .body("agent_capability_grants[0].capability", equalTo(approvalCap))
        .body("agent_capability_grants[0].status", equalTo("pending"))
        .body("approval", notNullValue())
        .body("approval.method", equalTo("device_authorization"))
        .body("approval.status_url", notNullValue());
  }

  /**
   * §5.4 + §2.13: when {@code /agent/request-capability} returns a pending grant for an
   * approval-required cap that the agent requested with a constraint scope, the response MUST stay
   * in the compact pending shape — neither {@code constraints} nor the internal
   * {@code requested_constraints} stash may appear on the wire. The constraint is held in storage
   * so the activation flow can promote it onto the active grant on approval (covered by the
   * round-trip test in {@link AgentAuthDeviceApprovalIT}).
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — pending response shape</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
   *      §2.13 Scoped Grants (Constraints)</a>
   */
  @Test
  void requestApprovalRequiredCapabilityWithConstraintsReturnsCompactPendingGrant() {
    String approvalCap = "constrained_pending_request_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Requires user approval",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, approvalCap, approvalCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": [
                {
                  "name": "%s",
                  "constraints": {"amount": {"max": 75}}
                }
              ]
            }
            """, approvalCap))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(200)
        .body("agent_capability_grants[0].capability", equalTo(approvalCap))
        .body("agent_capability_grants[0].status", equalTo("pending"))
        .body("agent_capability_grants[0].status_url", notNullValue())
        // §5.4: pending grant MUST NOT echo `constraints` (compact response shape).
        .body("agent_capability_grants[0].constraints", nullValue())
        // The internal stash MUST NOT leak onto the wire.
        .body("agent_capability_grants[0].requested_constraints", nullValue());
  }

  // ---------------------------------------------------------------------------
  // TODO stubs — spec requirements not yet covered by tests above
  // ---------------------------------------------------------------------------

  /**
   * §5.4 states that a request for multiple capabilities MAY result in partial approval: some
   * grants {@code active}, others {@code pending} or {@code denied}. The response MUST include one
   * grant object per requested capability, each with its own {@code status}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — partial approval behavior</a>
   */
  @Test
  void todoRequestMultipleCapabilitiesReturnsOneGrantPerCapability() {
    String mixedApprovalCap = "mixed_approval_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Requires user approval for mixed test",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, mixedApprovalCap, mixedApprovalCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s", "%s"],
              "reason": "Requesting two capabilities at once"
            }
            """, activeCapability, mixedApprovalCap))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(200)
        .body("agent_capability_grants", hasSize(2))
        .body("agent_capability_grants.find { it.capability == '%s' }.status"
            .formatted(activeCapability), equalTo("active"))
        .body("agent_capability_grants.find { it.capability == '%s' }.status"
            .formatted(mixedApprovalCap), equalTo("pending"));
  }

  /**
   * §5.4 specifies that the response includes an {@code agent_id} field at the top level
   * identifying the agent the grants were issued to.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — agent_id in response</a>
   */
  @Test
  void todoResponseIncludesAgentId() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    String responseCap = "agent_id_response_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Capability for agent_id response test",
              "visibility": "authenticated",
              "requires_approval": false,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, responseCap, responseCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "Testing agent_id in response"
            }
            """, responseCap))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(200)
        .body("agent_id", equalTo(agentId));
  }

  /**
   * §5.4 requires the server to extend the agent's session TTL on a successful capability request.
   * After a successful call to this endpoint the agent's expiry time MUST be refreshed.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — session TTL extension on success</a>
   */
  @Test
  void todoSuccessfulRequestExtendsAgentSessionTtl() throws InterruptedException {
    String initialExpiry = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .queryParam("agent_id", agentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(200)
        .body("expires_at", notNullValue())
        .extract()
        .path("expires_at");

    Thread.sleep(10L);

    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "TTL extension test"
            }
            """, activeCapability))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(200)
        .body("agent_capability_grants[0].status", equalTo("active"));

    String refreshedExpiry = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .queryParam("agent_id", agentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(200)
        .body("expires_at", notNullValue())
        .extract()
        .path("expires_at");

    Assertions.assertTrue(Instant.parse(refreshedExpiry).isAfter(Instant.parse(initialExpiry)),
        "A successful capability request must refresh expires_at");
  }

  /**
   * §5.4 allows the agent to supply a {@code preferred_method} hint for approval-required
   * capabilities. This implementation only supports admin-mediated HTTP approval, so unsupported
   * hints are accepted but the response remains {@code method:"admin"}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — preferred_method hint</a>
   */
  @Test
  void todoUnsupportedPreferredMethodHintFallsBackToAdminApprovalObject() {
    String prefMethodCap = "pref_method_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Requires approval for preferred_method test",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, prefMethodCap, prefMethodCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "Testing preferred_method hint",
              "preferred_method": "device_authorization"
            }
            """, prefMethodCap))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(200)
        .body("agent_capability_grants[0].status", equalTo("pending"))
        .body("approval.method", equalTo("device_authorization"))
        .body("approval.status_url", notNullValue())
        .body("approval.verification_uri", notNullValue())
        .body("approval.user_code", notNullValue());
  }

  /**
   * §5.4 allows the agent to supply a {@code login_hint}. Since this implementation does not start
   * a native CIBA/device flow, it accepts the field but keeps the admin approval object free of
   * device/CIBA-specific fields.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — login_hint field</a>
   */
  @Test
  void todoLoginHintIsAcceptedAndForwardedToApprovalFlow() {
    String loginHintCap = "login_hint_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Requires approval for login_hint test",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, loginHintCap, loginHintCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "Testing login_hint forwarding",
              "login_hint": "user@example.com"
            }
            """, loginHintCap))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(200)
        .body("agent_capability_grants[0].status", equalTo("pending"))
        .body("approval", notNullValue())
        .body("approval.method", equalTo("device_authorization"))
        .body("approval.login_hint", nullValue());
  }

  /**
   * §5.4 allows the agent to supply a {@code binding_message} for approval methods that surface it
   * to the approver. Admin-mediated approval accepts the field but does not echo CIBA-specific
   * metadata in the response object.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — binding_message field</a>
   */
  @Test
  void todoBindingMessageIsAcceptedForApprovalRequiredCapability() {
    String bindingMsgCap = "binding_msg_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Requires approval for binding_message test",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, bindingMsgCap, bindingMsgCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "Testing binding_message acceptance",
              "binding_message": "Approve transfer"
            }
            """, bindingMsgCap))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(200)
        .body("agent_capability_grants[0].status", equalTo("pending"))
        .body("approval", notNullValue())
        .body("approval.method", equalTo("device_authorization"))
        .body("approval.binding_message", nullValue());
  }

  /**
   * §2.3 states that an agent in the {@code expired} state MUST NOT use this endpoint; the server
   * MUST return HTTP 403 with error code {@code agent_expired}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#23-agent-states"> §2.3
   *      Agent States — expired state</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-request-post-agentrequest-capability">
   *      Error Codes — agent_expired</a>
   */
  @Test
  void requestCapabilityWithExpiredAgentReturns403() {
    // Distinct from requestCapabilityWithExpiredAgentJwtReturns401 which covers a JWT whose
    // exp claim has passed (HTTP 401, error "invalid_jwt"). This test covers an agent whose
    // server-side session state is "expired" while carrying a valid (non-expired) JWT.
    forceExpireAgent(agentId);

    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "Expired agent capability request test"
            }
            """, activeCapability))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(403)
        .body("error", equalTo("agent_expired"))
        .body("message", notNullValue());
  }

  /**
   * §2.13 states the server MUST NOT widen constraints beyond what the agent proposed without a new
   * approval; this test verifies that the effective constraints returned are always equal to or
   * narrower than the agent-proposed constraints.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
   *      §2.13 Scoped Grants (Constraints) — server must not widen constraints</a>
   */
  @Test
  void todoServerDoesNotWidenConstraintsBeyondAgentProposal() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    String narrowCapability = "narrow_constraint_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Capability for constraint narrowing test",
              "visibility": "authenticated",
              "requires_approval": false,
              "location": "https://resource.example.test/%s",
              "input": {
                "type": "object",
                "properties": {
                  "amount": {"type": "number"}
                }
              },
              "output": {"type": "object"}
            }
            """, narrowCapability, narrowCapability))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": [
                {
                  "name": "%s",
                  "constraints": {
                    "amount": {"max": 100}
                  }
                }
              ],
              "reason": "Testing that server does not widen agent constraints"
            }
            """, narrowCapability))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(200)
        .body("agent_capability_grants[0].constraints.amount.max", lessThanOrEqualTo(100));
  }

  /**
   * Capability Escalation rules require that escalated capabilities are dropped when an agent is
   * reactivated via §5.6; after reactivation the agent's capability list MUST reset to the host's
   * defaults and previously escalated capabilities MUST NOT appear.
   *
   * @see <a href="https://agent-auth-protocol.com/docs/capabilities#capability-escalation">
   *      Capability Escalation — capabilities reset on reactivation</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — escalated grants are not persistent across reactivation</a>
   */
  @Test
  void todoEscalatedCapabilitiesAreDroppedOnAgentReactivation() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "Temporary escalation before reactivation"
            }
            """, activeCapability))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(200)
        .body("agent_capability_grants[0].capability", equalTo(activeCapability))
        .body("agent_capability_grants[0].status", equalTo("active"));

    forceExpireAgent(agentId);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
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
        .body("status", equalTo("active"))
        .body("agent_capability_grants", hasSize(0));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .queryParam("agent_id", agentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(200)
        .body("agent_capability_grants", hasSize(0));
  }

  // ---------------------------------------------------------------------------
  // Zero-coverage gap tests
  // ---------------------------------------------------------------------------

  /**
   * §5.4 lists {@code capabilities} as a required request field; a POST with no body at all MUST be
   * rejected with HTTP 400 and error code {@code invalid_request}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — required request fields</a>
   */
  @Test
  void requestCapabilityWithNullBodyReturns400() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"))
        .body("message", notNullValue());
  }

  /**
   * §5.4 lists {@code capabilities} as a required, non-empty field; a request body with an empty
   * array MUST be rejected with HTTP 400 and error code {@code invalid_request}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — required request fields</a>
   */
  @Test
  void requestCapabilityWithEmptyCapabilitiesArrayReturns400() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "capabilities": [],
              "reason": "Empty capabilities array"
            }
            """)
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"))
        .body("message", notNullValue());
  }

  // ---------------------------------------------------------------------------
  // §5.4 approval flow — TDD tests (production code not yet implemented)
  // ---------------------------------------------------------------------------

  /**
   * §5.4 requires that when a capability has {@code requires_approval:true} the response {@code
   * approval} object MUST contain enough method-specific information for clients to poll the
   * approval flow. For the custom admin-mediated method, that shape is {@code method},
   * {@code expires_in}, {@code interval}, and {@code status_url}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — approval object required fields</a>
   */
  @Test
  void approvalObjectContainsRequiredFields() {
    String approvalFieldsCap = "approval_fields_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Requires approval for field presence test",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, approvalFieldsCap, approvalFieldsCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "Checking approval object required fields"
            }
            """, approvalFieldsCap))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(200)
        .body("approval.method", equalTo("device_authorization"))
        .body("approval.expires_in", notNullValue())
        .body("approval.interval", notNullValue())
        .body("approval.status_url", notNullValue())
        .body("approval.verification_uri", notNullValue())
        .body("approval.user_code", notNullValue());
  }

  /**
   * §5.4 specifies {@code expires_in} in the approval object as the seconds until the approval
   * request expires; it MUST be a positive integer so the agent can use it for polling/display.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — approval object expires_in</a>
   */
  @Test
  void approvalObjectExpiresInIsPositiveInteger() {
    String expiresInCap = "approval_expires_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Requires approval for expires_in test",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, expiresInCap, expiresInCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "Checking approval.expires_in is positive"
            }
            """, expiresInCap))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(200)
        .body("approval.expires_in", greaterThan(0));
  }

  /**
   * §5.4 specifies that a grant for an approval-required capability MUST carry {@code
   * status:"pending"} specifically on the grant object (not merely at the response root), so the
   * agent can distinguish per-capability state when multiple capabilities are requested.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — grant-level status field</a>
   */
  @Test
  void approvalPendingGrantHasStatusPending() {
    String pendingStatusCap = "pending_status_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Requires approval for pending status test",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, pendingStatusCap, pendingStatusCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "Checking grant.status is pending"
            }
            """, pendingStatusCap))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(200)
        .body("agent_capability_grants[0].capability", equalTo(pendingStatusCap))
        .body("agent_capability_grants[0].status", equalTo("pending"));
  }

  /**
   * §5.4 defines a polling flow: after requesting an approval-required capability the agent polls
   * the {@code status_url} from the grant until approval completes; once the user approves, a GET
   * to that URL MUST return {@code status:"active"} for the grant.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — approval polling via status_url</a>
   */
  @Test
  void approvalCompletionTransitionsPendingToActive() {
    String pollCap = "approval_poll_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Requires approval for polling transition test",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, pollCap, pollCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    String statusUrl = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "Testing approval polling transition"
            }
            """, pollCap))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(200)
        .body("agent_capability_grants[0].status", equalTo("pending"))
        .body("agent_capability_grants[0].status_url", notNullValue())
        .extract()
        .path("agent_capability_grants[0].status_url");

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .post("/agents/" + agentId + "/capabilities/" + pollCap + "/approve")
        .then()
        .statusCode(200)
        .body("status", equalTo("active"))
        // Per AAP §3.3.1, admin-mediated approval must record the approver's user id in
        // granted_by (not a literal string), separate from user_id (the end-user context).
        .body("granted_by",
            org.hamcrest.Matchers.matchesPattern(
                "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"));

    // §5.5 polling: the per-grant status URL is published for pending grants too, so it must be
    // host-authenticated — pending agents can't mint a valid agent+jwt (§2.3). The host owns the
    // grant lifecycle and is therefore the principal that polls.
    String pollingJwt = TestJwts.hostJwt(hostKey, issuerUrl());

    given()
        .header("Authorization", "Bearer " + pollingJwt)
        .when()
        .get(statusUrl)
        .then()
        .statusCode(200)
        .body("status", equalTo("active"));
  }

  /**
   * §5.4 states that when requesting multiple capabilities a mixed response is valid: auto-approved
   * capabilities appear as {@code "active"} and approval-required ones as {@code "pending"} in the
   * same {@code agent_capability_grants} array.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — partial approval, mixed grant statuses</a>
   */
  @Test
  void partialApprovalResponseHasMixedGrantStatuses() {
    String partialApprovalCap = "partial_approval_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    String partialActiveCap = "partial_active_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Auto-approved capability for mixed status test",
              "visibility": "authenticated",
              "requires_approval": false,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, partialActiveCap, partialActiveCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Approval-required capability for mixed status test",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, partialApprovalCap, partialApprovalCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s", "%s"],
              "reason": "Testing mixed grant statuses in one request"
            }
            """, partialActiveCap, partialApprovalCap))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(200)
        .body("agent_capability_grants", hasSize(2))
        .body("agent_capability_grants.status", hasItem("active"))
        .body("agent_capability_grants.status", hasItem("pending"));
  }

  // ---------------------------------------------------------------------------
  // §5.4 + §7.1 approval-expiry persistence (Audit 02 P1 regression)
  // ---------------------------------------------------------------------------

  /**
   * §5.4 + §7.1: a capability-request that returns a pending {@code approval} object MUST persist
   * {@code approval.issued_at_ms} on the agent so {@code /verify/approve} can enforce the same
   * window it advertised. Regression coverage for Audit 02 P1 — previously the approval blob was
   * only echoed in the response and never stored, leaving capability-request approvals redeemable
   * indefinitely past {@code expires_in}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#71-approval-flow">§7.1
   *      Approval Flow — expiry enforcement</a>
   */
  @Test
  @SuppressWarnings("unchecked")
  void requestCapabilityWithApproval_persistsIssuedAtMsOnAgent() {
    String approvalCap = "approval_persist_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Persist issued_at_ms test",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, approvalCap, approvalCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    long beforeMs = System.currentTimeMillis();
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "Persist issued_at_ms regression"
            }
            """, approvalCap))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(200)
        .body("approval.method", equalTo("device_authorization"))
        .body("approval.expires_in", greaterThan(0));
    long afterMs = System.currentTimeMillis();

    // Read the persisted approval blob via the admin GET /agents/{id} endpoint.
    java.util.Map<String, Object> agentBody = given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/agents/" + agentId)
        .then()
        .statusCode(200)
        .extract()
        .jsonPath()
        .getMap("$");

    Object approvalRaw = agentBody.get("approval");
    assertThat(approvalRaw)
        .as("Audit 02 P1: capability-request MUST persist approval blob on agent")
        .isInstanceOf(java.util.Map.class);
    java.util.Map<String, Object> approval = (java.util.Map<String, Object>) approvalRaw;
    Object issuedAtRaw = approval.get("issued_at_ms");
    assertThat(issuedAtRaw)
        .as("approval.issued_at_ms is required for verifyApprove expiry enforcement")
        .isInstanceOf(Number.class);
    long issuedAt = ((Number) issuedAtRaw).longValue();
    // Allow 5s clock-skew tolerance between the IT JVM and the Keycloak container. The exact
    // value is not the assertion target — what matters is that some non-stale millisecond
    // timestamp landed in the persisted blob so /verify/approve can compare against it.
    assertThat(issuedAt)
        .as("issued_at_ms must be a recent wall-clock millisecond timestamp")
        .isBetween(beforeMs - 5000L, afterMs + 5000L);
  }

  /**
   * §5.4 + §7.1: when an agent posts {@code /agent/request-capability} for an approval-required
   * cap, the {@code user_code} returned in the {@code approval} object MUST become unredeemable
   * once {@code expires_in} elapses. The realm's {@code agent_auth_approval_expires_in_seconds} is
   * temporarily lowered so the test can wait past the window without slowing the suite. Mirrors the
   * registration-path expiry test in {@link AgentAuthDeviceApprovalIT}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#71-approval-flow">§7.1
   *      Approval Flow — stale user_code MUST be rejected with {@code approval_expired}</a>
   */
  @Test
  void approveCapabilityRequestAfterUserCodeExpired_returns410() throws InterruptedException {
    long previous = currentApprovalExpirySeconds();
    setApprovalExpirySeconds(2L);
    try {
      String approvalCap = "capreq_expiry_cap_"
          + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
      given()
          .baseUri(adminApiUrl())
          .header("Authorization", "Bearer " + adminAccessToken())
          .contentType(ContentType.JSON)
          .body(String.format("""
              {
                "name": "%s",
                "description": "Capreq expiry test",
                "visibility": "authenticated",
                "requires_approval": true,
                "location": "https://resource.example.test/%s",
                "input": {"type": "object"},
                "output": {"type": "object"}
              }
              """, approvalCap, approvalCap))
          .when()
          .post("/capabilities")
          .then()
          .statusCode(201);

      String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());
      Response reqResp = given()
          .baseUri(issuerUrl())
          .header("Authorization", "Bearer " + agentJwt)
          .contentType(ContentType.JSON)
          .body(String.format("""
              {
                "capabilities": ["%s"],
                "reason": "Capreq expiry"
              }
              """, approvalCap))
          .when()
          .post("/agent/request-capability");
      reqResp.then()
          .statusCode(200)
          .body("approval.expires_in", equalTo(2));
      String userCode = reqResp.jsonPath().getString("approval.user_code");

      // Wait past the expiry threshold (with margin for test latency).
      Thread.sleep(3000L);

      String username = "capreq-expiry-approver-"
          + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
      createTestUser(username);
      String token = realmUserAccessToken(username);

      given()
          .baseUri(issuerUrl())
          .header("Authorization", "Bearer " + token)
          .contentType(ContentType.JSON)
          .body(Map.of("user_code", userCode))
          .when()
          .post("/verify/approve")
          .then()
          .statusCode(410)
          .body("error", equalTo("approval_expired"));
    } finally {
      setApprovalExpirySeconds(previous);
    }
  }

  /**
   * §5.4 + §7.1: control test for the expiry-after-N-seconds case — when the approver acts within
   * the advertised {@code expires_in} window the approval MUST succeed and flip the pending grant
   * to {@code active}. Pairs with
   * {@link #approveCapabilityRequestAfterUserCodeExpired_returns410()} to bracket the expiry
   * boundary.
   */
  @Test
  void approveCapabilityRequestWithinWindow_succeeds() {
    String approvalCap = "capreq_within_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Capreq within-window approval test",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, approvalCap, approvalCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());
    Response reqResp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "Capreq within window"
            }
            """, approvalCap))
        .when()
        .post("/agent/request-capability");
    reqResp.then()
        .statusCode(200)
        .body("approval.user_code", notNullValue());
    String userCode = reqResp.jsonPath().getString("approval.user_code");

    String username = "capreq-within-approver-"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    createTestUser(username);
    String token = realmUserAccessToken(username);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", userCode))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(200);
  }

  // --- §5.5 per-grant status URL: host+jwt polling semantics ---

  /**
   * §5.5 polling: the per-grant status URL ({@code GET /agent/{agentId}/capabilities/{cap}/status})
   * is published in the registration response for pending grants too. Pending agents cannot mint a
   * valid agent+jwt (§2.3), so the host — the principal that registered the agent — is what polls
   * the URL. With the agent still in {@code pending}, the host's host+jwt MUST authenticate on this
   * endpoint and the response MUST surface the grant's {@code pending} status. Without this, hosts
   * watching for an agent to clear approval would never reach a usable signal.
   */
  @Test
  void pendingAgentHostCanPollPerGrantStatusAndSeesPending() {
    OctetKeyPair pendingHostKey = TestKeys.generateEd25519();
    OctetKeyPair pendingAgentKey = TestKeys.generateEd25519();
    preRegisterHost(pendingHostKey);

    String approvalCap = "host_poll_pending_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Host polling pending-agent grant",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, approvalCap, approvalCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    String hostJwt = TestJwts.hostJwtForRegistration(pendingHostKey, pendingAgentKey, issuerUrl());
    Response register = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Pending host-poll agent",
              "host_name": "host-poll-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "host polling regression"
            }
            """, approvalCap))
        .when()
        .post("/agent/register");
    register.then()
        .statusCode(200)
        .body("status", equalTo("pending"))
        .body("agent_capability_grants[0].status_url", notNullValue());
    String statusUrl = register.jsonPath().getString("agent_capability_grants[0].status_url");

    String pollingHostJwt = TestJwts.hostJwt(pendingHostKey, issuerUrl());
    given()
        .header("Authorization", "Bearer " + pollingHostJwt)
        .when()
        .get(statusUrl)
        .then()
        .statusCode(200)
        .body("status", equalTo("pending"))
        .body("capability", equalTo(approvalCap));
  }

  /**
   * §5.5 polling: the per-grant status endpoint must reject a host JWT signed by a different host
   * than the one that owns the agent. Even a fully-valid host+jwt for some other host MUST surface
   * 403 {@code unauthorized} so that one tenant's host can never inspect another tenant's grants.
   */
  @Test
  void perGrantStatusRejectsHostJwtFromDifferentHost() {
    String approvalCap = "host_poll_wrong_host_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Host polling wrong-host rejection",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, approvalCap, approvalCap))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());
    String statusUrl = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "Wrong-host rejection"
            }
            """, approvalCap))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(200)
        .body("agent_capability_grants[0].status_url", notNullValue())
        .extract()
        .path("agent_capability_grants[0].status_url");

    OctetKeyPair otherHostKey = TestKeys.generateEd25519();
    preRegisterHost(otherHostKey);
    String wrongHostJwt = TestJwts.hostJwt(otherHostKey, issuerUrl());

    given()
        .header("Authorization", "Bearer " + wrongHostJwt)
        .when()
        .get(statusUrl)
        .then()
        .statusCode(403)
        .body("error", equalTo("unauthorized"));
  }

  // --- helpers for approval-expiry tests ---

  private static long currentApprovalExpirySeconds() {
    String token = adminAccessToken();
    Response resp = given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + token)
        .when()
        .get("/admin/realms/" + REALM);
    resp.then().statusCode(200);
    String raw = resp.jsonPath().getString("attributes.agent_auth_approval_expires_in_seconds");
    if (raw == null || raw.isBlank()) {
      return 600L;
    }
    return Long.parseLong(raw.trim());
  }

  @SuppressWarnings("unchecked")
  private static void setApprovalExpirySeconds(long seconds) {
    String token = adminAccessToken();
    Response current = given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + token)
        .when()
        .get("/admin/realms/" + REALM);
    current.then().statusCode(200);
    Map<String, Object> body = current.jsonPath().getMap("$");
    Map<String, Object> attrs = body.get("attributes") instanceof Map
        ? (Map<String, Object>) body.get("attributes")
        : new java.util.HashMap<>();
    attrs = new java.util.HashMap<>(attrs);
    attrs.put("agent_auth_approval_expires_in_seconds", String.valueOf(seconds));
    body.put("attributes", attrs);

    given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(body)
        .when()
        .put("/admin/realms/" + REALM)
        .then()
        .statusCode(204);
  }

  private static String createTestUser(String username) {
    String adminToken = adminAccessToken();
    Response resp = given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + adminToken)
        .contentType(ContentType.JSON)
        .body(Map.of(
            "username", username,
            "enabled", true,
            "emailVerified", true,
            "email", username + "@example.test",
            "firstName", "Test",
            "lastName", "User",
            "requiredActions", java.util.List.of()))
        .when()
        .post("/admin/realms/" + REALM + "/users");
    resp.then().statusCode(201);
    String location = resp.getHeader("Location");
    String userId = location.substring(location.lastIndexOf('/') + 1);

    given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + adminToken)
        .contentType(ContentType.JSON)
        .body(Map.of("type", "password", "value", "testpass", "temporary", false))
        .when()
        .put("/admin/realms/" + REALM + "/users/" + userId + "/reset-password")
        .then()
        .statusCode(204);
    return userId;
  }

  private static String realmUserAccessToken(String username) {
    String tokenUrl = KEYCLOAK.getAuthServerUrl() + "/realms/" + REALM;
    Response resp = given()
        .baseUri(tokenUrl)
        .contentType(ContentType.URLENC)
        .formParam("grant_type", "password")
        .formParam("client_id", "agent-auth-test-client")
        .formParam("username", username)
        .formParam("password", "testpass")
        .when()
        .post("/protocol/openid-connect/token");
    if (resp.getStatusCode() != 200) {
      throw new AssertionError("Password grant failed: status=" + resp.getStatusCode()
          + " body=" + resp.getBody().asString());
    }
    return resp.jsonPath().getString("access_token");
  }
}
