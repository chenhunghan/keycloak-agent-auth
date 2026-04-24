package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.matchesPattern;

import com.github.chh.keycloak.agentauth.support.BaseKeycloakIT;
import com.github.chh.keycloak.agentauth.support.TestJwts;
import com.github.chh.keycloak.agentauth.support.TestKeys;
import com.nimbusds.jose.jwk.OctetKeyPair;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Device-authorization approval flow for delegated agent registration (AAP §5.3 + §7.1).
 *
 * <p>
 * Scope for this IT:
 *
 * <ul>
 * <li>§5.1: discovery advertises {@code device_authorization} in {@code approval_methods}.</li>
 * <li>§5.3 + §7.1: registration of a delegated agent under an unlinked host returns
 * {@code status=pending} and an {@code approval} object with {@code method="device_authorization"},
 * a short {@code user_code}, {@code verification_uri}, {@code verification_uri_complete},
 * {@code expires_in} and {@code interval}.</li>
 * <li>§7.1: when a KC user approves via {@code POST /verify/approve}, the agent transitions to
 * {@code active} and the host is linked (host.user_id = approving user's id).</li>
 * <li>§7.1: denial is terminal — {@code POST /verify/deny} transitions the agent to
 * {@code rejected}; re-attempting approve on the same user_code is rejected.</li>
 * <li>§8.11: approval requires a real authenticated Keycloak user identity (not the admin service
 * token). The IT supplies a fresh access token via direct-access grant.</li>
 * </ul>
 *
 * <p>
 * MVP omissions (tracked for follow-up): no HTML verification page, no CIBA, no WebAuthn
 * escalation, no partial per-capability approval.
 */
class AgentAuthDeviceApprovalIT extends BaseKeycloakIT {

  private static final String USER_PASSWORD = "testpass";

  @Test
  void discoveryAdvertisesDeviceAuthorization() {
    // §5.1: `approval_methods` is required and includes core values.
    given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .when()
        .get("/realms/" + REALM + "/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .body("approval_methods",
            org.hamcrest.Matchers.hasItem("device_authorization"));
  }

  @Test
  void registerDelegatedAgentOnUnlinkedHost_returnsDeviceAuthApprovalObject() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String cap = registerApprovalRequiredCapability("devauth_reg_" + suffix());

    Response resp = registerDelegatedAgent(hostKey, agentKey, cap);
    resp.then()
        .statusCode(200)
        .body("status", org.hamcrest.Matchers.equalTo("pending"))
        .body("approval.method", org.hamcrest.Matchers.equalTo("device_authorization"))
        .body("approval.user_code", matchesPattern("[A-Z]{4}-[A-Z]{4}"))
        .body("approval.verification_uri", org.hamcrest.Matchers.notNullValue())
        .body("approval.expires_in", org.hamcrest.Matchers.greaterThan(0))
        .body("approval.interval", org.hamcrest.Matchers.greaterThan(0));

    String userCode = resp.jsonPath().getString("approval.user_code");
    String vuriComplete = resp.jsonPath().getString("approval.verification_uri_complete");
    assertThat(vuriComplete).contains(userCode);
  }

  @Test
  void approveViaUserCode_activatesAgentAndLinksHostToApprover() {
    // Set up a pending registration.
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String cap = registerApprovalRequiredCapability("devauth_approve_" + suffix());
    Response regResp = registerDelegatedAgent(hostKey, agentKey, cap);
    String agentId = regResp.jsonPath().getString("agent_id");
    String userCode = regResp.jsonPath().getString("approval.user_code");

    // Create a realm user + acquire their access token.
    String username = "approver-" + suffix();
    String userId = createTestUser(username);
    String userAccessToken = realmUserAccessToken(username);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + userAccessToken)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", userCode))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(200);

    // Agent flipped to active.
    Map<String, Object> status = agentStatusBody(agentId, hostKey);
    assertThat(status.get("status")).isEqualTo("active");
    // Host linked to the approving user.
    assertThat(status.get("user_id")).isEqualTo(userId);
  }

  @Test
  void denyViaUserCode_transitionsAgentToRejected() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String cap = registerApprovalRequiredCapability("devauth_deny_" + suffix());
    Response regResp = registerDelegatedAgent(hostKey, agentKey, cap);
    String agentId = regResp.jsonPath().getString("agent_id");
    String userCode = regResp.jsonPath().getString("approval.user_code");

    String username = "denier-" + suffix();
    createTestUser(username);
    String userAccessToken = realmUserAccessToken(username);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + userAccessToken)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", userCode))
        .when()
        .post("/verify/deny")
        .then()
        .statusCode(200);

    assertThat(agentStatusBody(agentId, hostKey).get("status")).isEqualTo("rejected");
  }

  @Test
  void approveAfterDeny_returns410_becauseDenialIsTerminal() {
    // §7.1: "User denial is terminal for that attempt. Client MUST NOT retry." The re-approval
    // attempt must be rejected.
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String cap = registerApprovalRequiredCapability("devauth_denyterm_" + suffix());
    Response regResp = registerDelegatedAgent(hostKey, agentKey, cap);
    String userCode = regResp.jsonPath().getString("approval.user_code");

    String username = "denier-then-approver-" + suffix();
    createTestUser(username);
    String token = realmUserAccessToken(username);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", userCode))
        .when()
        .post("/verify/deny")
        .then()
        .statusCode(200);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", userCode))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(410);
  }

  @Test
  void approveUnknownUserCode_returns404() {
    String username = "stranger-" + suffix();
    createTestUser(username);
    String token = realmUserAccessToken(username);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", "ZZZZ-ZZZZ"))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(404);
  }

  @Test
  void capabilityRequestApproval_activatesGrantsWithoutChangingAgentStatus() {
    // §5.4 + §7 + §7.1: a capability-request on an already-active agent that needs user
    // approval MUST go through the same device_authorization flow. The agent stays `active`;
    // only the pending grants flip to `active`.
    String autoCap = registerAutoCapability("devauth_capreq_auto_" + suffix());
    String approvalCap = registerApprovalRequiredCapability("devauth_capreq_" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();

    // Register the agent with only the auto-approved capability → status=active straight away.
    String agentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "capreq agent",
              "capabilities": ["%s"],
              "mode": "delegated"
            }
            """, autoCap))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("status", org.hamcrest.Matchers.equalTo("active"))
        .extract()
        .path("agent_id");

    // Agent now requests the approval-required capability.
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());
    Response reqResp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"]
            }
            """, approvalCap))
        .when()
        .post("/agent/request-capability");
    reqResp.then()
        .statusCode(200)
        .body("approval.method", org.hamcrest.Matchers.equalTo("device_authorization"))
        .body("approval.user_code", matchesPattern("[A-Z]{4}-[A-Z]{4}"));
    String userCode = reqResp.jsonPath().getString("approval.user_code");

    // User approves.
    String username = "capreq-approver-" + suffix();
    createTestUser(username);
    String userAccessToken = realmUserAccessToken(username);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + userAccessToken)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", userCode))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(200);

    // Agent status remains active; the newly-requested grant is now active too.
    Map<String, Object> status = agentStatusBody(agentId, hostKey);
    assertThat(status.get("status")).isEqualTo("active");
    @SuppressWarnings("unchecked")
    java.util.List<Map<String, Object>> grants = (java.util.List<Map<String, Object>>) status
        .get("agent_capability_grants");
    Map<String, Object> requestedGrant = grants.stream()
        .filter(g -> approvalCap.equals(g.get("capability")))
        .findFirst()
        .orElseThrow(() -> new AssertionError("Requested grant missing"));
    assertThat(requestedGrant.get("status")).isEqualTo("active");
  }

  @Test
  void reactivateApproval_flipsExpiredAgentBackToActive() {
    // §5.6 + §7: reactivate of an expired agent triggers approval again when reactivated grants
    // require it. After the first approval the host is linked to the approver, so the
    // reactivation approval follows the CIBA path (§7.3 — prefer CIBA when user is known);
    // the user approves via agent_id rather than user_code.
    String approvalCap = registerApprovalRequiredCapability("devauth_react_" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();

    // Register as delegated + capability requires approval → pending + device_authorization.
    Response regResp = registerDelegatedAgent(hostKey, agentKey, approvalCap);
    String agentId = regResp.jsonPath().getString("agent_id");
    String firstUserCode = regResp.jsonPath().getString("approval.user_code");

    // First approval to get to active. This links the host to the approver.
    String username = "reactivate-approver-" + suffix();
    createTestUser(username);
    String userAccessToken = realmUserAccessToken(username);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + userAccessToken)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", firstUserCode))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(200);

    // Admin forces expiration of the agent.
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .when()
        .post("/agents/" + agentId + "/expire")
        .then()
        .statusCode(200);

    // Agent requests reactivation — default_capability_grants replay forces approval again.
    // Host is now linked → CIBA approval.
    String hostJwtForReact = TestJwts.hostJwt(hostKey, issuerUrl());
    Response reactResp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwtForReact)
        .contentType(ContentType.JSON)
        .body(Map.of("agent_id", agentId))
        .when()
        .post("/agent/reactivate");
    reactResp.then()
        .statusCode(200)
        .body("status", org.hamcrest.Matchers.equalTo("pending"))
        .body("approval.method", org.hamcrest.Matchers.equalTo("ciba"))
        .body("approval.user_code", org.hamcrest.Matchers.nullValue())
        .body("approval.verification_uri", org.hamcrest.Matchers.nullValue());

    // Approve the reactivation via CIBA agent_id path.
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + realmUserAccessToken(username))
        .contentType(ContentType.JSON)
        .body(Map.of("agent_id", agentId))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(200);

    assertThat(agentStatusBody(agentId, hostKey).get("status")).isEqualTo("active");
  }

  @Test
  @SuppressWarnings("unchecked")
  void partialApproval_subsetOfCapabilitiesApproved_restDenied() {
    // §5.3: "When a registration requests multiple capabilities, the user MAY approve some and
    // deny others. The server MUST reflect this in the agent_capability_grants array — each
    // grant carries its own status."
    String capA = registerApprovalRequiredCapability("devauth_partial_a_" + suffix());
    String capB = registerApprovalRequiredCapability("devauth_partial_b_" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();

    Response regResp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "partial agent",
              "capabilities": ["%s", "%s"],
              "mode": "delegated"
            }
            """, capA, capB))
        .when()
        .post("/agent/register");
    regResp.then().statusCode(200).body("status", org.hamcrest.Matchers.equalTo("pending"));
    String agentId = regResp.jsonPath().getString("agent_id");
    String userCode = regResp.jsonPath().getString("approval.user_code");

    String username = "partial-approver-" + suffix();
    createTestUser(username);
    String token = realmUserAccessToken(username);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", userCode, "capabilities", java.util.List.of(capA)))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(200);

    Map<String, Object> status = agentStatusBody(agentId, hostKey);
    assertThat(status.get("status")).as("agent becomes active even on partial approval")
        .isEqualTo("active");
    java.util.List<Map<String, Object>> grants = (java.util.List<Map<String, Object>>) status
        .get("agent_capability_grants");
    Map<String, Object> grantA = grants.stream()
        .filter(g -> capA.equals(g.get("capability"))).findFirst().orElseThrow();
    Map<String, Object> grantB = grants.stream()
        .filter(g -> capB.equals(g.get("capability"))).findFirst().orElseThrow();
    assertThat(grantA.get("status")).as("selected capability approved").isEqualTo("active");
    assertThat(grantB.get("status")).as("unselected capability denied").isEqualTo("denied");
  }

  @Test
  @SuppressWarnings("unchecked")
  void partialApproval_emptyCapabilitiesList_deniesAllButLeavesAgentActive() {
    // §5.3: "A fully denied registration (all capabilities denied) sets the agent status to
    // "active" with an empty or all-denied grants array." — this is distinct from /verify/deny
    // which is the explicit "reject the agent entirely" path.
    String capA = registerApprovalRequiredCapability("devauth_emptyapprove_a_" + suffix());
    String capB = registerApprovalRequiredCapability("devauth_emptyapprove_b_" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();

    Response regResp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "empty-approve agent",
              "capabilities": ["%s", "%s"],
              "mode": "delegated"
            }
            """, capA, capB))
        .when()
        .post("/agent/register");
    String agentId = regResp.jsonPath().getString("agent_id");
    String userCode = regResp.jsonPath().getString("approval.user_code");

    String username = "empty-approver-" + suffix();
    createTestUser(username);
    String token = realmUserAccessToken(username);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", userCode, "capabilities", java.util.List.of()))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(200);

    Map<String, Object> status = agentStatusBody(agentId, hostKey);
    assertThat(status.get("status")).isEqualTo("active");
    java.util.List<Map<String, Object>> grants = (java.util.List<Map<String, Object>>) status
        .get("agent_capability_grants");
    assertThat(grants).allSatisfy(g -> assertThat(g.get("status")).isEqualTo("denied"));
  }

  @Test
  @SuppressWarnings("unchecked")
  void partialApproval_onCapabilityRequest_deniesUnselectedGrantsButKeepsAgentActive() {
    String autoCap = registerAutoCapability("devauth_capreq_partial_auto_" + suffix());
    String approvA = registerApprovalRequiredCapability("devauth_capreq_partial_a_" + suffix());
    String approvB = registerApprovalRequiredCapability("devauth_capreq_partial_b_" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();

    String agentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "partial cap-req agent",
              "capabilities": ["%s"],
              "mode": "delegated"
            }
            """, autoCap))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());
    Response reqResp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s", "%s"]
            }
            """, approvA, approvB))
        .when()
        .post("/agent/request-capability");
    String userCode = reqResp.jsonPath().getString("approval.user_code");

    String username = "partial-capreq-" + suffix();
    createTestUser(username);
    String token = realmUserAccessToken(username);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", userCode, "capabilities", java.util.List.of(approvA)))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(200);

    Map<String, Object> status = agentStatusBody(agentId, hostKey);
    assertThat(status.get("status")).isEqualTo("active");
    java.util.List<Map<String, Object>> grants = (java.util.List<Map<String, Object>>) status
        .get("agent_capability_grants");
    assertThat(grants.stream().filter(g -> approvA.equals(g.get("capability"))).findFirst()
        .orElseThrow().get("status")).isEqualTo("active");
    assertThat(grants.stream().filter(g -> approvB.equals(g.get("capability"))).findFirst()
        .orElseThrow().get("status")).isEqualTo("denied");
    // The originally-active auto capability must stay active.
    assertThat(grants.stream().filter(g -> autoCap.equals(g.get("capability"))).findFirst()
        .orElseThrow().get("status")).isEqualTo("active");
  }

  @Test
  void approveWithoutAuth_returns401() {
    given()
        .baseUri(issuerUrl())
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", "AAAA-BBBB"))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(401);
  }

  // --- helpers ---

  private static String suffix() {
    return UUID.randomUUID().toString().replace("-", "").substring(0, 8);
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

    // Set password via the dedicated reset-password endpoint so no "UPDATE_PASSWORD" required
    // action is planted on the account (which would block direct-access grant with
    // "Account is not fully set up").
    given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + adminToken)
        .contentType(ContentType.JSON)
        .body(Map.of("type", "password", "value", USER_PASSWORD, "temporary", false))
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
        .formParam("password", USER_PASSWORD)
        .when()
        .post("/protocol/openid-connect/token");
    if (resp.getStatusCode() != 200) {
      throw new AssertionError("Password grant failed: status=" + resp.getStatusCode()
          + " body=" + resp.getBody().asString());
    }
    return resp.jsonPath().getString("access_token");
  }

  private static String registerAutoCapability(String name) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Auto-approved capability",
              "visibility": "authenticated",
              "requires_approval": false,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, name, name))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);
    return name;
  }

  private static String registerApprovalRequiredCapability(String name) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Capability requiring approval",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, name, name))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);
    return name;
  }

  private static Response registerDelegatedAgent(OctetKeyPair hostKey, OctetKeyPair agentKey,
      String capability) {
    String jwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl());
    return given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + jwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "device-auth agent",
              "capabilities": ["%s"],
              "mode": "delegated"
            }
            """, capability))
        .when()
        .post("/agent/register");
  }

  private static Map<String, Object> agentStatusBody(String agentId, OctetKeyPair hostKey) {
    return given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .queryParam("agent_id", agentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(200)
        .extract()
        .jsonPath()
        .getMap("$");
  }
}
