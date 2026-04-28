package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import com.github.chh.keycloak.agentauth.support.BaseKeycloakIT;
import com.github.chh.keycloak.agentauth.support.TestJwts;
import com.github.chh.keycloak.agentauth.support.TestKeys;
import com.nimbusds.jose.jwk.OctetKeyPair;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * AAP §7.2 CIBA (Client Initiated Backchannel Authentication) flow.
 *
 * <p>
 * "In this protocol, CIBA is not a separate initiation flow. The client still starts with POST
 * /agent/register ... If the server chooses CIBA, it returns approval.method = 'ciba' in the normal
 * approval object." — §7.2 of the spec.
 *
 * <p>
 * This extension chooses CIBA when the host is already linked to a user (§7.3: "prefer CIBA over
 * device authorization when the requesting agent has potential browser access"). Without push-
 * notification infrastructure, approvals surface through an in-Keycloak inbox endpoint at {@code
 * GET /agent-auth/inbox}; the user then approves via {@code /verify/approve} passing {@code
 * agent_id} instead of a {@code user_code}.
 */
class AgentAuthCibaApprovalIT extends BaseKeycloakIT {

  private static final String USER_PASSWORD = "testpass";

  @Test
  void registerUnderLinkedHost_returnsCibaApprovalObject() {
    String cap = registerApprovalCap("ciba_reg_" + suffix());
    String username = "ciba-reg-" + suffix();
    String userId = createTestUser(username);

    OctetKeyPair hostKey = TestKeys.generateEd25519();
    preRegisterHostLinked(hostKey, userId);

    OctetKeyPair agentKey = TestKeys.generateEd25519();
    Response resp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "ciba agent",
              "capabilities": ["%s"],
              "mode": "delegated",
              "binding_message": "Approve connection for checks"
            }
            """, cap))
        .when()
        .post("/agent/register");
    resp.then()
        .statusCode(200)
        .body("status", org.hamcrest.Matchers.equalTo("pending"))
        .body("approval.method", org.hamcrest.Matchers.equalTo("ciba"))
        .body("approval.binding_message",
            org.hamcrest.Matchers.equalTo("Approve connection for checks"))
        .body("approval.user_code", org.hamcrest.Matchers.nullValue())
        .body("approval.verification_uri", org.hamcrest.Matchers.nullValue());
  }

  @Test
  @SuppressWarnings("unchecked")
  void inboxListsPendingApprovalsForLinkedUser() {
    String cap = registerApprovalCap("ciba_inbox_" + suffix());
    String username = "ciba-inbox-" + suffix();
    String userId = createTestUser(username);
    String token = passwordGrantToken(username);

    OctetKeyPair hostKey = TestKeys.generateEd25519();
    preRegisterHostLinked(hostKey, userId);

    OctetKeyPair agentKey = TestKeys.generateEd25519();
    Response regResp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "ciba inbox agent",
              "capabilities": ["%s"],
              "mode": "delegated"
            }
            """, cap))
        .when()
        .post("/agent/register");
    String agentId = regResp.jsonPath().getString("agent_id");

    Response inboxResp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + token)
        .when()
        .get("/inbox");
    inboxResp.then().statusCode(200);

    List<Map<String, Object>> pending = inboxResp.jsonPath().getList("pending_approvals");
    assertThat(pending).as("inbox must list the pending agent").isNotEmpty();
    assertThat(pending.stream().anyMatch(a -> agentId.equals(a.get("agent_id"))))
        .as("inbox entry must include the new agent").isTrue();
  }

  @Test
  void approveViaAgentIdByLinkedUser_activatesAgent() {
    String cap = registerApprovalCap("ciba_approve_" + suffix());
    String username = "ciba-approve-" + suffix();
    String userId = createTestUser(username);
    String token = passwordGrantToken(username);

    OctetKeyPair hostKey = TestKeys.generateEd25519();
    preRegisterHostLinked(hostKey, userId);

    OctetKeyPair agentKey = TestKeys.generateEd25519();
    Response regResp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "ciba approve agent",
              "capabilities": ["%s"],
              "mode": "delegated"
            }
            """, cap))
        .when()
        .post("/agent/register");
    String agentId = regResp.jsonPath().getString("agent_id");

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("agent_id", agentId))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(200);

    assertThat(adminFetchAgent(agentId).get("status")).isEqualTo("active");
  }

  @Test
  void approveViaAgentIdByStrangerUser_rejected() {
    // §7.2 + §8.11: agent_id lookup must verify the caller actually owns the host.
    String cap = registerApprovalCap("ciba_stranger_" + suffix());
    String ownerUsername = "ciba-owner-" + suffix();
    String ownerUserId = createTestUser(ownerUsername);
    String strangerUsername = "ciba-stranger-" + suffix();
    createTestUser(strangerUsername);
    String strangerToken = passwordGrantToken(strangerUsername);

    OctetKeyPair hostKey = TestKeys.generateEd25519();
    preRegisterHostLinked(hostKey, ownerUserId);

    OctetKeyPair agentKey = TestKeys.generateEd25519();
    Response regResp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "ciba stranger-test agent",
              "capabilities": ["%s"],
              "mode": "delegated"
            }
            """, cap))
        .when()
        .post("/agent/register");
    String agentId = regResp.jsonPath().getString("agent_id");

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + strangerToken)
        .contentType(ContentType.JSON)
        .body(Map.of("agent_id", agentId))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(403)
        .body("error", org.hamcrest.Matchers.equalTo("not_approver"));
  }

  @Test
  void capabilityRequestUnderLinkedHost_returnsCibaApprovalObject() {
    // §5.4 + §7.3: capability-request against an already-linked host should emit CIBA, not
    // device_authorization. Without this, cap-request on a linked host would force the user
    // through a user_code flow even though the server already knows who the user is.
    String autoCap = registerAutoCap("ciba_capreq_auto_" + suffix());
    String approvalCap = registerApprovalCap("ciba_capreq_approv_" + suffix());
    String username = "ciba-capreq-" + suffix();
    String userId = createTestUser(username);

    OctetKeyPair hostKey = TestKeys.generateEd25519();
    preRegisterHostLinked(hostKey, userId);

    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String agentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "ciba capreq agent",
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
    Response capReqResp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "binding_message": "Grant extra permission"
            }
            """, approvalCap))
        .when()
        .post("/agent/request-capability");
    capReqResp.then()
        .statusCode(200)
        .body("approval.method", org.hamcrest.Matchers.equalTo("ciba"))
        .body("approval.user_code", org.hamcrest.Matchers.nullValue())
        .body("approval.binding_message",
            org.hamcrest.Matchers.equalTo("Grant extra permission"));

    // User approves via agent_id path; grant becomes active, agent stays active.
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + passwordGrantToken(username))
        .contentType(ContentType.JSON)
        .body(Map.of("agent_id", agentId))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(200);

    @SuppressWarnings("unchecked")
    List<Map<String, Object>> grants = (List<Map<String, Object>>) adminFetchAgent(agentId)
        .get("agent_capability_grants");
    Map<String, Object> newGrant = grants.stream()
        .filter(g -> approvalCap.equals(g.get("capability"))).findFirst().orElseThrow();
    assertThat(newGrant.get("status")).isEqualTo("active");
  }

  private static String registerAutoCap(String name) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "CIBA cap-request auto",
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

  @Test
  void cibaRegisterSucceedsEvenWhenSmtpDeliveryFails() {
    // §7.2 push channel must be best-effort: when SMTP can't deliver, the inbox is the
    // fallback. The register response itself must NOT fail.
    String cap = registerApprovalCap("ciba_smtp_fail_" + suffix());
    String username = "ciba-smtpfail-" + suffix();
    String userId = createTestUser(username);

    // Point the realm's SMTP at a host that will refuse connections so EmailSenderProvider
    // throws. Must be reverted at the end of the test so other CIBA tests aren't disturbed.
    Map<String, Object> originalRealm = adminGetRealm();
    @SuppressWarnings("unchecked")
    Map<String, String> originalSmtp = (Map<String, String>) originalRealm.getOrDefault(
        "smtpServer",
        new java.util.HashMap<String, String>());
    try {
      adminPutRealm(Map.of("smtpServer", Map.of(
          "host", "127.0.0.1",
          "port", "1",
          "from", "noreply@agent-auth.test",
          "fromDisplayName", "Agent Auth")));

      OctetKeyPair hostKey = TestKeys.generateEd25519();
      preRegisterHostLinked(hostKey, userId);

      OctetKeyPair agentKey = TestKeys.generateEd25519();
      Response resp = given()
          .baseUri(issuerUrl())
          .header("Authorization", "Bearer "
              + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
          .contentType(ContentType.JSON)
          .body(String.format("""
              {
                "name": "smtp-fail agent",
                "capabilities": ["%s"],
                "mode": "delegated"
              }
              """, cap))
          .when()
          .post("/agent/register");
      // Email delivery to 127.0.0.1:1 will fail. Register response must still be 200 and
      // CIBA-shaped — that's the resilience contract.
      resp.then().statusCode(200)
          .body("status", org.hamcrest.Matchers.equalTo("pending"))
          .body("approval.method", org.hamcrest.Matchers.equalTo("ciba"));
    } finally {
      adminPutRealm(Map.of("smtpServer", originalSmtp));
    }
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> adminGetRealm() {
    return given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/admin/realms/" + REALM)
        .then()
        .statusCode(200)
        .extract()
        .jsonPath()
        .getMap("$");
  }

  private static void adminPutRealm(Map<String, Object> patch) {
    given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(patch)
        .when()
        .put("/admin/realms/" + REALM)
        .then()
        .statusCode(204);
  }

  @Test
  void inboxWithoutAuth_returns401() {
    given()
        .baseUri(issuerUrl())
        .when()
        .get("/inbox")
        .then()
        .statusCode(401);
  }

  @Test
  void registerWithoutUserCodeOrAgentId_returns400() {
    String username = "ciba-missing-" + suffix();
    createTestUser(username);
    String token = passwordGrantToken(username);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of())
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(400);
  }

  // --- helpers ---

  private static String suffix() {
    return UUID.randomUUID().toString().replace("-", "").substring(0, 8);
  }

  /**
   * Pre-registers a host bound to {@code userId} so the host comes up active+linked in one admin
   * call. Wave 5 AAP-ADMIN-001: admin {@code POST /hosts} without {@code user_id} now stages the
   * host as {@code pending}, and the subsequent {@code POST /hosts/{id}/link} only sets the
   * {@code user_id} attribute without flipping the host to active. Pending hosts cascade to pending
   * agents — which breaks every CIBA test that needs the linked-host approval-method selector to
   * fire on register. Folding the link into the pre-register step keeps the same surface
   * (active+linked host with a known user_id) the tests were originally written against.
   */
  private static void preRegisterHostLinked(OctetKeyPair hostKey, String userId) {
    java.util.Map<String, Object> body = new java.util.HashMap<>();
    body.put("host_public_key", hostKey.toPublicJWK().toJSONObject());
    body.put("user_id", userId);
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(body)
        .when()
        .post("/hosts")
        .then()
        .statusCode(org.hamcrest.Matchers.anyOf(
            org.hamcrest.Matchers.equalTo(201),
            org.hamcrest.Matchers.equalTo(409)));
  }

  private static String registerApprovalCap(String name) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "CIBA IT cap",
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

  @SuppressWarnings("unchecked")
  private static Map<String, Object> adminFetchAgent(String agentId) {
    return given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/admin/realms/" + REALM + "/agent-auth/agents/" + agentId)
        .then()
        .statusCode(200)
        .extract()
        .jsonPath()
        .getMap("$");
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
            "requiredActions", List.of()))
        .when()
        .post("/admin/realms/" + REALM + "/users");
    resp.then().statusCode(201);
    String location = resp.getHeader("Location");
    String userId = location.substring(location.lastIndexOf('/') + 1);
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

  private static String passwordGrantToken(String username) {
    return given()
        .baseUri(KEYCLOAK.getAuthServerUrl() + "/realms/" + REALM)
        .contentType(ContentType.URLENC)
        .formParam("grant_type", "password")
        .formParam("client_id", "agent-auth-test-client")
        .formParam("username", username)
        .formParam("password", USER_PASSWORD)
        .when()
        .post("/protocol/openid-connect/token")
        .then()
        .statusCode(200)
        .extract()
        .path("access_token");
  }
}
