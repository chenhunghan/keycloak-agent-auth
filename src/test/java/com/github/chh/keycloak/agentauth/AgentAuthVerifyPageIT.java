package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;

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
 * HTML verification page — the browser-facing companion to the JSON verify/approve and verify/deny
 * endpoints (AAP §5.3, §7.1). Covers:
 *
 * <ul>
 * <li>GET /verify with no user_code shows an input prompt.</li>
 * <li>GET /verify with a valid user_code renders the approval form populated with host + agent
 * details.</li>
 * <li>GET /verify with an unknown user_code renders an error page (still 200 so browsers show
 * it).</li>
 * <li>POST /verify with form body + access_token form field approves through the same transition
 * path the JSON endpoints use.</li>
 * <li>POST /verify with Authorization header + form body approves the same way.</li>
 * <li>POST /verify without auth renders a 401 HTML page.</li>
 * </ul>
 */
class AgentAuthVerifyPageIT extends BaseKeycloakIT {

  private static final String USER_PASSWORD = "testpass";

  @Test
  void getVerifyPageWithoutUserCode_rendersPrompt() {
    given()
        .baseUri(issuerUrl())
        .when()
        .get("/verify")
        .then()
        .statusCode(200)
        .contentType(ContentType.HTML)
        .body(containsString("user_code"))
        .body(containsString("<form"));
  }

  @Test
  void getVerifyPageWithPendingUserCode_rendersApprovalForm() {
    String cap = registerApprovalCap("verifypage_ok_" + suffix());
    Response regResp = registerPending(cap);
    String userCode = regResp.jsonPath().getString("approval.user_code");

    given()
        .baseUri(issuerUrl())
        .queryParam("user_code", userCode)
        .when()
        .get("/verify")
        .then()
        .statusCode(200)
        .contentType(ContentType.HTML)
        .body(containsString("Approve"))
        .body(containsString("Deny"))
        .body(containsString("access_token"))
        .body(containsString(htmlEscape(userCode)));
  }

  @Test
  void getVerifyPageWithUnknownUserCode_rendersErrorHtml() {
    given()
        .baseUri(issuerUrl())
        .queryParam("user_code", "ZZZZ-ZZZZ")
        .when()
        .get("/verify")
        .then()
        .statusCode(200)
        .contentType(ContentType.HTML)
        .body(containsString("No pending approval"));
  }

  @Test
  void postVerifyFormWithAccessTokenField_approves() {
    String cap = registerApprovalCap("verifypage_postfield_" + suffix());
    Response regResp = registerPending(cap);
    String agentId = regResp.jsonPath().getString("agent_id");
    String userCode = regResp.jsonPath().getString("approval.user_code");
    OctetKeyPair hostKey = probeHostKey(agentId);

    String username = "verifypage-form-" + suffix();
    createTestUser(username);
    String accessToken = realmUserAccessToken(username);

    given()
        .baseUri(issuerUrl())
        .contentType(ContentType.URLENC)
        .formParam("user_code", userCode)
        .formParam("decision", "approve")
        .formParam("access_token", accessToken)
        .when()
        .post("/verify")
        .then()
        .statusCode(200)
        .contentType(ContentType.HTML)
        .body(containsString("Approved"));

    // Agent state reflects the approval.
    assertThat(agentStatusBody(agentId, hostKey).get("status")).isEqualTo("active");
  }

  @Test
  void postVerifyFormWithBearerHeader_approves() {
    String cap = registerApprovalCap("verifypage_postbearer_" + suffix());
    Response regResp = registerPending(cap);
    String agentId = regResp.jsonPath().getString("agent_id");
    String userCode = regResp.jsonPath().getString("approval.user_code");
    OctetKeyPair hostKey = probeHostKey(agentId);

    String username = "verifypage-bearer-" + suffix();
    createTestUser(username);
    String accessToken = realmUserAccessToken(username);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + accessToken)
        .contentType(ContentType.URLENC)
        .formParam("user_code", userCode)
        .formParam("decision", "approve")
        .when()
        .post("/verify")
        .then()
        .statusCode(200)
        .body(containsString("Approved"));

    assertThat(agentStatusBody(agentId, hostKey).get("status")).isEqualTo("active");
  }

  @Test
  void postVerifyFormDenyDecision_transitionsToRejectedAndShowsHtml() {
    String cap = registerApprovalCap("verifypage_deny_" + suffix());
    Response regResp = registerPending(cap);
    String agentId = regResp.jsonPath().getString("agent_id");
    String userCode = regResp.jsonPath().getString("approval.user_code");
    OctetKeyPair hostKey = probeHostKey(agentId);

    String username = "verifypage-deny-" + suffix();
    createTestUser(username);
    String accessToken = realmUserAccessToken(username);

    given()
        .baseUri(issuerUrl())
        .contentType(ContentType.URLENC)
        .formParam("user_code", userCode)
        .formParam("decision", "deny")
        .formParam("access_token", accessToken)
        .when()
        .post("/verify")
        .then()
        .statusCode(200)
        .body(containsString("Denied"));

    assertThat(agentStatusBody(agentId, hostKey).get("status")).isEqualTo("rejected");
  }

  @Test
  void postVerifyFormWithoutAuth_returns401Html() {
    given()
        .baseUri(issuerUrl())
        .contentType(ContentType.URLENC)
        .formParam("user_code", "AAAA-BBBB")
        .formParam("decision", "approve")
        .when()
        .post("/verify")
        .then()
        .statusCode(401)
        .contentType(ContentType.HTML)
        .body(containsString("Authentication required"));
  }

  @Test
  void postVerifyFormWithMissingDecision_returns400Html() {
    given()
        .baseUri(issuerUrl())
        .contentType(ContentType.URLENC)
        .formParam("user_code", "AAAA-BBBB")
        .when()
        .post("/verify")
        .then()
        .statusCode(400)
        .body(containsString("Missing user_code or decision"));
  }

  @Test
  void postVerifyFormWithInvalidDecision_returns400Html() {
    given()
        .baseUri(issuerUrl())
        .contentType(ContentType.URLENC)
        .formParam("user_code", "AAAA-BBBB")
        .formParam("decision", "maybe")
        .when()
        .post("/verify")
        .then()
        .statusCode(400)
        .body(containsString("Invalid decision"));
  }

  // --- helpers ---

  private static String suffix() {
    return UUID.randomUUID().toString().replace("-", "").substring(0, 8);
  }

  private static String htmlEscape(String raw) {
    return raw.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace("\"", "&quot;").replace("'", "&#x27;");
  }

  private static String registerApprovalCap(String name) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "verify-page IT cap",
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

  private static Response registerPending(String capability) {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    return given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "verify-page agent",
              "capabilities": ["%s"],
              "mode": "delegated"
            }
            """, capability))
        .when()
        .post("/agent/register");
  }

  /**
   * Looks up the host key for a just-registered agent by re-deriving it from the host JWT — we
   * cached the keys inside the registerPending helper, but didn't return them. For this IT we only
   * need to assert the agent transitioned; we grant ourselves a fresh host by querying status using
   * a host key we newly generate, accepting that this returns 403 host_mismatch — we only care
   * about agent.status which we get via a secondary path below.
   */
  private static OctetKeyPair probeHostKey(String agentId) {
    // See agentStatusBody — we don't actually need to match the real host to read the agent's
    // stored status through /admin/realms/{r}/agent-auth/... (which we don't have here). For
    // this IT we keep the real path in registerPending via a tweak: read status via the same
    // host JWT we used to register. Since registerPending generated the key locally, we cannot
    // reconstruct it — so the assertions below go through the admin-level lookup instead.
    return null;
  }

  /**
   * Reads the agent record via the same approval pipeline — /agent/status requires a host JWT we
   * don't retain here, so we use a thin admin fetch instead. Falls back to /agent/status only for
   * tests that have the host key.
   */
  @SuppressWarnings("unchecked")
  private static Map<String, Object> agentStatusBody(String agentId, OctetKeyPair maybeHostKey) {
    // Admin lookup is the one that works without remembering the host key.
    return given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/admin/realms/" + REALM + "/agent-auth/agents/" + agentId)
        .then()
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
        .body(Map.of("type", "password", "value", USER_PASSWORD, "temporary", false))
        .when()
        .put("/admin/realms/" + REALM + "/users/" + userId + "/reset-password")
        .then()
        .statusCode(204);
    return userId;
  }

  private static String realmUserAccessToken(String username) {
    String tokenUrl = KEYCLOAK.getAuthServerUrl() + "/realms/" + REALM;
    return given()
        .baseUri(tokenUrl)
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
