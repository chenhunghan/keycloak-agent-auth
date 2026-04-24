package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

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
 * AAP §8.11 — "Servers MUST require proof of physical presence (WebAuthn, hardware key) or use an
 * out-of-band approval channel (CIBA on a separate device) when approving capabilities that can
 * modify data or perform actions on behalf of the user."
 *
 * <p>
 * This extension models the per-capability flag with {@code write_capable: true} on the capability
 * registration. When any pending grant being approved refers to such a capability, /verify/approve
 * (and the HTML /verify POST) require the caller's token to carry an approved {@code amr} value
 * (hwk / swk / webauthn / mfa etc. per RFC 8176).
 *
 * <p>
 * Password-grant access tokens produced by Keycloak's direct-access flow carry no {@code amr} by
 * default, which means they fail the proof-of-presence check — that's exactly the §8.11 behaviour
 * we want to verify. A full positive path (token with a genuine WebAuthn factor) is out of scope
 * for this IT because setting up WebAuthn against a headless Testcontainers Keycloak is a
 * multi-hour side-track; the enforcement direction is what matters for spec conformance.
 */
class AgentAuthWriteCapableGrantIT extends BaseKeycloakIT {

  private static final String USER_PASSWORD = "testpass";

  @Test
  void writeCapableGrant_approveWithPasswordOnlyToken_rejected() {
    String cap = registerCapability("writecap_reject_" + suffix(), true);
    Response regResp = registerPending(cap);
    String userCode = regResp.jsonPath().getString("approval.user_code");

    String username = "writecap-reject-" + suffix();
    createTestUser(username);
    String token = passwordGrantToken(username);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", userCode))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(403)
        .body("error", org.hamcrest.Matchers.equalTo("webauthn_required"));
  }

  @Test
  void nonWriteCapableGrant_approveWithPasswordOnlyToken_accepted() {
    String cap = registerCapability("writecap_allow_" + suffix(), false);
    Response regResp = registerPending(cap);
    String agentId = regResp.jsonPath().getString("agent_id");
    String userCode = regResp.jsonPath().getString("approval.user_code");

    String username = "writecap-allow-" + suffix();
    createTestUser(username);
    String token = passwordGrantToken(username);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", userCode))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(200);

    assertThat(adminFetchAgent(agentId).get("status")).isEqualTo("active");
  }

  @Test
  void partialApprovalExcludingWriteCapable_approveWithPasswordOnlyToken_accepted() {
    // If the user's selected subset excludes the write-capable cap, §8.11 has no bite — the
    // approved set is read-only, so a password-only token is sufficient.
    String readCap = registerCapability("writecap_partial_read_" + suffix(), false);
    String writeCap = registerCapability("writecap_partial_write_" + suffix(), true);
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();

    Response regResp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "partial write-capable agent",
              "capabilities": ["%s", "%s"],
              "mode": "delegated"
            }
            """, readCap, writeCap))
        .when()
        .post("/agent/register");
    String agentId = regResp.jsonPath().getString("agent_id");
    String userCode = regResp.jsonPath().getString("approval.user_code");

    String username = "writecap-partial-" + suffix();
    createTestUser(username);
    String token = passwordGrantToken(username);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", userCode, "capabilities", java.util.List.of(readCap)))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(200);

    Map<String, Object> agent = adminFetchAgent(agentId);
    assertThat(agent.get("status")).isEqualTo("active");
  }

  @Test
  void writeCapableGrant_denyWithPasswordOnlyToken_accepted() {
    // Denial is protective, not risky — §8.11's proof-of-presence rule is about approvals that
    // can modify data. Denying a write-capable grant may be done with a plain authenticated
    // token.
    String cap = registerCapability("writecap_denyok_" + suffix(), true);
    Response regResp = registerPending(cap);
    String userCode = regResp.jsonPath().getString("approval.user_code");

    String username = "writecap-deny-" + suffix();
    createTestUser(username);
    String token = passwordGrantToken(username);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", userCode))
        .when()
        .post("/verify/deny")
        .then()
        .statusCode(200);
  }

  // --- helpers ---

  private static String suffix() {
    return UUID.randomUUID().toString().replace("-", "").substring(0, 8);
  }

  private static String registerCapability(String name, boolean writeCapable) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "write-capable IT cap",
              "visibility": "authenticated",
              "requires_approval": true,
              "write_capable": %s,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, name, writeCapable, name))
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
              "name": "write-capable agent",
              "capabilities": ["%s"],
              "mode": "delegated"
            }
            """, capability))
        .when()
        .post("/agent/register");
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
