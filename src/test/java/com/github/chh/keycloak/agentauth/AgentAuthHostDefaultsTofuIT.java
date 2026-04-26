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
 * §3.1 + §5.3 + §5.6: per-host TOFU defaults — a capability the linked user has approved on a host
 * once is added to {@code host.default_capabilities}, and subsequent registrations under that host
 * (or reactivation) auto-grant per the §5.3 rule "if the capabilities fall within its defaults,
 * auto-approve."
 *
 * <p>
 * Coverage:
 *
 * <ul>
 * <li>{@code /verify/approve} appends the approved cap to {@code host.default_capabilities}.</li>
 * <li>The admin grant-approve endpoint also appends.</li>
 * <li>A second agent under the same host registering for a previously-approved cap auto-grants
 * (status=active, agent=active) without an approval flow.</li>
 * <li>Reactivation honors host defaults: a cap that requires approval at first register skips the
 * approval prompt at reactivation when it's in the host's defaults.</li>
 * </ul>
 */
class AgentAuthHostDefaultsTofuIT extends BaseKeycloakIT {

  private static final String USER_PASSWORD = "testpass";

  @Test
  @SuppressWarnings("unchecked")
  void verifyApprove_appendsCapToHostDefaults_andSecondRegisterAutoGrants() {
    String cap = registerApprovalRequiredCapability("tofu_va_" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair firstAgentKey = TestKeys.generateEd25519();

    // 1. First register: host unknown → pending agent + pending grant + device-auth approval.
    Response firstReg = registerDelegatedAgent(hostKey, firstAgentKey, cap);
    firstReg.then().statusCode(200).body("status", org.hamcrest.Matchers.equalTo("pending"));
    String firstAgentId = firstReg.jsonPath().getString("agent_id");
    String userCode = firstReg.jsonPath().getString("approval.user_code");

    // 2. User approves → agent active, host linked, cap added to host.default_capabilities.
    String username = "tofu-va-" + suffix();
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

    Map<String, Object> firstStatus = agentStatusBody(firstAgentId, hostKey);
    assertThat(firstStatus.get("status")).isEqualTo("active");

    // 3. Second register on the SAME host (different agent key) → cap is in host.defaults so
    // the grant auto-approves and the agent itself comes up active immediately.
    OctetKeyPair secondAgentKey = TestKeys.generateEd25519();
    Response secondReg = registerDelegatedAgent(hostKey, secondAgentKey, cap);
    secondReg.then()
        .statusCode(200)
        .body("status", org.hamcrest.Matchers.equalTo("active"))
        .body("approval", org.hamcrest.Matchers.nullValue())
        .body("agent_capability_grants[0].capability", org.hamcrest.Matchers.equalTo(cap))
        .body("agent_capability_grants[0].status", org.hamcrest.Matchers.equalTo("active"));
  }

  @Test
  @SuppressWarnings("unchecked")
  void adminApprove_appendsCapToHostDefaults_andSecondRegisterAutoGrants() {
    String cap = registerApprovalRequiredCapability("tofu_admin_" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair firstAgentKey = TestKeys.generateEd25519();

    Response firstReg = registerDelegatedAgent(hostKey, firstAgentKey, cap);
    String firstAgentId = firstReg.jsonPath().getString("agent_id");

    // Admin approves the pending grant via the admin REST endpoint (not /verify/approve).
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .post("/agents/" + firstAgentId + "/capabilities/" + cap + "/approve")
        .then()
        .statusCode(200);

    OctetKeyPair secondAgentKey = TestKeys.generateEd25519();
    Response secondReg = registerDelegatedAgent(hostKey, secondAgentKey, cap);
    secondReg.then()
        .statusCode(200)
        .body("status", org.hamcrest.Matchers.equalTo("active"))
        .body("agent_capability_grants[0].status", org.hamcrest.Matchers.equalTo("active"));
  }

  @Test
  @SuppressWarnings("unchecked")
  void reactivation_grantsCapAutomaticallyWhenInHostDefaults() {
    // §5.6 "follow the same auto-approval logic as registration" — a previously-approved cap in
    // the host's defaults should reactivate to active without a fresh approval prompt.
    String cap = registerApprovalRequiredCapability("tofu_react_" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();

    Response reg = registerDelegatedAgent(hostKey, agentKey, cap);
    String agentId = reg.jsonPath().getString("agent_id");
    String userCode = reg.jsonPath().getString("approval.user_code");

    String username = "tofu-react-" + suffix();
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

    // Force-expire so reactivate has work to do.
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .post("/agents/" + agentId + "/expire")
        .then()
        .statusCode(200);

    // Reactivate via host+jwt — cap is in host.default_capabilities, so even though the cap's
    // registry record still says requires_approval=true, the §5.3 host-defaults rule auto-grants.
    Response reactivate = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(Map.of("agent_id", agentId))
        .when()
        .post("/agent/reactivate");
    reactivate.then()
        .statusCode(200)
        .body("status", org.hamcrest.Matchers.equalTo("active"))
        .body("approval", org.hamcrest.Matchers.nullValue());
    List<Map<String, Object>> grants = reactivate.jsonPath()
        .getList("agent_capability_grants", (Class<Map<String, Object>>) (Class<?>) Map.class);
    assertThat(grants)
        .anySatisfy(g -> {
          assertThat(g.get("capability")).isEqualTo(cap);
          assertThat(g.get("status")).isEqualTo("active");
        });
  }

  // --- helpers ---

  private static String suffix() {
    return UUID.randomUUID().toString().replace("-", "").substring(0, 8);
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
              "name": "tofu-agent",
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
}
