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

  /**
   * §5.3 + §5.4: {@code /agent/request-capability} MUST follow the same auto-approval rule as
   * {@code /agent/register} when the requested cap is in {@code host.default_capabilities}. Without
   * this, the same agent + same cap returns {@code active} via /register but {@code pending} via
   * /request-capability — a semantic inconsistency between sibling endpoints. Audit 02 P2.
   */
  @Test
  @SuppressWarnings("unchecked")
  void requestCapability_autoApprovesWhenCapInHostDefaults() {
    String cap = registerApprovalRequiredCapability("tofu_req_active_" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair firstAgentKey = TestKeys.generateEd25519();

    // 1. First register: pending grant + device-auth approval seeded.
    Response firstReg = registerDelegatedAgent(hostKey, firstAgentKey, cap);
    String userCode = firstReg.jsonPath().getString("approval.user_code");

    // 2. User approves → cap is now in host.default_capabilities.
    String username = "tofu-req-" + suffix();
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

    // 3. Register a second agent under the same host, this time with an empty cap list — the agent
    // is active but has no grants yet, so /agent/request-capability has work to do.
    OctetKeyPair secondAgentKey = TestKeys.generateEd25519();
    String secondReg = given()
        .baseUri(issuerUrl())
        .header("Authorization",
            "Bearer " + TestJwts.hostJwtForRegistration(hostKey, secondAgentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "tofu-req-agent",
              "capabilities": [],
              "mode": "delegated"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("status", org.hamcrest.Matchers.equalTo("active"))
        .extract()
        .path("agent_id");

    // 4. Now /agent/request-capability for that approval-required cap. Because the host already
    // has it in defaults, the response MUST be active (not pending) and MUST omit the approval
    // object. This mirrors registration's path under the same conditions.
    Response reqResp = given()
        .baseUri(issuerUrl())
        .header("Authorization",
            "Bearer " + TestJwts.agentJwt(hostKey, secondAgentKey, secondReg, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"]
            }
            """, cap))
        .when()
        .post("/agent/request-capability");
    reqResp.then()
        .statusCode(200)
        .body("approval", org.hamcrest.Matchers.nullValue())
        .body("agent_capability_grants", org.hamcrest.Matchers.hasSize(1))
        .body("agent_capability_grants[0].capability", org.hamcrest.Matchers.equalTo(cap))
        .body("agent_capability_grants[0].status", org.hamcrest.Matchers.equalTo("active"));
  }

  /**
   * Regression coverage: when the requested cap is NOT in the host's defaults, /request-capability
   * keeps the existing pending-with-approval behavior. Pairs with
   * {@link #requestCapability_autoApprovesWhenCapInHostDefaults()} to bracket the host-defaults
   * branch.
   */
  @Test
  @SuppressWarnings("unchecked")
  void requestCapability_pendingWhenCapNotInHostDefaults() {
    // Cap A seeds the host's defaults via the first approval; cap B is requested fresh and should
    // remain pending because B was never approved on this host.
    String capA = registerApprovalRequiredCapability("tofu_req_seed_" + suffix());
    String capB = registerApprovalRequiredCapability("tofu_req_other_" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair firstAgentKey = TestKeys.generateEd25519();

    Response firstReg = registerDelegatedAgent(hostKey, firstAgentKey, capA);
    String userCode = firstReg.jsonPath().getString("approval.user_code");

    String username = "tofu-req-other-" + suffix();
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

    // Second agent under the same host, register with empty caps (active immediately).
    OctetKeyPair secondAgentKey = TestKeys.generateEd25519();
    String secondAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization",
            "Bearer " + TestJwts.hostJwtForRegistration(hostKey, secondAgentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "tofu-req-other-agent",
              "capabilities": [],
              "mode": "delegated"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    // Request cap B — not in host defaults → pending + approval object emitted.
    Response reqResp = given()
        .baseUri(issuerUrl())
        .header("Authorization",
            "Bearer " + TestJwts.agentJwt(hostKey, secondAgentKey, secondAgentId, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"]
            }
            """, capB))
        .when()
        .post("/agent/request-capability");
    // Once the host is linked (after the first approval seeded host.user_id) the approval flow
    // switches from device-auth to CIBA, so there's no user_code — assert on `method` instead,
    // which is set on every approval object regardless of channel.
    reqResp.then()
        .statusCode(200)
        .body("approval", org.hamcrest.Matchers.notNullValue())
        .body("approval.method", org.hamcrest.Matchers.notNullValue())
        .body("agent_capability_grants[0].capability", org.hamcrest.Matchers.equalTo(capB))
        .body("agent_capability_grants[0].status", org.hamcrest.Matchers.equalTo("pending"));
  }

  /**
   * Mixed request: one cap in host.defaults, one not. The defaulted cap MUST come back active, the
   * non-defaulted one MUST come back pending with an approval object — same per-grant decision as
   * registration.
   */
  @Test
  @SuppressWarnings("unchecked")
  void requestCapability_mixedHostDefaultsReturnsPerGrantStatus() {
    String defaultedCap = registerApprovalRequiredCapability("tofu_req_mix_def_" + suffix());
    String pendingCap = registerApprovalRequiredCapability("tofu_req_mix_pend_" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair firstAgentKey = TestKeys.generateEd25519();

    Response firstReg = registerDelegatedAgent(hostKey, firstAgentKey, defaultedCap);
    String userCode = firstReg.jsonPath().getString("approval.user_code");

    String username = "tofu-req-mix-" + suffix();
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

    OctetKeyPair secondAgentKey = TestKeys.generateEd25519();
    String secondAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization",
            "Bearer " + TestJwts.hostJwtForRegistration(hostKey, secondAgentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "tofu-req-mix-agent",
              "capabilities": [],
              "mode": "delegated"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    Response reqResp = given()
        .baseUri(issuerUrl())
        .header("Authorization",
            "Bearer " + TestJwts.agentJwt(hostKey, secondAgentKey, secondAgentId, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s", "%s"]
            }
            """, defaultedCap, pendingCap))
        .when()
        .post("/agent/request-capability");
    reqResp.then()
        .statusCode(200)
        .body("approval", org.hamcrest.Matchers.notNullValue())
        .body("agent_capability_grants", org.hamcrest.Matchers.hasSize(2));

    List<Map<String, Object>> grants = reqResp.jsonPath()
        .getList("agent_capability_grants", (Class<Map<String, Object>>) (Class<?>) Map.class);
    assertThat(grants)
        .anySatisfy(g -> {
          assertThat(g.get("capability")).isEqualTo(defaultedCap);
          assertThat(g.get("status")).isEqualTo("active");
        })
        .anySatisfy(g -> {
          assertThat(g.get("capability")).isEqualTo(pendingCap);
          assertThat(g.get("status")).isEqualTo("pending");
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
