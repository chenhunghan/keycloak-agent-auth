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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Phase 2 of the multi-tenant authz plan: layer-2 enforcement at approval time and at introspect
 * time.
 *
 * <p>
 * {@code /verify/approve} now refuses to flip a pending grant to {@code active} if the approving
 * user fails the cap's org/role gate — the grant goes to {@code denied} with
 * {@code reason=insufficient_authority}, mirroring the existing {@code user_denied} shape so
 * partial-approval semantics still hold.
 *
 * <p>
 * {@code /agent/introspect} now re-evaluates the gate against the agent's user on every call,
 * stripping grants whose cap the user no longer satisfies. Combined with the eager cascade planned
 * for Phase 4 on org-membership changes, this implements the hybrid cascade Q4 settled on (lazy on
 * roles, eager on orgs).
 */
class AgentAuthMultiTenantApprovalIT extends BaseKeycloakIT {

  private static final String USER_PASSWORD = "Password1!";

  private static String suffix;
  private static String acmeOrgId;
  private static String globexOrgId;
  private static String aliceUserId;
  private static String aliceUsername;

  private static String acmeCap;
  private static String globexCap;
  private static String roleGatedCap;
  private static String openCap;
  private static final String ROLE_NAME = "phase2_accountant";

  @BeforeAll
  static void setUp() {
    suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    aliceUsername = "alice-p2-" + suffix;
    aliceUserId = createTestUser(aliceUsername);

    acmeOrgId = createOrganization("acmep2-" + suffix);
    globexOrgId = createOrganization("globexp2-" + suffix);
    addUserToOrganization(acmeOrgId, aliceUserId);

    createRealmRole(ROLE_NAME);

    acmeCap = "phase2_acme_" + suffix;
    globexCap = "phase2_globex_" + suffix;
    roleGatedCap = "phase2_role_" + suffix;
    openCap = "phase2_open_" + suffix;
    registerCapability(acmeCap, "authenticated", true, acmeOrgId, null);
    registerCapability(globexCap, "authenticated", true, globexOrgId, null);
    registerCapability(roleGatedCap, "authenticated", true, null, ROLE_NAME);
    registerCapability(openCap, "authenticated", true, null, null);
  }

  @Test
  void approveSplitsGrantsByLayer2Gate() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    Response regResp = registerDelegatedAgent(hostKey, agentKey,
        List.of(acmeCap, globexCap, openCap));
    String userCode = regResp.jsonPath().getString("approval.user_code");

    String accessToken = realmUserAccessToken(aliceUsername);

    Response approveResp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + accessToken)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", userCode))
        .when()
        .post("/verify/approve");
    approveResp.then().statusCode(200);

    List<Map<String, Object>> grants = approveResp.jsonPath()
        .getList("agent_capability_grants");
    Map<String, String> statusByCap = new java.util.HashMap<>();
    Map<String, String> reasonByCap = new java.util.HashMap<>();
    for (Map<String, Object> g : grants) {
      statusByCap.put((String) g.get("capability"), (String) g.get("status"));
      reasonByCap.put((String) g.get("capability"), (String) g.get("reason"));
    }
    assertThat(statusByCap).containsEntry(acmeCap, "active");
    assertThat(statusByCap).containsEntry(openCap, "active");
    assertThat(statusByCap).containsEntry(globexCap, "denied");
    assertThat(reasonByCap).containsEntry(globexCap, "insufficient_authority");
  }

  @Test
  void approveDeniesRoleGatedCapWhenUserLacksRole() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    Response regResp = registerDelegatedAgent(hostKey, agentKey,
        List.of(roleGatedCap, openCap));
    String userCode = regResp.jsonPath().getString("approval.user_code");

    String accessToken = realmUserAccessToken(aliceUsername);

    Response approveResp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + accessToken)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", userCode))
        .when()
        .post("/verify/approve");
    approveResp.then().statusCode(200);

    List<Map<String, Object>> grants = approveResp.jsonPath()
        .getList("agent_capability_grants");
    Map<String, String> statusByCap = new java.util.HashMap<>();
    Map<String, String> reasonByCap = new java.util.HashMap<>();
    for (Map<String, Object> g : grants) {
      statusByCap.put((String) g.get("capability"), (String) g.get("status"));
      reasonByCap.put((String) g.get("capability"), (String) g.get("reason"));
    }
    assertThat(statusByCap).containsEntry(openCap, "active");
    assertThat(statusByCap).containsEntry(roleGatedCap, "denied");
    assertThat(reasonByCap).containsEntry(roleGatedCap, "insufficient_authority");
  }

  @Test
  void introspectStripsGrantWhenCapGetsOrgGateAfterApproval() {
    // Approve a grant for an open (gateless) cap, then mutate the cap to add an org gate the
    // user doesn't satisfy. Grant stays in storage (revocation is the cascade's job, Phase 4),
    // but introspect filters it from the response.
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();

    String mutableCap = "phase2_mutable_" + suffix;
    registerCapability(mutableCap, "authenticated", true, null, null);

    Response regResp = registerDelegatedAgent(hostKey, agentKey, List.of(mutableCap));
    String agentId = regResp.jsonPath().getString("agent_id");
    String userCode = regResp.jsonPath().getString("approval.user_code");

    String accessToken = realmUserAccessToken(aliceUsername);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + accessToken)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", userCode))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(200);

    // §4.3: agent+jwt aud MUST be the resolved location URL. The cap registered above declares
    // location = https://resource.example.test/<name>.
    String mutableCapLocation = "https://resource.example.test/" + mutableCap;

    // First introspect: grant is visible (gate passes — cap has no org/role).
    Response introBefore = introspect(
        TestJwts.agentJwt(hostKey, agentKey, agentId, mutableCapLocation));
    introBefore.then().statusCode(200).body("active", org.hamcrest.Matchers.equalTo(true));
    List<Map<String, Object>> grantsBefore = introBefore.jsonPath()
        .getList("agent_capability_grants");
    assertThat(grantsBefore).extracting(g -> g.get("capability"))
        .contains(mutableCap);

    // Mutate the cap: add organization_id=globexOrgId. Alice is in Acme, not Globex.
    updateCapability(mutableCap, "authenticated", true, globexOrgId, null);

    // Second introspect: aud check happens before the entitlement re-eval, so the token's aud
    // still matches the cap's location and we reach the grant-filter step that strips the cap.
    // Generate a fresh JWT — the previous one's jti is consumed by the replay guard.
    Response introAfter = introspect(
        TestJwts.agentJwt(hostKey, agentKey, agentId, mutableCapLocation));
    introAfter.then().statusCode(200).body("active", org.hamcrest.Matchers.equalTo(true));
    List<Map<String, Object>> grantsAfter = introAfter.jsonPath()
        .getList("agent_capability_grants");
    assertThat(grantsAfter).extracting(g -> g.get("capability"))
        .doesNotContain(mutableCap);
  }

  // --- helpers ---

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

  private static String createOrganization(String alias) {
    String token = adminAccessToken();
    Response resp = given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of(
            "name", alias,
            "alias", alias,
            "domains", List.of(Map.of("name", alias + ".test"))))
        .when()
        .post("/admin/realms/" + REALM + "/organizations");
    resp.then().statusCode(201);
    String location = resp.getHeader("Location");
    return location.substring(location.lastIndexOf('/') + 1);
  }

  private static void addUserToOrganization(String orgId, String userId) {
    String token = adminAccessToken();
    given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(userId)
        .when()
        .post("/admin/realms/" + REALM + "/organizations/" + orgId + "/members")
        .then()
        .statusCode(org.hamcrest.Matchers.anyOf(
            org.hamcrest.Matchers.equalTo(201),
            org.hamcrest.Matchers.equalTo(204)));
  }

  private static void createRealmRole(String roleName) {
    String token = adminAccessToken();
    given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("name", roleName))
        .when()
        .post("/admin/realms/" + REALM + "/roles")
        .then()
        .statusCode(org.hamcrest.Matchers.anyOf(
            org.hamcrest.Matchers.equalTo(201),
            org.hamcrest.Matchers.equalTo(409)));
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

  private static void registerCapability(
      String name, String visibility, boolean requiresApproval,
      String organizationId, String requiredRole) {
    StringBuilder body = new StringBuilder();
    body.append("{")
        .append("\"name\":\"").append(name).append("\",")
        .append("\"description\":\"Phase 2 multi-tenant approval test cap\",")
        .append("\"visibility\":\"").append(visibility).append("\",")
        .append("\"requires_approval\":").append(requiresApproval).append(",")
        .append("\"location\":\"https://resource.example.test/").append(name).append("\",")
        .append("\"input\":{\"type\":\"object\"},")
        .append("\"output\":{\"type\":\"object\"}");
    if (organizationId != null) {
      body.append(",\"organization_id\":\"").append(organizationId).append("\"");
    }
    if (requiredRole != null) {
      body.append(",\"required_role\":\"").append(requiredRole).append("\"");
    }
    body.append("}");
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(body.toString())
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);
  }

  private static void updateCapability(
      String name, String visibility, boolean requiresApproval,
      String organizationId, String requiredRole) {
    StringBuilder body = new StringBuilder();
    body.append("{")
        .append("\"name\":\"").append(name).append("\",")
        .append("\"description\":\"Phase 2 multi-tenant approval test cap (mutated)\",")
        .append("\"visibility\":\"").append(visibility).append("\",")
        .append("\"requires_approval\":").append(requiresApproval).append(",")
        .append("\"location\":\"https://resource.example.test/").append(name).append("\",")
        .append("\"input\":{\"type\":\"object\"},")
        .append("\"output\":{\"type\":\"object\"}");
    if (organizationId != null) {
      body.append(",\"organization_id\":\"").append(organizationId).append("\"");
    }
    if (requiredRole != null) {
      body.append(",\"required_role\":\"").append(requiredRole).append("\"");
    }
    body.append("}");
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(body.toString())
        .when()
        .put("/capabilities/" + name)
        .then()
        .statusCode(200);
  }

  private static Response registerDelegatedAgent(
      OctetKeyPair hostKey, OctetKeyPair agentKey, List<String> capabilities) {
    String regJwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl());
    String capsArray = capabilities.stream()
        .map(c -> "\"" + c + "\"")
        .collect(java.util.stream.Collectors.joining(","));
    return given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Phase 2 approval test agent",
              "host_name": "p2-host",
              "capabilities": [%s],
              "mode": "delegated",
              "reason": "Phase 2 approval test"
            }
            """, capsArray))
        .when()
        .post("/agent/register");
  }

  private static Response introspect(String agentJwt) {
    return given()
        .baseUri(issuerUrl())
        .contentType(ContentType.JSON)
        .body(Map.of("token", agentJwt))
        .when()
        .post("/agent/introspect");
  }
}
