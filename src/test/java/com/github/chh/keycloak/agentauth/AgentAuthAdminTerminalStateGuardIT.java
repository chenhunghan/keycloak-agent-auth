package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

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
 * Integration tests asserting that the admin force-expire and force-reject endpoints preserve
 * terminal agent states. Per Agent Auth Protocol v1.0-draft §§2.3, 2.6, 2.10:
 *
 * <ul>
 * <li>{@code revoked} and {@code rejected} are terminal — cannot be reactivated.</li>
 * <li>{@code claimed} is terminal — a previously-autonomous agent linked to a user.</li>
 * </ul>
 *
 * <p>
 * Without these guards, an admin could overwrite a terminal state with {@code expired} and then use
 * {@code POST /agent/reactivate} to revive the agent — bypassing revocation/rejection entirely.
 */
class AgentAuthAdminTerminalStateGuardIT extends BaseKeycloakIT {

  // -------------------- expire guards --------------------

  @Test
  void forceExpire_onRevokedAgent_returns409_andStateIsPreserved() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String capability = registerAutoCapability("expguard_revoked");
    String agentId = registerDelegatedAgent(hostKey, agentKey, capability);

    // Drive the agent to revoked via the host-facing /agent/revoke endpoint.
    String hostJwt = TestJwts.hostJwt(hostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(Map.of("agent_id", agentId))
        .when()
        .post("/agent/revoke")
        .then()
        .statusCode(200)
        .body("status", equalTo("revoked"));

    forceExpireRaw(agentId).then()
        .statusCode(409)
        .body("error", equalTo("invalid_state"));

    assertAdminAgentStatus(agentId, "revoked");
  }

  @Test
  void forceExpire_onRejectedAgent_returns409_andStateIsPreserved() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String capability = registerApprovalCapability("expguard_rejected");
    String agentId = registerPendingAgent(hostKey, agentKey, capability);

    // Reject from pending — the legitimate, sanctioned reject path.
    forceRejectRaw(agentId).then()
        .statusCode(200)
        .body("status", equalTo("rejected"));

    forceExpireRaw(agentId).then()
        .statusCode(409)
        .body("error", equalTo("invalid_state"));

    assertAdminAgentStatus(agentId, "rejected");
  }

  @Test
  void forceExpire_onClaimedAgent_returns409_andStateIsPreserved() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String capability = registerAutoCapability("expguard_claimed");
    String agentId = registerAutonomousAgent(hostKey, agentKey, capability);
    String hostId = TestKeys.thumbprint(hostKey);

    String userId = createTestUser("expguard-claimed-" + suffix());
    linkHostRaw(hostId, userId).then().statusCode(200);
    assertAdminAgentStatus(agentId, "claimed");

    forceExpireRaw(agentId).then()
        .statusCode(409)
        .body("error", equalTo("invalid_state"));

    assertAdminAgentStatus(agentId, "claimed");
  }

  // -------------------- reject guards --------------------

  @Test
  void forceReject_onActiveAgent_returns409_andStateIsPreserved() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String capability = registerAutoCapability("rejguard_active");
    String agentId = registerDelegatedAgent(hostKey, agentKey, capability);
    assertAdminAgentStatus(agentId, "active");

    forceRejectRaw(agentId).then()
        .statusCode(409)
        .body("error", equalTo("invalid_state"));

    assertAdminAgentStatus(agentId, "active");
  }

  @Test
  void forceReject_onRevokedAgent_returns409_andStateIsPreserved() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String capability = registerAutoCapability("rejguard_revoked");
    String agentId = registerDelegatedAgent(hostKey, agentKey, capability);

    String hostJwt = TestJwts.hostJwt(hostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(Map.of("agent_id", agentId))
        .when()
        .post("/agent/revoke")
        .then()
        .statusCode(200);

    forceRejectRaw(agentId).then()
        .statusCode(409)
        .body("error", equalTo("invalid_state"));

    assertAdminAgentStatus(agentId, "revoked");
  }

  // -------------------- regression: legitimate happy paths still work --------------------

  @Test
  void forceExpire_onActiveAgent_stillSucceeds() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String capability = registerAutoCapability("regress_expire_active");
    String agentId = registerDelegatedAgent(hostKey, agentKey, capability);

    forceExpireRaw(agentId).then()
        .statusCode(200)
        .body("status", equalTo("expired"));
  }

  @Test
  void forceReject_onPendingAgent_stillSucceeds() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String capability = registerApprovalCapability("regress_reject_pending");
    String agentId = registerPendingAgent(hostKey, agentKey, capability);

    forceRejectRaw(agentId).then()
        .statusCode(200)
        .body("status", equalTo("rejected"));
  }

  // -------------------- helpers --------------------

  private static String suffix() {
    return UUID.randomUUID().toString().replace("-", "").substring(0, 8);
  }

  private static String registerAutoCapability(String prefix) {
    String name = prefix + "_" + suffix();
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Auto-approved capability for terminal-state guard tests",
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

  private static String registerApprovalCapability(String prefix) {
    String name = prefix + "_" + suffix();
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Approval-required capability for terminal-state guard tests",
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

  private static String registerDelegatedAgent(OctetKeyPair hostKey, OctetKeyPair agentKey,
      String capability) {
    return registerAgent(hostKey, agentKey, capability, "delegated");
  }

  private static String registerAutonomousAgent(OctetKeyPair hostKey, OctetKeyPair agentKey,
      String capability) {
    return registerAgent(hostKey, agentKey, capability, "autonomous");
  }

  private static String registerPendingAgent(OctetKeyPair hostKey, OctetKeyPair agentKey,
      String capability) {
    return registerAgent(hostKey, agentKey, capability, "delegated");
  }

  private static String registerAgent(OctetKeyPair hostKey, OctetKeyPair agentKey,
      String capability, String mode) {
    String jwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl());
    preRegisterHost(hostKey);
    return given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + jwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "terminal-state-guard agent",
              "capabilities": ["%s"],
              "mode": "%s"
            }
            """, capability, mode))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");
  }

  private static Response forceExpireRaw(String agentId) {
    return given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body("{}")
        .when()
        .post("/agents/" + agentId + "/expire");
  }

  private static Response forceRejectRaw(String agentId) {
    return given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body("{}")
        .when()
        .post("/agents/" + agentId + "/reject");
  }

  private static Response linkHostRaw(String hostId, String userId) {
    return given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of("user_id", userId))
        .when()
        .post("/hosts/{hostId}/link", hostId);
  }

  private static String createTestUser(String username) {
    String token = adminAccessToken();
    Response resp = given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("username", username, "enabled", true))
        .when()
        .post("/admin/realms/" + REALM + "/users");
    resp.then().statusCode(201);
    String location = resp.getHeader("Location");
    return location.substring(location.lastIndexOf('/') + 1);
  }

  private static void assertAdminAgentStatus(String agentId, String expectedStatus) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/agents/" + agentId)
        .then()
        .statusCode(200)
        .body("status", equalTo(expectedStatus));
  }
}
