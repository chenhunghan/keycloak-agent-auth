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
 * Integration tests for Host Linking per Agent Auth Protocol v1.0-draft §2.9, §2.10, §3.2.
 *
 * <p>
 * Linking is "implementation-specific" per §2.9, but the spec prescribes the <em>consequences</em>
 * of a link/unlink action via MUST language. These tests assert exactly those consequences:
 *
 * <ul>
 * <li>§2.9: a host MUST NOT be linked to more than one user — re-link to a different user is 409.
 * </li>
 * <li>§2.9: on unlink, the server MUST revoke all delegated agents under the host.</li>
 * <li>§2.10: on link, active autonomous agents MUST be claimed (status=claimed, grants revoked).
 * </li>
 * <li>§3.2: agent.user_id is "set from the host's user_id" — delegated agents inherit it.</li>
 * </ul>
 *
 * <p>
 * In this Keycloak extension, linking is exposed via the admin REST API at {@code POST
 * /admin/realms/{realm}/agent-auth/hosts/{hostId}/link} (body {@code {"user_id":
 * "<kc-user-uuid>"}}) and {@code DELETE ... /link} — chosen because §2.9 explicitly lists "admin
 * API" as one of the implementation-specific linking mechanisms.
 */
class AgentAuthHostLinkIT extends BaseKeycloakIT {

  @Test
  void linkHost_setsUserIdOnHostAndReturnsUpdatedHost() {
    String userId = createTestUser("link-basic-" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    registerDelegatedAgent(hostKey, agentKey, registerAutoCapability("linkbasic"));
    String hostId = TestKeys.thumbprint(hostKey);

    Response response = linkHostRaw(hostId, userId);
    response.then().statusCode(200);
    assertThat(response.jsonPath().getString("host_id")).isEqualTo(hostId);
    assertThat(response.jsonPath().getString("user_id")).isEqualTo(userId);
  }

  @Test
  void linkHost_propagatesUserIdToExistingDelegatedAgents() {
    // §3.2: agent.user_id is set from the host's user_id.
    String userId = createTestUser("link-delegated-" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String agentId = registerDelegatedAgent(hostKey, agentKey,
        registerAutoCapability("linkdeleg"));
    String hostId = TestKeys.thumbprint(hostKey);

    linkHostRaw(hostId, userId).then().statusCode(200);

    String propagated = agentStatusField(agentId, hostKey, "user_id");
    assertThat(propagated).as("delegated agent inherits host.user_id").isEqualTo(userId);
  }

  @Test
  @SuppressWarnings("unchecked")
  void linkHost_claimsAutonomousAgentsAndRevokesTheirGrants() {
    // §2.10: on link, each active autonomous agent MUST have status="claimed" and
    // its capabilities revoked.
    String userId = createTestUser("link-auto-" + suffix());
    String capability = registerAutoCapability("linkauto");
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String agentId = registerAutonomousAgent(hostKey, agentKey, capability);
    String hostId = TestKeys.thumbprint(hostKey);

    linkHostRaw(hostId, userId).then().statusCode(200);

    Map<String, Object> statusBody = agentStatusBody(agentId, hostKey);
    assertThat(statusBody.get("status"))
        .as("§2.10: autonomous agent must be claimed").isEqualTo("claimed");
    List<Map<String, Object>> grants = (List<Map<String, Object>>) statusBody
        .get("agent_capability_grants");
    assertThat(grants)
        .as("§2.10: all grants must be revoked on claim")
        .allSatisfy(g -> assertThat(g.get("status")).isEqualTo("revoked"));
  }

  @Test
  void linkHostAlreadyLinkedToDifferentUser_returns409() {
    // §2.9: "A host MUST NOT be linked to more than one user."
    String userA = createTestUser("link-conflict-a-" + suffix());
    String userB = createTestUser("link-conflict-b-" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    registerDelegatedAgent(hostKey, agentKey, registerAutoCapability("linkconflict"));
    String hostId = TestKeys.thumbprint(hostKey);

    linkHostRaw(hostId, userA).then().statusCode(200);
    linkHostRaw(hostId, userB).then().statusCode(409);
  }

  @Test
  void linkHostAlreadyLinkedToSameUser_isIdempotent() {
    String userId = createTestUser("link-idem-" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    registerDelegatedAgent(hostKey, agentKey, registerAutoCapability("linkidem"));
    String hostId = TestKeys.thumbprint(hostKey);

    linkHostRaw(hostId, userId).then().statusCode(200);
    linkHostRaw(hostId, userId).then().statusCode(200);
  }

  @Test
  void linkNonExistentHost_returns404() {
    String userId = createTestUser("link-no-host-" + suffix());
    linkHostRaw("this-thumbprint-does-not-exist", userId).then().statusCode(404);
  }

  @Test
  void linkNonExistentUser_returns404() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    registerDelegatedAgent(hostKey, agentKey, registerAutoCapability("linknouser"));
    String hostId = TestKeys.thumbprint(hostKey);

    linkHostRaw(hostId, UUID.randomUUID().toString()).then().statusCode(404);
  }

  @Test
  void unlinkHost_clearsUserIdAndRevokesDelegatedAgents() {
    // §2.9: on unlink, the server MUST revoke all delegated agents under the host.
    String userId = createTestUser("unlink-deleg-" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String agentId = registerDelegatedAgent(hostKey, agentKey,
        registerAutoCapability("unlinkdeleg"));
    String hostId = TestKeys.thumbprint(hostKey);

    linkHostRaw(hostId, userId).then().statusCode(200);
    unlinkHostRaw(hostId).then().statusCode(204);

    assertThat(agentStatusField(agentId, hostKey, "status"))
        .as("§2.9: delegated agent must be revoked on unlink").isEqualTo("revoked");
  }

  @Test
  void unlinkHost_leavesClaimedAutonomousAgentsAlone() {
    // §2.10: claimed is terminal. Unlink must not reanimate or further mutate claimed agents.
    String userId = createTestUser("unlink-auto-" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String agentId = registerAutonomousAgent(hostKey, agentKey,
        registerAutoCapability("unlinkauto"));
    String hostId = TestKeys.thumbprint(hostKey);

    linkHostRaw(hostId, userId).then().statusCode(200);
    assertThat(agentStatusField(agentId, hostKey, "status")).isEqualTo("claimed");
    unlinkHostRaw(hostId).then().statusCode(204);
    assertThat(agentStatusField(agentId, hostKey, "status"))
        .as("claimed agent must stay claimed after unlink").isEqualTo("claimed");
  }

  @Test
  void unlinkNotLinkedHost_returns204Idempotent() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    registerDelegatedAgent(hostKey, agentKey, registerAutoCapability("unlinkidem"));
    String hostId = TestKeys.thumbprint(hostKey);

    unlinkHostRaw(hostId).then().statusCode(204);
  }

  // --- helpers ---

  private static String suffix() {
    return UUID.randomUUID().toString().replace("-", "").substring(0, 8);
  }

  private static String createTestUser(String username) {
    String token = adminAccessToken(); // also triggers ensureStarted()
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

  private static String registerAutoCapability(String prefix) {
    String name = prefix + "_" + suffix();
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Auto-approved capability for link tests",
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

  private static String registerDelegatedAgent(OctetKeyPair hostKey, OctetKeyPair agentKey,
      String capability) {
    return registerAgent(hostKey, agentKey, capability, "delegated");
  }

  private static String registerAutonomousAgent(OctetKeyPair hostKey, OctetKeyPair agentKey,
      String capability) {
    return registerAgent(hostKey, agentKey, capability, "autonomous");
  }

  private static String registerAgent(OctetKeyPair hostKey, OctetKeyPair agentKey,
      String capability, String mode) {
    String jwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl());
    return given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + jwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "link-test agent",
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

  private static Response linkHostRaw(String hostId, String userId) {
    return given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of("user_id", userId))
        .when()
        .post("/hosts/{hostId}/link", hostId);
  }

  private static Response unlinkHostRaw(String hostId) {
    return given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .delete("/hosts/{hostId}/link", hostId);
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

  private static String agentStatusField(String agentId, OctetKeyPair hostKey, String field) {
    Object value = agentStatusBody(agentId, hostKey).get(field);
    return value == null ? null : value.toString();
  }
}
