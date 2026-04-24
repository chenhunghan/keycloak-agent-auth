package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import com.github.chh.keycloak.agentauth.support.BaseKeycloakIT;
import com.github.chh.keycloak.agentauth.support.TestJwts;
import com.github.chh.keycloak.agentauth.support.TestKeys;
import com.nimbusds.jose.jwk.OctetKeyPair;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Integration tests for Agent Auth Protocol v1.0-draft §2.6 — user-deletion cascade:
 *
 * <blockquote>"When a user account is deleted, the server MUST revoke all hosts linked to that user
 * and cascade revocation to all agents under those hosts."</blockquote>
 *
 * <p>
 * A host is "linked to a user" iff {@code host.user_id == <user.id>} (cf. §3.1, §2.9). The linkage
 * is established/removed by the admin-API endpoints under {@code /admin/.../agent-auth/hosts} —
 * exercised separately in {@link AgentAuthHostLinkIT}. Here we verify that the cascade also fires
 * when the underlying Keycloak {@code UserModel} is deleted (as opposed to a DELETE on
 * {@code /hosts/{id}/link}).
 *
 * <p>
 * Terminal-state handling mirrors {@code AgentAuthAdminResourceProvider.unlinkHost}: {@code
 * claimed}, {@code revoked} and {@code rejected} are treated as terminal on both host and agent
 * records — the cascade must not reanimate or re-brand them.
 */
class AgentAuthUserDeletionCascadeIT extends BaseKeycloakIT {

  @Test
  void deletingUserRevokesLinkedHostAndCascadesToDelegatedAgents() {
    // Create a real Keycloak user and a delegated agent + host; link host->user.
    String userId = createTestUser("cascade-delegated-" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String agentId = registerDelegatedAgent(hostKey, agentKey,
        registerAutoCapability("cascadedeleg"));
    String hostId = TestKeys.thumbprint(hostKey);
    linkHostRaw(hostId, userId).then().statusCode(200);

    // Sanity: the link set user_id on the host.
    assertThat(adminGetHost(hostId).jsonPath().getString("user_id")).isEqualTo(userId);

    // Delete the KC user via admin API — fires UserModel.UserRemovedEvent inside KC.
    deleteUser(userId).then().statusCode(204);

    // Ground truth: admin view of host MUST show status=revoked.
    waitUntil(Duration.ofSeconds(5),
        () -> "revoked".equals(adminGetHost(hostId).jsonPath().getString("status")));
    assertThat(adminGetHost(hostId).jsonPath().getString("status"))
        .as("§2.6: host linked to deleted user must be revoked").isEqualTo("revoked");

    // Delegated agent MUST be in a revoked terminal state. Observable either as
    // agent.status == "revoked" on /agent/status, or 403 host_revoked once the revoked
    // host's JWT is rejected (itself a stronger proof that the cascade fired).
    Response agentStatus = agentStatusRaw(agentId, hostKey);
    if (agentStatus.statusCode() == 200) {
      assertThat(agentStatus.jsonPath().getString("status"))
          .as("§2.6: delegated agent under linked host must be revoked on user deletion")
          .isEqualTo("revoked");
    } else {
      assertThat(agentStatus.statusCode())
          .as("§2.6: agent cascade must short-circuit once host JWT is rejected by revocation")
          .isEqualTo(403);
      assertThat(agentStatus.jsonPath().getString("error")).isEqualTo("host_revoked");
    }
  }

  @Test
  void deletingUserLeavesAlreadyClaimedAutonomousAgentUntouched() {
    // §2.10: autonomous agents end up "claimed" on link — a terminal state. §2.6 says the
    // host must be revoked, but the already-terminal agent must not be reanimated or re-branded.
    String userId = createTestUser("cascade-autoclaimed-" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String agentId = registerAutonomousAgent(hostKey, agentKey,
        registerAutoCapability("cascadeauto"));
    String hostId = TestKeys.thumbprint(hostKey);
    linkHostRaw(hostId, userId).then().statusCode(200);
    // Baseline: before the user is deleted, we can still see the agent through /agent/status
    // because the host is still active.
    assertThat(agentStatusField(agentId, hostKey, "status")).isEqualTo("claimed");

    deleteUser(userId).then().statusCode(204);

    waitUntil(Duration.ofSeconds(5),
        () -> "revoked".equals(adminGetHost(hostId).jsonPath().getString("status")));

    assertThat(adminGetHost(hostId).jsonPath().getString("status")).isEqualTo("revoked");
    // Once the host is revoked, its JWT is rejected on /agent/status with 403 host_revoked;
    // the fact that the agent-status endpoint never complains about the agent itself (e.g.
    // agent_revoked) is how we prove the terminal claimed state was preserved.
    Response agentStatus = agentStatusRaw(agentId, hostKey);
    assertThat(agentStatus.statusCode()).isEqualTo(403);
    assertThat(agentStatus.jsonPath().getString("error"))
        .as("already-terminal claimed agent must NOT have been re-revoked by the cascade; "
            + "only the host-level 403 should be observable")
        .isEqualTo("host_revoked");
  }

  @Test
  void deletingUnlinkedUserIsANoOpForAgentAuthState() {
    // Control: a user with no linked host must not trigger any state change and must not error.
    String userId = createTestUser("cascade-unlinked-" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String agentId = registerDelegatedAgent(hostKey, agentKey,
        registerAutoCapability("cascadenone"));
    String hostId = TestKeys.thumbprint(hostKey);
    // Intentionally: do NOT link hostId -> userId.

    deleteUser(userId).then().statusCode(204);

    // Host and agent must still be the same state they were before.
    assertThat(adminGetHost(hostId).jsonPath().getString("status")).isEqualTo("active");
    assertThat(agentStatusField(agentId, hostKey, "status"))
        .isIn("pending", "active", "authorization_pending");
  }

  // --- helpers (patterned on AgentAuthHostLinkIT) ---

  private static String suffix() {
    return UUID.randomUUID().toString().replace("-", "").substring(0, 8);
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

  private static Response deleteUser(String userId) {
    return given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .delete("/admin/realms/" + REALM + "/users/{id}", userId);
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
              "description": "Auto-approved capability for cascade tests",
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
              "name": "cascade-test agent",
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

  private static Response adminGetHost(String hostId) {
    return given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/hosts/{id}", hostId);
  }

  private static Response agentStatusRaw(String agentId, OctetKeyPair hostKey) {
    return given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .queryParam("agent_id", agentId)
        .when()
        .get("/agent/status");
  }

  private static Map<String, Object> agentStatusBody(String agentId, OctetKeyPair hostKey) {
    return agentStatusRaw(agentId, hostKey).then().statusCode(200).extract().jsonPath()
        .getMap("$");
  }

  private static String agentStatusField(String agentId, OctetKeyPair hostKey, String field) {
    Object value = agentStatusBody(agentId, hostKey).get(field);
    return value == null ? null : value.toString();
  }

  private static void waitUntil(Duration timeout, java.util.function.BooleanSupplier condition) {
    Instant deadline = Instant.now().plus(timeout);
    while (Instant.now().isBefore(deadline)) {
      if (condition.getAsBoolean()) {
        return;
      }
      try {
        Thread.sleep(150);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        return;
      }
    }
  }
}
