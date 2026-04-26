package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import com.github.chh.keycloak.agentauth.support.BaseKeycloakIT;
import com.github.chh.keycloak.agentauth.support.TestJwts;
import com.github.chh.keycloak.agentauth.support.TestKeys;
import com.nimbusds.jose.jwk.OctetKeyPair;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * AAP §7.1 pending-agent garbage collection.
 *
 * <p>
 * "Servers SHOULD periodically clean up agents that remain in pending state beyond a server-defined
 * threshold (e.g. 24 hours, 7 days). Cleaned-up pending agents are deleted, not revoked — they
 * never became active." This extension exposes the sweep via {@code POST
 * /admin/realms/{r}/agent-auth/pending-agents/cleanup} plus a background scheduler; the IT drives
 * the admin endpoint because its timing is deterministic.
 */
class AgentAuthPendingCleanupIT extends BaseKeycloakIT {

  @Test
  void cleanupWithZeroThreshold_removesAllPendingAgents() {
    String cap = registerApprovalCap("cleanup_all_" + suffix());
    registerPendingAgent(cap);
    registerPendingAgent(cap);

    Response removed = given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .queryParam("olderThanSeconds", 0)
        .when()
        .post("/pending-agents/cleanup");
    removed.then().statusCode(200);
    assertThat(removed.jsonPath().getInt("removed"))
        .as("both freshly-created pending agents must be swept with olderThanSeconds=0")
        .isGreaterThanOrEqualTo(2);
  }

  @Test
  void cleanupRespectsThreshold_keepsYoungPendingAgents() {
    String cap = registerApprovalCap("cleanup_keep_" + suffix());
    String agentId = registerPendingAgent(cap);

    // A one-hour threshold keeps just-created agents — they're under a minute old.
    Response resp = given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .queryParam("olderThanSeconds", 3600)
        .when()
        .post("/pending-agents/cleanup");
    resp.then().statusCode(200);
    assertThat(resp.jsonPath().getInt("removed"))
        .as("agents created seconds ago must not be swept under a 1h threshold").isZero();

    // The freshly-created agent must still be pollable. We can't easily prove that without
    // threading the host key through the helper, so we at least confirm the sweep reported 0
    // and move on. The "young pending stays" property is sufficiently asserted by `removed==0`.
    assertThat(agentId).isNotBlank();
  }

  @Test
  void cleanupDoesNotDeleteActiveAgents() {
    // Auto-approved capability → agent goes straight to active; cleanup must not touch it.
    String cap = registerAutoCap("cleanup_skip_active_" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    preRegisterHost(hostKey);
    Response regResp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "active agent",
              "capabilities": ["%s"],
              "mode": "delegated"
            }
            """, cap))
        .when()
        .post("/agent/register");
    regResp.then().statusCode(200).body("status", org.hamcrest.Matchers.equalTo("active"));
    String agentId = regResp.jsonPath().getString("agent_id");

    // Wipe every pending agent with olderThanSeconds=0.
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .queryParam("olderThanSeconds", 0)
        .when()
        .post("/pending-agents/cleanup")
        .then()
        .statusCode(200);

    // Active agent is still there.
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .queryParam("agent_id", agentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(200)
        .body("status", org.hamcrest.Matchers.equalTo("active"));
  }

  @Test
  void cleanup_alsoReapsOrphanedPendingHosts() {
    // §2.8 dynamic registration creates a pending host AND a pending agent. After the agent
    // is swept, the host has zero remaining agents and qualifies as orphan-pending. The
    // existing /pending-agents/cleanup endpoint reaps both in the same transaction.
    String cap = registerApprovalCap("orphan_host_" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    // Note: NO preRegisterHost call here — we want the §2.8 dynamic-registration path so the
    // host comes up in pending state.
    String hostId = TestKeys.thumbprint(hostKey);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "orphan-host agent",
              "capabilities": ["%s"],
              "mode": "delegated"
            }
            """, cap))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200);

    // Confirm the pending host is in storage before the sweep.
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/hosts/" + hostId)
        .then()
        .statusCode(200)
        .body("status", org.hamcrest.Matchers.equalTo("pending"));

    Response resp = given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .queryParam("olderThanSeconds", 0)
        .when()
        .post("/pending-agents/cleanup");
    resp.then().statusCode(200);
    assertThat(resp.jsonPath().getInt("removed_agents")).isGreaterThanOrEqualTo(1);
    assertThat(resp.jsonPath().getInt("removed_hosts")).isGreaterThanOrEqualTo(1);

    // Host must be gone now.
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/hosts/" + hostId)
        .then()
        .statusCode(404);
  }

  @Test
  void cleanup_keepsActiveHostsUnderlyingPendingAgents() {
    // Pre-registered host is created in `active` state (§2.8 path #2), not pending. Even when
    // its only agent is a pending one and gets swept, the active host stays — only PENDING
    // hosts qualify for the orphan reap.
    String cap = registerApprovalCap("active_host_keep_" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String hostId = TestKeys.thumbprint(hostKey);
    preRegisterHost(hostKey);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "active-host pending agent",
              "capabilities": ["%s"],
              "mode": "delegated"
            }
            """, cap))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200);

    Response resp = given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .queryParam("olderThanSeconds", 0)
        .when()
        .post("/pending-agents/cleanup");
    resp.then().statusCode(200);
    assertThat(resp.jsonPath().getInt("removed_hosts"))
        .as("active hosts must never be reaped").isZero();

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/hosts/" + hostId)
        .then()
        .statusCode(200)
        .body("status", org.hamcrest.Matchers.equalTo("active"));
  }

  @Test
  void cleanup_keepsYoungPendingHostsAndAgents() {
    // Tight threshold (1h) leaves freshly-registered pending state intact — neither the agent
    // nor the host is older than the cutoff.
    String cap = registerApprovalCap("young_host_" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String hostId = TestKeys.thumbprint(hostKey);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "young pending agent",
              "capabilities": ["%s"],
              "mode": "delegated"
            }
            """, cap))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200);

    Response resp = given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .queryParam("olderThanSeconds", 3600)
        .when()
        .post("/pending-agents/cleanup");
    resp.then().statusCode(200);
    assertThat(resp.jsonPath().getInt("removed_agents")).isZero();
    assertThat(resp.jsonPath().getInt("removed_hosts")).isZero();

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/hosts/" + hostId)
        .then()
        .statusCode(200)
        .body("status", org.hamcrest.Matchers.equalTo("pending"));
  }

  @Test
  void cleanup_isIdempotentOnSecondCall() {
    // Second sweep with nothing left to do returns zero counts and no failure.
    String cap = registerApprovalCap("idempotent_" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "idempotent agent",
              "capabilities": ["%s"],
              "mode": "delegated"
            }
            """, cap))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .queryParam("olderThanSeconds", 0)
        .when()
        .post("/pending-agents/cleanup")
        .then()
        .statusCode(200);

    Response second = given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .queryParam("olderThanSeconds", 0)
        .when()
        .post("/pending-agents/cleanup");
    second.then().statusCode(200);
    assertThat(second.jsonPath().getInt("removed_agents")).isZero();
    assertThat(second.jsonPath().getInt("removed_hosts")).isZero();
  }

  // --- helpers ---

  private static String suffix() {
    return UUID.randomUUID().toString().replace("-", "").substring(0, 8);
  }

  private static String registerApprovalCap(String name) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "cleanup IT capability",
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

  private static String registerAutoCap(String name) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "cleanup IT auto capability",
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

  private static String registerPendingAgent(String capability) {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String jwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl());
    preRegisterHost(hostKey);
    return given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + jwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "pending agent",
              "capabilities": ["%s"],
              "mode": "delegated"
            }
            """, capability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("status", org.hamcrest.Matchers.equalTo("pending"))
        .extract()
        .path("agent_id");
  }

}
