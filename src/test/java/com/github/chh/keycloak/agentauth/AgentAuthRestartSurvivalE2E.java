package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;

import com.github.chh.keycloak.agentauth.support.PostgresSupport;
import com.github.chh.keycloak.agentauth.support.TestJwts;
import com.github.chh.keycloak.agentauth.support.TestKeys;
import com.nimbusds.jose.jwk.OctetKeyPair;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.restassured.http.ContentType;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.Network;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * End-to-end test that Keycloak can be stopped and started again against the same Postgres without
 * losing Agent Auth state — the property that the InMemoryRegistry could never satisfy and that the
 * JPA migration is entirely for.
 *
 * <p>
 * Flow: start KC #1 → register capability + agent (pending, delegated) → admin approve → stop KC #1
 * → start KC #2 pointing at the same Postgres volume → verify agent and grant survived with
 * status=active → revoke → stop KC #2 → start KC #3 → verify revocation survived.
 */
class AgentAuthRestartSurvivalE2E {

  private static final String REALM = "agent-auth-test";
  private static final String ADMIN_REALM = "master";

  private static Network network;
  private static PostgreSQLContainer postgres;

  @BeforeAll
  static void startPostgres() {
    network = Network.newNetwork();
    postgres = PostgresSupport.newPostgres(network);
    postgres.start();
  }

  @AfterAll
  static void stopPostgres() {
    if (postgres != null) {
      postgres.stop();
      postgres = null;
    }
    if (network != null) {
      network.close();
      network = null;
    }
  }

  @Test
  void agentStateSurvivesKeycloakRestart() {
    String capability = "survival_cap_" + UUID.randomUUID().toString().replace("-", "").substring(0,
        8);
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String agentId;

    // --- KC #1: register + approve ---
    try (KeycloakContainer kc = startKeycloak()) {
      registerCapability(kc, capability);
      // AAP-ADMIN-001: admin grant approval on a delegated agent now requires the host be linked
      // to a realm user. Pre-register the host bound to the master-realm admin so the dynamic
      // /agent/register call below registers under a linked host and the subsequent admin
      // approve succeeds. The dynamic-register path stays the same; only the host-bootstrap
      // step changes.
      preRegisterHostToAdmin(kc, hostKey);
      agentId = registerAgent(kc, hostKey, agentKey, capability);
      assertThat(statusOf(kc, agentId, hostKey))
          .as("before approve").isEqualTo("pending");
      approveCapability(kc, agentId, capability);
      assertThat(statusOf(kc, agentId, hostKey))
          .as("after approve, before restart").isEqualTo("active");
    }

    // --- KC #2: verify state persisted ---
    try (KeycloakContainer kc = startKeycloak()) {
      assertThat(statusOf(kc, agentId, hostKey))
          .as("status survived first restart").isEqualTo("active");
      introspect(kc, hostKey, agentKey, agentId)
          .statusCode(200)
          .body("active", equalTo(true))
          .body("agent_id", equalTo(agentId));
      revoke(kc, hostKey, agentId);
    }

    // --- KC #3: verify revocation persisted ---
    try (KeycloakContainer kc = startKeycloak()) {
      assertThat(statusOf(kc, agentId, hostKey))
          .as("revocation survived second restart").isEqualTo("revoked");
      introspect(kc, hostKey, agentKey, agentId)
          .statusCode(200)
          .body("active", equalTo(false));
    }
  }

  private static KeycloakContainer startKeycloak() {
    KeycloakContainer kc = PostgresSupport.newKeycloakOnPostgres(network);
    kc.start();
    return kc;
  }

  // --- HTTP helpers (mirroring those in AgentAuthFullJourneyE2E but parameterised on container)
  // ---

  private static String issuerUrl(KeycloakContainer kc) {
    return kc.getAuthServerUrl() + "/realms/" + REALM + "/agent-auth";
  }

  private static String adminApiUrl(KeycloakContainer kc) {
    return kc.getAuthServerUrl() + "/admin/realms/" + REALM + "/agent-auth";
  }

  private static String adminAccessToken(KeycloakContainer kc) {
    String adminTokenUrl = kc.getAuthServerUrl() + "/realms/" + ADMIN_REALM;
    return given()
        .baseUri(adminTokenUrl)
        .contentType(ContentType.URLENC)
        .formParam("grant_type", "password")
        .formParam("client_id", "admin-cli")
        .formParam("username", kc.getAdminUsername())
        .formParam("password", kc.getAdminPassword())
        .when()
        .post("/protocol/openid-connect/token")
        .then()
        .statusCode(200)
        .extract()
        .path("access_token");
  }

  private static void registerCapability(KeycloakContainer kc, String name) {
    given()
        .baseUri(adminApiUrl(kc))
        .header("Authorization", "Bearer " + adminAccessToken(kc))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Restart-survival capability",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "http://127.0.0.1:1/execute",
              "input": { "type": "object" },
              "output": { "type": "object" }
            }
            """, name))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);
  }

  /**
   * AAP-ADMIN-001: pre-bind the host to the master admin user before dynamic registration so the
   * subsequent admin grant approval has an owning user to gate against. Mirrors what
   * {@code BaseKeycloakIT#preRegisterHost} does for the testcontainers-managed harness; replicated
   * here because this E2E starts/stops its own Keycloak container per phase and can't extend the
   * shared base class.
   */
  @SuppressWarnings("unchecked")
  private static void preRegisterHostToAdmin(KeycloakContainer kc, OctetKeyPair hostKey) {
    String token = adminAccessToken(kc);
    java.util.List<java.util.Map<String, Object>> matches = given()
        .baseUri(kc.getAuthServerUrl())
        .header("Authorization", "Bearer " + token)
        .queryParam("username", kc.getAdminUsername())
        .queryParam("exact", true)
        .when()
        .get("/admin/realms/" + ADMIN_REALM + "/users")
        .then()
        .statusCode(200)
        .extract()
        .as(new io.restassured.common.mapper.TypeRef<java.util.List<java.util.Map<String, Object>>>() {
        });
    String userId = (String) matches.get(0).get("id");
    java.util.Map<String, Object> body = new java.util.HashMap<>();
    body.put("host_public_key", hostKey.toPublicJWK().toJSONObject());
    body.put("user_id", userId);
    given()
        .baseUri(adminApiUrl(kc))
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(body)
        .when()
        .post("/hosts")
        .then()
        // Idempotent: 201 fresh, 409 if container restart re-runs against persisted Postgres.
        .statusCode(org.hamcrest.Matchers.anyOf(
            org.hamcrest.Matchers.equalTo(201),
            org.hamcrest.Matchers.equalTo(409)));
  }

  private static String registerAgent(KeycloakContainer kc, OctetKeyPair hostKey,
      OctetKeyPair agentKey, String capability) {
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl(kc));
    return given()
        .baseUri(issuerUrl(kc))
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Survival agent",
              "host_name": "survival-host",
              "capabilities": ["%s"],
              "mode": "delegated"
            }
            """, capability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");
  }

  private static String statusOf(KeycloakContainer kc, String agentId, OctetKeyPair hostKey) {
    return given()
        .baseUri(issuerUrl(kc))
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl(kc)))
        .queryParam("agent_id", agentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(200)
        .extract()
        .path("status");
  }

  private static void approveCapability(KeycloakContainer kc, String agentId, String capability) {
    given()
        .baseUri(adminApiUrl(kc))
        .header("Authorization", "Bearer " + adminAccessToken(kc))
        .when()
        .post("/agents/" + agentId + "/capabilities/" + capability + "/approve")
        .then()
        .statusCode(200);
  }

  private static io.restassured.response.ValidatableResponse introspect(KeycloakContainer kc,
      OctetKeyPair hostKey, OctetKeyPair agentKey, String agentId) {
    // §4.3: agent+jwt aud MUST be the resolved location URL — the cap registered above declares
    // location = http://127.0.0.1:1/execute (no real backend; introspect doesn't proxy).
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, "http://127.0.0.1:1/execute");
    return given()
        .baseUri(issuerUrl(kc))
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl(kc)))
        .contentType(ContentType.JSON)
        .body(String.format("""
            { "token": "%s" }
            """, agentJwt))
        .when()
        .post("/agent/introspect")
        .then();
  }

  private static void revoke(KeycloakContainer kc, OctetKeyPair hostKey, String agentId) {
    given()
        .baseUri(issuerUrl(kc))
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl(kc)))
        .contentType(ContentType.JSON)
        .body(String.format("""
            { "agent_id": "%s" }
            """, agentId))
        .when()
        .post("/agent/revoke")
        .then()
        .statusCode(200);
  }
}
