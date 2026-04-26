package com.github.chh.keycloak.agentauth.support;

import static io.restassured.RestAssured.given;

import com.nimbusds.jose.jwk.OctetKeyPair;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.restassured.http.ContentType;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.testcontainers.containers.Network;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Base class for E2E tests that need a Postgres-backed Keycloak. Each test class gets its own
 * Postgres + Keycloak pair (surefire/failsafe run classes in separate forks).
 */
public abstract class BasePostgresE2E {

  protected static final String REALM = "agent-auth-test";
  private static final String ADMIN_REALM = "master";

  protected static Network NETWORK;
  protected static PostgreSQLContainer POSTGRES;
  @SuppressWarnings("resource")
  protected static KeycloakContainer KEYCLOAK;

  protected static String realmUrl() {
    ensureStarted();
    return KEYCLOAK.getAuthServerUrl() + "/realms/" + REALM;
  }

  protected static String issuerUrl() {
    return realmUrl() + "/agent-auth";
  }

  protected static String adminApiUrl() {
    ensureStarted();
    return KEYCLOAK.getAuthServerUrl() + "/admin/realms/" + REALM + "/agent-auth";
  }

  protected static String adminAccessToken() {
    ensureStarted();
    String adminTokenUrl = KEYCLOAK.getAuthServerUrl() + "/realms/" + ADMIN_REALM;
    return given()
        .baseUri(adminTokenUrl)
        .contentType(ContentType.URLENC)
        .formParam("grant_type", "password")
        .formParam("client_id", "admin-cli")
        .formParam("username", KEYCLOAK.getAdminUsername())
        .formParam("password", KEYCLOAK.getAdminPassword())
        .when()
        .post("/protocol/openid-connect/token")
        .then()
        .statusCode(200)
        .extract()
        .path("access_token");
  }

  /**
   * Pre-registers a host via the admin API (§2.8 path #2) so the host comes up {@code active}
   * immediately, bypassing the dynamic-register {@code pending} state introduced for §2.11.
   * Idempotent: returns silently if the host already exists (HTTP 409).
   */
  protected static void preRegisterHost(OctetKeyPair hostKey) {
    ensureStarted();
    Map<String, Object> jwk = new HashMap<>(hostKey.toPublicJWK().toJSONObject());
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of("host_public_key", jwk))
        .when()
        .post("/hosts")
        .then()
        .statusCode(org.hamcrest.Matchers.anyOf(
            org.hamcrest.Matchers.equalTo(201),
            org.hamcrest.Matchers.equalTo(409)));
  }

  private static synchronized void ensureStarted() {
    if (NETWORK == null) {
      NETWORK = Network.newNetwork();
    }
    if (POSTGRES == null) {
      POSTGRES = PostgresSupport.newPostgres(NETWORK);
      POSTGRES.start();
    }
    if (KEYCLOAK == null) {
      KEYCLOAK = PostgresSupport.newKeycloakOnPostgres(NETWORK);
    }
    if (!KEYCLOAK.isRunning()) {
      KEYCLOAK.start();
    }
  }

  @AfterAll
  static synchronized void stopAll() {
    if (KEYCLOAK != null) {
      KEYCLOAK.stop();
      KEYCLOAK = null;
    }
    if (POSTGRES != null) {
      POSTGRES.stop();
      POSTGRES = null;
    }
    if (NETWORK != null) {
      NETWORK.close();
      NETWORK = null;
    }
  }
}
