package com.github.chh.keycloak.agentauth.support;

import static io.restassured.RestAssured.given;

import com.nimbusds.jose.jwk.OctetKeyPair;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.restassured.http.ContentType;
import java.util.HashMap;
import java.util.List;
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

  /** Cached master-realm admin user id; see {@link #defaultTestUserId()}. */
  private static volatile String CACHED_ADMIN_USER_ID;

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
   * Resolves (and caches) the master-realm admin user id used as the default {@code user_id} when
   * pre-registering hosts. Mirrors {@code BaseKeycloakIT#defaultTestUserId} so the Postgres-backed
   * E2E suite plays by the same Wave-5 rules.
   */
  protected static String defaultTestUserId() {
    ensureStarted();
    String cached = CACHED_ADMIN_USER_ID;
    if (cached != null) {
      return cached;
    }
    synchronized (BasePostgresE2E.class) {
      if (CACHED_ADMIN_USER_ID != null) {
        return CACHED_ADMIN_USER_ID;
      }
      List<Map<String, Object>> matches = given()
          .baseUri(KEYCLOAK.getAuthServerUrl())
          .header("Authorization", "Bearer " + adminAccessToken())
          .queryParam("username", KEYCLOAK.getAdminUsername())
          .queryParam("exact", true)
          .when()
          .get("/admin/realms/" + ADMIN_REALM + "/users")
          .then()
          .statusCode(200)
          .extract()
          .as(new io.restassured.common.mapper.TypeRef<List<Map<String, Object>>>() {
          });
      if (matches == null || matches.isEmpty() || matches.get(0).get("id") == null) {
        throw new IllegalStateException(
            "Unable to resolve master-realm admin user id; got " + matches);
      }
      CACHED_ADMIN_USER_ID = (String) matches.get(0).get("id");
      return CACHED_ADMIN_USER_ID;
    }
  }

  /**
   * Pre-registers a host via the admin API (§2.8 path #2) so the host comes up {@code active}
   * immediately, bypassing the dynamic-register {@code pending} state introduced for §2.11.
   * Idempotent: returns silently if the host already exists (HTTP 409). Wave-5 requires
   * {@code user_id} (or {@code client_id}) to keep the host active; we default to the master-realm
   * admin user.
   */
  protected static void preRegisterHost(OctetKeyPair hostKey) {
    preRegisterHostForUser(hostKey, defaultTestUserId());
  }

  /**
   * Pre-registers a host bound to a specific {@code userId}. Idempotent on 409. Named distinctly
   * from the single-arg helper so subclasses with a private {@code preRegisterHost(OctetKeyPair,
   * String)} of their own (where the second arg is a host name) keep compiling.
   */
  protected static void preRegisterHostForUser(OctetKeyPair hostKey, String userId) {
    ensureStarted();
    Map<String, Object> jwk = new HashMap<>(hostKey.toPublicJWK().toJSONObject());
    Map<String, Object> body = new HashMap<>();
    body.put("host_public_key", jwk);
    if (userId != null && !userId.isBlank()) {
      body.put("user_id", userId);
    }
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(body)
        .when()
        .post("/hosts")
        .then()
        .statusCode(org.hamcrest.Matchers.anyOf(
            org.hamcrest.Matchers.equalTo(201),
            org.hamcrest.Matchers.equalTo(409)));
  }

  /**
   * Pre-registers a host without {@code user_id} or {@code client_id}, leaving it in
   * {@code pending} per Wave-5. Use only for tests that intentionally exercise the §2.11
   * admin-pending-host bootstrap.
   */
  protected static void preRegisterHostAsPending(OctetKeyPair hostKey) {
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
    CACHED_ADMIN_USER_ID = null;
  }
}
