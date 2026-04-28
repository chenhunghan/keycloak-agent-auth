package com.github.chh.keycloak.agentauth.support;

import static io.restassured.RestAssured.given;

import com.nimbusds.jose.jwk.OctetKeyPair;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;

/**
 * Shared Keycloak container for all integration tests. Uses the singleton container pattern to
 * avoid starting a new Keycloak instance per test class.
 *
 * <p>
 * Extend this class in IT tests instead of declaring your own {@code @Container}.
 */
public abstract class BaseKeycloakIT {

  /** Dedicated, hermetic test realm imported on container startup. */
  protected static final String REALM = "agent-auth-test";

  /** Realm hosting the Keycloak admin user; used to mint admin tokens. */
  private static final String ADMIN_REALM = "master";

  /**
   * Cached resolution of the master-realm admin user id. The master admin is the only user
   * guaranteed to exist after realm import, so it doubles as the default {@code user_id} when
   * pre-registering a host that needs to come up active.
   */
  private static volatile String CACHED_ADMIN_USER_ID;

  @SuppressWarnings("resource")
  protected static KeycloakContainer KEYCLOAK;

  /** Base URL for realm-scoped requests, e.g. http://localhost:PORT/realms/agent-auth-test */
  protected static String realmUrl() {
    ensureStarted();
    return KEYCLOAK.getAuthServerUrl() + "/realms/" + REALM;
  }

  /** The server issuer URL used as the 'aud' claim in host JWTs. */
  protected static String issuerUrl() {
    return realmUrl() + "/agent-auth";
  }

  /**
   * Base URL for admin extension requests, e.g.
   * http://localhost:PORT/admin/realms/agent-auth-test/agent-auth
   */
  protected static String adminApiUrl() {
    ensureStarted();
    return KEYCLOAK.getAuthServerUrl() + "/admin/realms/" + REALM + "/agent-auth";
  }

  /**
   * Fetches an admin access token for Keycloak's admin REST API. The token is minted from the
   * {@code master} realm (where the admin user lives) regardless of the test realm, and is accepted
   * cross-realm because the admin role grants realm-admin on all realms.
   */
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
   * Resolves the master-realm admin user id (cached) by querying Keycloak's user search. Used as
   * the default {@code user_id} for {@link #preRegisterHost(OctetKeyPair)} so Wave-5's
   * "active-but-unowned host" guard is satisfied without the test having to provision its own user.
   * The lookup runs once per JVM.
   */
  protected static String defaultTestUserId() {
    ensureStarted();
    String cached = CACHED_ADMIN_USER_ID;
    if (cached != null) {
      return cached;
    }
    synchronized (BaseKeycloakIT.class) {
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
   * immediately, bypassing the dynamic-register pending state. Use in tests that don't care about
   * the §2.11 host-pending bootstrap (the common case — most ITs just want a working agent).
   *
   * <p>
   * The host's public JWK is sent inline; the master-realm admin user id is supplied as
   * {@code user_id} so Wave-5's gate (admin POST /hosts without {@code client_id} AND without
   * {@code user_id} now stages the host as {@code pending}) is satisfied — the host therefore comes
   * up active and pre-bound to a real user, matching pre-Wave-5 behavior. Idempotent: returns
   * silently if the host already exists (HTTP 409). Intended for {@code @BeforeAll} or per-test
   * setup.
   */
  protected static void preRegisterHost(OctetKeyPair hostKey) {
    preRegisterHostForUser(hostKey, defaultTestUserId());
  }

  /**
   * Pre-registers a host bound to a specific {@code userId}. Use when the test needs a host owned
   * by a freshly-provisioned realm user (CIBA flows, multi-user authz checks). Idempotent on 409.
   *
   * <p>
   * Named distinctly from the single-arg helper so subclasses that already define a private
   * {@code preRegisterHost(OctetKeyPair, String)} (e.g. {@code AgentAuthCibaApprovalIT}, where the
   * second arg is a host {@code name}) keep compiling. New tests should prefer this name.
   */
  protected static void preRegisterHostForUser(OctetKeyPair hostKey, String userId) {
    ensureStarted();
    Map<String, Object> jwk = new HashMap<>(hostKey.toPublicJWK().toJSONObject());
    Map<String, Object> body = new HashMap<>();
    body.put("host_public_key", jwk);
    if (userId != null && !userId.isBlank()) {
      body.put("user_id", userId);
    }
    Response resp = given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(body)
        .when()
        .post("/hosts");
    resp.then().statusCode(org.hamcrest.Matchers.anyOf(
        org.hamcrest.Matchers.equalTo(201),
        org.hamcrest.Matchers.equalTo(409)));
  }

  /**
   * Pre-registers a host without supplying {@code user_id} or {@code client_id}, so the host comes
   * up in {@code pending} state per Wave-5. Reserved for tests that intentionally exercise the
   * §2.11 admin-pending-host bootstrap (e.g. verifying the first /verify/approve flips it to
   * active). Most tests should prefer {@link #preRegisterHost(OctetKeyPair)} which yields an active
   * host.
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
    if (KEYCLOAK == null) {
      KEYCLOAK = TestcontainersSupport.newKeycloakContainer();
    }
    if (!KEYCLOAK.isRunning()) {
      KEYCLOAK.start();
    }
  }

  @AfterAll
  static synchronized void stopContainer() {
    if (KEYCLOAK != null) {
      KEYCLOAK.stop();
      KEYCLOAK = null;
    }
    CACHED_ADMIN_USER_ID = null;
  }
}
