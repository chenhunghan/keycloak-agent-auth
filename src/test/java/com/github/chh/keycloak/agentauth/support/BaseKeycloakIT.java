package com.github.chh.keycloak.agentauth.support;

import static io.restassured.RestAssured.given;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.restassured.http.ContentType;
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
  }
}
