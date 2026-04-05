package com.github.chh.keycloak.agentauth.support;

import static io.restassured.RestAssured.given;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.restassured.http.ContentType;

/**
 * Shared Keycloak container for all integration tests. Uses the singleton container pattern to
 * avoid starting a new Keycloak instance per test class.
 *
 * <p>
 * Extend this class in IT tests instead of declaring your own {@code @Container}.
 */
public abstract class BaseKeycloakIT {

  protected static final String REALM = "master";

  @SuppressWarnings("resource")
  protected static final KeycloakContainer KEYCLOAK = TestcontainersSupport.newKeycloakContainer();

  static {
    KEYCLOAK.start();
  }

  /** Base URL for realm-scoped requests, e.g. http://localhost:PORT/realms/master */
  protected static String realmUrl() {
    return KEYCLOAK.getAuthServerUrl() + "/realms/" + REALM;
  }

  /** The server issuer URL used as the 'aud' claim in host JWTs. */
  protected static String issuerUrl() {
    return realmUrl() + "/agent-auth";
  }

  /**
   * Base URL for admin extension requests, e.g.
   * http://localhost:PORT/admin/realms/master/agent-auth
   */
  protected static String adminApiUrl() {
    return KEYCLOAK.getAuthServerUrl() + "/admin/realms/" + REALM + "/agent-auth";
  }

  /** Fetches an admin access token for Keycloak's admin REST API. */
  protected static String adminAccessToken() {
    return given()
        .baseUri(realmUrl())
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
}
