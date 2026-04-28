package com.github.chh.keycloak.agentauth.support;

import static io.restassured.RestAssured.given;

import com.nimbusds.jose.jwk.OctetKeyPair;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Reusable HTTP helpers for CIBA-flow integration tests. Mirrors the inline helpers in
 * {@code AgentAuthCibaApprovalIT} but lifts them out so multiple ITs can share without copying. All
 * helpers take an explicit {@code authServerUrl} so they work against any container instance.
 */
public final class CibaTestHelpers {

  public static final String REALM = "agent-auth-test";
  public static final String ADMIN_REALM = "master";
  public static final String TEST_CLIENT_ID = "agent-auth-test-client";
  public static final String TEST_USER_PASSWORD = "testpass";

  private CibaTestHelpers() {
  }

  public static String adminApiUrl(String authServerUrl) {
    return authServerUrl + "/admin/realms/" + REALM + "/agent-auth";
  }

  public static String issuerUrl(String authServerUrl) {
    return authServerUrl + "/realms/" + REALM + "/agent-auth";
  }

  public static String adminAccessToken(String authServerUrl, String adminUser,
      String adminPassword) {
    return given()
        .baseUri(authServerUrl + "/realms/" + ADMIN_REALM)
        .contentType(ContentType.URLENC)
        .formParam("grant_type", "password")
        .formParam("client_id", "admin-cli")
        .formParam("username", adminUser)
        .formParam("password", adminPassword)
        .when()
        .post("/protocol/openid-connect/token")
        .then()
        .statusCode(200)
        .extract()
        .path("access_token");
  }

  /** Configure the realm's SMTP settings (best-effort, returns immediately). */
  public static void putRealmSmtp(String authServerUrl, String adminToken,
      Map<String, String> smtp) {
    given()
        .baseUri(authServerUrl)
        .header("Authorization", "Bearer " + adminToken)
        .contentType(ContentType.JSON)
        .body(Map.of("smtpServer", smtp))
        .when()
        .put("/admin/realms/" + REALM)
        .then()
        .statusCode(204);
  }

  /** Create a verified-email user; returns the new user_id. */
  public static String createTestUser(String authServerUrl, String adminToken, String username,
      String email) {
    Response resp = given()
        .baseUri(authServerUrl)
        .header("Authorization", "Bearer " + adminToken)
        .contentType(ContentType.JSON)
        .body(Map.of(
            "username", username,
            "enabled", true,
            "emailVerified", true,
            "email", email,
            "firstName", "Test",
            "lastName", "User",
            "requiredActions", List.of()))
        .when()
        .post("/admin/realms/" + REALM + "/users");
    resp.then().statusCode(201);
    String location = resp.getHeader("Location");
    String userId = location.substring(location.lastIndexOf('/') + 1);
    given()
        .baseUri(authServerUrl)
        .header("Authorization", "Bearer " + adminToken)
        .contentType(ContentType.JSON)
        .body(Map.of("type", "password", "value", TEST_USER_PASSWORD, "temporary", false))
        .when()
        .put("/admin/realms/" + REALM + "/users/" + userId + "/reset-password")
        .then()
        .statusCode(204);
    return userId;
  }

  public static String registerApprovalCap(String authServerUrl, String adminToken, String name) {
    given()
        .baseUri(adminApiUrl(authServerUrl))
        .header("Authorization", "Bearer " + adminToken)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "CIBA email E2E cap",
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

  public static void preRegisterHost(String authServerUrl, String adminToken, OctetKeyPair hostKey,
      String name) {
    preRegisterHost(authServerUrl, adminToken, hostKey, name, null);
  }

  /**
   * CIBA-flow variant of host pre-registration that lets the caller bind the host to a specific
   * {@code userId}. Wave-5 requires either {@code user_id} or {@code client_id} for the host to
   * land {@code active}; this overload is the test-side knob. Pass {@code null} to preserve the
   * original (now-{@code pending}) behavior — most CIBA tests follow up with
   * {@link #linkHost(String, String, String, String)} so leaving the host pending is fine, but
   * tests that expect an immediately-active host should pass the user id here.
   */
  public static void preRegisterHost(String authServerUrl, String adminToken, OctetKeyPair hostKey,
      String name, String userId) {
    Map<String, Object> body = new java.util.HashMap<>();
    body.put("host_public_key", hostKey.toPublicJWK().toJSONObject());
    body.put("name", name);
    if (userId != null && !userId.isBlank()) {
      body.put("user_id", userId);
    }
    given()
        .baseUri(adminApiUrl(authServerUrl))
        .header("Authorization", "Bearer " + adminToken)
        .contentType(ContentType.JSON)
        .body(body)
        .when()
        .post("/hosts")
        .then()
        .statusCode(201);
  }

  public static void linkHost(String authServerUrl, String adminToken, String hostId,
      String userId) {
    given()
        .baseUri(adminApiUrl(authServerUrl))
        .header("Authorization", "Bearer " + adminToken)
        .contentType(ContentType.JSON)
        .body(Map.of("user_id", userId))
        .when()
        .post("/hosts/" + hostId + "/link")
        .then()
        .statusCode(200);
  }

  public static String randomSuffix() {
    return UUID.randomUUID().toString().replace("-", "").substring(0, 8);
  }
}
