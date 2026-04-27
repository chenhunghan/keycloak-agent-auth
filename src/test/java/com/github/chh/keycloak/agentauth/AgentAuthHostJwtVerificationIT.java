package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

import com.github.chh.keycloak.agentauth.support.BaseKeycloakIT;
import com.github.chh.keycloak.agentauth.support.TestJwts;
import com.github.chh.keycloak.agentauth.support.TestKeys;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.sun.net.httpserver.HttpServer;
import io.restassured.http.ContentType;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.util.JsonSerialization;
import org.testcontainers.Testcontainers;

/**
 * Spec-compliance regression coverage for §4.5.1 (Host JWT verification) and §5.9 (Rotate Host Key)
 * lifecycle endpoints.
 *
 * <p>
 * Two bugs covered:
 * <ul>
 * <li>Bug 1: {@code POST /host/rotate-key} previously created a host record on the fly when the
 * caller's host JWT didn't match any stored host — letting a self-signed host JWT materialize an
 * active host. The fix guards the endpoint with a {@code host_not_found} 404 + an "active state
 * required" check, and rejects rotated/retired thumbprints.</li>
 * <li>Bug 2: All six lifecycle endpoints hand-rolled host JWT verification with inline
 * {@code host_public_key} only — JWKS-served hosts (§4.2) couldn't authenticate after registration.
 * The fix routes all six endpoints through {@code HostJwtVerifier}, which falls back to
 * {@code host_jwks_url} per §4.5.1.</li>
 * </ul>
 */
class AgentAuthHostJwtVerificationIT extends BaseKeycloakIT {

  private static OctetKeyPair jwksHostKey;
  private static OctetKeyPair jwksAgentKey;
  private static String jwksKid;
  private static String jwksUrl;
  private static HttpServer jwksServer;
  private static String capabilityName;

  @BeforeAll
  static void setup() throws Exception {
    jwksHostKey = TestKeys.generateEd25519();
    jwksAgentKey = TestKeys.generateEd25519();
    jwksKid = "host-verifier-kid-" + UUID.randomUUID();
    jwksServer = startJwksServer(jwksHostKey, jwksKid);
    Testcontainers.exposeHostPorts(jwksServer.getAddress().getPort());
    jwksUrl = "http://host.testcontainers.internal:"
        + jwksServer.getAddress().getPort() + "/jwks";

    String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    capabilityName = "hostjwt_verify_cap_" + suffix;
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Host-JWT verifier IT capability",
              "visibility": "authenticated",
              "requires_approval": false,
              "location": "https://resource.example.test/hostjwt/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, capabilityName, capabilityName))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);
  }

  @AfterAll
  static void teardown() {
    if (jwksServer != null) {
      jwksServer.stop(0);
    }
  }

  private static HttpServer startJwksServer(OctetKeyPair key, String kid) throws Exception {
    Map<String, Object> jwk = new HashMap<>(key.toPublicJWK().toJSONObject());
    jwk.put("kid", kid);
    jwk.put("alg", "EdDSA");
    jwk.put("use", "sig");
    byte[] body = JsonSerialization.writeValueAsString(Map.of("keys", List.of(jwk)))
        .getBytes(StandardCharsets.UTF_8);

    HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", 0), 0);
    server.createContext("/jwks", exchange -> {
      exchange.getResponseHeaders().add("Content-Type", "application/json");
      exchange.getResponseHeaders().add("Cache-Control", "max-age=60, public");
      exchange.sendResponseHeaders(200, body.length);
      exchange.getResponseBody().write(body);
      exchange.close();
    });
    server.start();
    return server;
  }

  /**
   * Bug 1: a self-signed host JWT for a host that has never registered must NOT materialize an
   * active host record on {@code POST /host/rotate-key}. The endpoint must respond with
   * {@code 404 host_not_found}, and the storage row for the JWT's iss must remain absent.
   */
  @Test
  void rotateHostKeyForUnknownHostDoesNotCreateRecord() {
    OctetKeyPair unknownHostKey = TestKeys.generateEd25519();
    OctetKeyPair newKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwt(unknownHostKey, issuerUrl());
    String unknownHostId = TestKeys.thumbprint(unknownHostKey);

    // Sanity: the host is NOT in storage before the rotate-key call.
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/hosts/" + unknownHostId)
        .then()
        .statusCode(404);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "public_key": %s
            }
            """, newKey.toPublicJWK().toJSONString()))
        .when()
        .post("/host/rotate-key")
        .then()
        .statusCode(404)
        .body("error", equalTo("host_not_found"));

    // Confirm via admin API that no host record was materialized at the unknown thumbprint.
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/hosts/" + unknownHostId)
        .then()
        .statusCode(404);
  }

  /**
   * Bug 1: a stale/rotated host thumbprint cannot be used to rotate again. After a successful
   * rotation (active host → newKey), a JWT signed by the OLD key must be rejected. The endpoint
   * also records the old host_id as rotated, so even a JWT signed by yet-another key but bearing
   * the rotated iss would 401.
   */
  @Test
  void rotateHostKeyRejectsAlreadyRotatedThumbprint() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair midKey = TestKeys.generateEd25519();
    preRegisterHost(hostKey);

    String firstRotateJwt = TestJwts.hostJwt(hostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + firstRotateJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "public_key": %s
            }
            """, midKey.toPublicJWK().toJSONString()))
        .when()
        .post("/host/rotate-key")
        .then()
        .statusCode(200);

    String stalePostRotateJwt = TestJwts.hostJwt(hostKey, issuerUrl());
    OctetKeyPair newKey = TestKeys.generateEd25519();
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + stalePostRotateJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "public_key": %s
            }
            """, newKey.toPublicJWK().toJSONString()))
        .when()
        .post("/host/rotate-key")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_jwt"));
  }

  /**
   * Bug 1: a host that is not yet active (pending dynamic-registration state) cannot rotate its
   * key. The endpoint must respond with {@code 409 invalid_state}.
   */
  @Test
  void rotateHostKeyRejectsPendingHost() {
    OctetKeyPair pendingHostKey = TestKeys.generateEd25519();
    OctetKeyPair pendingAgentKey = TestKeys.generateEd25519();

    // Register an agent through the dynamic-registration path so the host is created pending.
    String regJwt = TestJwts.hostJwtForRegistration(pendingHostKey, pendingAgentKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Pending Host Rotate Agent",
              "host_name": "pending-rotate",
              "capabilities": ["%s"],
              "mode": "delegated"
            }
            """, capabilityName))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200);

    OctetKeyPair newKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwt(pendingHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "public_key": %s
            }
            """, newKey.toPublicJWK().toJSONString()))
        .when()
        .post("/host/rotate-key")
        .then()
        .statusCode(409)
        .body("error", equalTo("invalid_state"));
  }

  /**
   * Bug 2: {@code GET /agent/status} accepts a JWKS-based host JWT (no inline
   * {@code host_public_key} claim). Pre-fix, the endpoint required the inline claim and rejected
   * any JWKS-only host with a hard 401 even when the host record carried a {@code host_jwks_url}.
   */
  @Test
  void agentStatusAcceptsJwksOnlyHostJwt() {
    // Bootstrap: register an agent through the dynamic-registration path with host_jwks_url —
    // this lands a pending host in storage with the URL persisted. We then admin-link the host
    // to a known user via the admin API and admin-approve to flip the agent + host to active so
    // /agent/status can return the agent record.
    String regJwt = TestJwts.hostJwtForRegistrationWithHostJwksUrl(
        jwksHostKey, jwksAgentKey, jwksUrl, jwksKid, issuerUrl());
    String agentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "JWKS Verifier Agent",
              "host_name": "jwks-verifier",
              "capabilities": ["%s"],
              "mode": "delegated"
            }
            """, capabilityName))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    String hostId = TestKeys.thumbprint(jwksHostKey);
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of("user_id", findFirstUserId()))
        .when()
        .post("/hosts/" + hostId + "/link")
        .then()
        .statusCode(200);

    // Admin approve the cap → triggers §2.8/§2.11 host activation cascade.
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .post("/agents/" + agentId + "/capabilities/" + capabilityName + "/approve")
        .then()
        .statusCode(200);

    String jwksHostJwt = TestJwts.hostJwtWithHostJwksUrl(jwksHostKey, jwksUrl, jwksKid,
        issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + jwksHostJwt)
        .queryParam("agent_id", agentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(200)
        .body("agent_id", equalTo(agentId))
        .body("host_id", equalTo(hostId))
        .body("status", equalTo("active"));
  }

  /**
   * Bug 2: a host that registered with {@code host_jwks_url} can revoke an agent through
   * {@code POST /agent/revoke} using a JWKS-only host JWT.
   */
  @Test
  void agentRevokeAcceptsJwksOnlyHostJwt() {
    OctetKeyPair localHostKey = TestKeys.generateEd25519();
    OctetKeyPair localAgentKey = TestKeys.generateEd25519();
    String localKid = "host-revoke-kid-" + UUID.randomUUID();

    HttpServer localJwks;
    try {
      localJwks = startJwksServer(localHostKey, localKid);
    } catch (Exception e) {
      throw new AssertionError("Failed to spin up local JWKS server", e);
    }
    try {
      Testcontainers.exposeHostPorts(localJwks.getAddress().getPort());
      String localUrl = "http://host.testcontainers.internal:"
          + localJwks.getAddress().getPort() + "/jwks";

      String regJwt = TestJwts.hostJwtForRegistrationWithHostJwksUrl(
          localHostKey, localAgentKey, localUrl, localKid, issuerUrl());
      String agentId = given()
          .baseUri(issuerUrl())
          .header("Authorization", "Bearer " + regJwt)
          .contentType(ContentType.JSON)
          .body(String.format("""
              {
                "name": "JWKS Revoke Agent",
                "host_name": "jwks-revoke",
                "capabilities": ["%s"],
                "mode": "delegated"
              }
              """, capabilityName))
          .when()
          .post("/agent/register")
          .then()
          .statusCode(200)
          .extract()
          .path("agent_id");

      String hostId = TestKeys.thumbprint(localHostKey);
      given()
          .baseUri(adminApiUrl())
          .header("Authorization", "Bearer " + adminAccessToken())
          .contentType(ContentType.JSON)
          .body(Map.of("user_id", findFirstUserId()))
          .when()
          .post("/hosts/" + hostId + "/link")
          .then()
          .statusCode(200);

      given()
          .baseUri(adminApiUrl())
          .header("Authorization", "Bearer " + adminAccessToken())
          .when()
          .post("/agents/" + agentId + "/capabilities/" + capabilityName + "/approve")
          .then()
          .statusCode(200);

      String revokeJwt = TestJwts.hostJwtWithHostJwksUrl(localHostKey, localUrl, localKid,
          issuerUrl());
      given()
          .baseUri(issuerUrl())
          .header("Authorization", "Bearer " + revokeJwt)
          .contentType(ContentType.JSON)
          .body(String.format("""
              {
                "agent_id": "%s"
              }
              """, agentId))
          .when()
          .post("/agent/revoke")
          .then()
          .statusCode(200)
          .body("status", equalTo("revoked"));
    } finally {
      localJwks.stop(0);
    }
  }

  /** Find any user id from the realm so we can link a host. Defensive against empty realms. */
  private static String findFirstUserId() {
    Object id = given()
        .baseUri(KEYCLOAK.getAuthServerUrl() + "/admin/realms/" + REALM)
        .header("Authorization", "Bearer " + adminAccessToken())
        .queryParam("first", 0)
        .queryParam("max", 1)
        .when()
        .get("/users")
        .then()
        .statusCode(200)
        .extract()
        .path("[0].id");
    if (id == null) {
      // Create one on-demand so the test is hermetic.
      String newUsername = "hostjwt-test-user-" + UUID.randomUUID();
      String location = given()
          .baseUri(KEYCLOAK.getAuthServerUrl() + "/admin/realms/" + REALM)
          .header("Authorization", "Bearer " + adminAccessToken())
          .contentType(ContentType.JSON)
          .body(Map.of("username", newUsername, "enabled", true))
          .when()
          .post("/users")
          .then()
          .statusCode(201)
          .extract()
          .header("Location");
      return location.substring(location.lastIndexOf('/') + 1);
    }
    return id.toString();
  }
}
