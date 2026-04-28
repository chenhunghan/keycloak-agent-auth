package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import com.github.chh.keycloak.agentauth.support.BaseKeycloakIT;
import com.github.chh.keycloak.agentauth.support.TestJwts;
import com.github.chh.keycloak.agentauth.support.TestKeys;
import com.nimbusds.jose.jwk.OctetKeyPair;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.Test;

/**
 * Integration tests for admin-driven host pre-registration, the "Pre-registration" flow of Agent
 * Auth Protocol v1.0-draft §2.8 ("A user or administrator pre-registers the host through the
 * server's dashboard, admin API, or any other server-specific mechanism"). The spec leaves the
 * exact shape of this endpoint implementation-specific; this extension exposes it at {@code POST
 * /admin/realms/{realm}/agent-auth/hosts}.
 *
 * <p>
 * Contract exercised here:
 * <ul>
 * <li>Admin can create a host record with an inline Ed25519 JWK. Response status is 201; the
 * returned record carries {@code status="active"} and a {@code host_id} equal to the JWK's RFC 7638
 * thumbprint.</li>
 * <li>Missing / malformed key payloads are rejected with HTTP 400.</li>
 * <li>Pre-registering the same key twice returns HTTP 409 ({@code host_exists}).</li>
 * <li>Requests without a bearer admin token are rejected with HTTP 401.</li>
 * <li>Admin-set metadata (name, description) survives a later {@code /agent/register} under the
 * same host key.</li>
 * </ul>
 */
class AgentAuthAdminHostPreRegistrationIT extends BaseKeycloakIT {

  @Test
  void preRegisterHostReturnsActiveHostRecord() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    String expectedHostId = TestKeys.thumbprint(hostKey);

    // Wave 5 AAP-ADMIN-001: admin POST /hosts must supply user_id (or client_id) to come up
    // active. Without one of those, the host stages as `pending` and the first /verify/approve
    // links a user. Use defaultTestUserId so this test still asserts the active-pre-registered
    // shape end-to-end.
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "host_public_key": %s,
              "name": "cron-runner",
              "description": "Nightly batch host",
              "user_id": "%s"
            }
            """, hostKey.toPublicJWK().toJSONString(), defaultTestUserId()))
        .when()
        .post("/hosts")
        .then()
        .statusCode(201)
        .body("host_id", equalTo(expectedHostId))
        .body("status", equalTo("active"))
        .body("name", equalTo("cron-runner"))
        .body("description", equalTo("Nightly batch host"))
        .body("created_at", notNullValue())
        .body("public_key.kty", equalTo("OKP"))
        .body("public_key.crv", equalTo("Ed25519"));
  }

  @Test
  void preRegisterHostOmittingMetadataReturnsHostWithoutThoseFields() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();

    // AAP-ADMIN-001: omitting both user_id and client_id stages the host as pending — the
    // status assertion is updated accordingly. The metadata-absence assertions are unchanged.
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "host_public_key": %s
            }
            """, hostKey.toPublicJWK().toJSONString()))
        .when()
        .post("/hosts")
        .then()
        .statusCode(201)
        .body("status", equalTo("pending"))
        .body("name", nullValue())
        .body("description", nullValue());
  }

  @Test
  void preRegisterHostWithMissingPublicKeyReturns400() {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "no-key-host"
            }
            """)
        .when()
        .post("/hosts")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  @Test
  void preRegisterHostWithMalformedPublicKeyReturns400() {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body("""
            {
              "host_public_key": {
                "kty": "OKP"
              }
            }
            """)
        .when()
        .post("/hosts")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  @Test
  void preRegisterSameHostTwiceReturns409() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    String body = String.format("""
        {
          "host_public_key": %s
        }
        """, hostKey.toPublicJWK().toJSONString());

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(body)
        .when()
        .post("/hosts")
        .then()
        .statusCode(201);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(body)
        .when()
        .post("/hosts")
        .then()
        .statusCode(409)
        .body("error", equalTo("host_exists"));
  }

  @Test
  void preRegisterHostWithoutAuthReturns401() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();

    given()
        .baseUri(adminApiUrl())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "host_public_key": %s
            }
            """, hostKey.toPublicJWK().toJSONString()))
        .when()
        .post("/hosts")
        .then()
        .statusCode(401);
  }

  @Test
  void getPreRegisteredHostReturnsRecord() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    // Wave 5 AAP-ADMIN-001: supply user_id at admin POST so the host comes up active.
    String hostId = given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "host_public_key": %s,
              "name": "fetch-test",
              "user_id": "%s"
            }
            """, hostKey.toPublicJWK().toJSONString(), defaultTestUserId()))
        .when()
        .post("/hosts")
        .then()
        .statusCode(201)
        .extract()
        .path("host_id");

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/hosts/" + hostId)
        .then()
        .statusCode(200)
        .body("host_id", equalTo(hostId))
        .body("status", equalTo("active"))
        .body("name", equalTo("fetch-test"));
  }

  @Test
  void getUnknownHostReturns404() {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/hosts/unknown-host-id")
        .then()
        .statusCode(404)
        .body("error", equalTo("host_not_found"));
  }

  @Test
  void agentRegistrationForPreRegisteredHostPreservesAdminMetadata() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    // Wave 5 AAP-ADMIN-001: bind to user_id so the host comes up active and the autonomous-mode
    // agent registers active under the linked host (autonomous on a pending host fails the
    // host_pre_registration_required guard).
    String hostId = given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "host_public_key": %s,
              "name": "linked-service",
              "description": "Pre-approved service host",
              "user_id": "%s"
            }
            """, hostKey.toPublicJWK().toJSONString(), defaultTestUserId()))
        .when()
        .post("/hosts")
        .then()
        .statusCode(201)
        .extract()
        .path("host_id");

    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "test agent",
              "host_name": "linked-service",
              "capabilities": [],
              "mode": "autonomous",
              "reason": "test"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/hosts/" + hostId)
        .then()
        .statusCode(200)
        .body("name", equalTo("linked-service"))
        .body("description", equalTo("Pre-approved service host"))
        .body("status", equalTo("active"));
  }
}
