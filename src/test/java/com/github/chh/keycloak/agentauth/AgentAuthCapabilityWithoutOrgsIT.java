package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;

import com.github.chh.keycloak.agentauth.support.BaseKeycloakIT;
import com.github.chh.keycloak.agentauth.support.TestJwts;
import com.github.chh.keycloak.agentauth.support.TestKeys;
import com.nimbusds.jose.jwk.OctetKeyPair;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Phase 1 robustness check: the extension must keep working when KC's Organizations feature is
 * disabled at the realm level. Capabilities without {@code organization_id} continue to work
 * normally; capabilities with {@code organization_id} become invisible to all callers (fail-safe —
 * the gate fails because no user has any orgs).
 *
 * <p>
 * This IT class disables orgs on the test realm in {@code @BeforeAll}. Each {@link BaseKeycloakIT}
 * subclass gets its own Keycloak container (the {@code @AfterAll} stops it and the next class
 * restarts), so flipping the realm flag here doesn't pollute other suites.
 *
 * <p>
 * Server-level feature-off (where {@code session.getProvider(OrganizationProvider.class)} itself
 * may return null or throw) is covered by the defensive try/catch in
 * {@code AgentAuthRealmResourceProvider.loadUserEntitlement}. Exercising that path end-to-end would
 * require a separate testcontainer started without {@code --features=organization}, which isn't
 * worth the lift for what is paranoia-defense code.
 */
class AgentAuthCapabilityWithoutOrgsIT extends BaseKeycloakIT {

  private static String suffix;
  private static String userId;
  private static String nullGateCap;
  private static String orgGatedCap;
  private static String publicCap;
  private static OctetKeyPair hostKey;
  private static OctetKeyPair agentKey;
  private static String agentId;

  @BeforeAll
  static void setUp() {
    suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    nullGateCap = "phase1_nofeat_nullgate_" + suffix;
    orgGatedCap = "phase1_nofeat_orggated_" + suffix;
    publicCap = "phase1_nofeat_public_" + suffix;

    // Phase 1 of setup: while orgs are still enabled, create a real org and bind the org-gated
    // cap through the org-scoped endpoint. AAP-ADMIN-005 closed the realm-POST `organization_id`
    // body field, so this is the only path to a persisted org-tagged cap row. The test then
    // disables orgs to assert visibility behaviour — the cap row outlives the feature flip.
    String tempOrgId = createOrganization("nofeat-org-" + suffix);
    registerOrgScopedCapability(tempOrgId, orgGatedCap, "authenticated");

    // Phase 2: now disable orgs and register the remaining (null-org) caps.
    disableOrganizationsOnRealm();

    userId = createTestUser("nofeat-" + suffix);

    registerCapability(nullGateCap, "authenticated", null);
    registerCapability(publicCap, "public", null);

    hostKey = TestKeys.generateEd25519();
    agentKey = TestKeys.generateEd25519();
    // Pre-register the host bound to the test user directly. The default preRegisterHost binds
    // to the master admin user and a subsequent linkHostToUser call to a different user would
    // 409 with host_already_linked.
    preRegisterHostForUser(hostKey, userId);
    agentId = registerDelegatedAgent(hostKey, agentKey, nullGateCap);
  }

  private static String createOrganization(String alias) {
    String token = adminAccessToken();
    Response resp = given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of(
            "name", alias,
            "alias", alias,
            "domains", java.util.List.of(Map.of("name", alias + ".test"))))
        .when()
        .post("/admin/realms/" + REALM + "/organizations");
    resp.then().statusCode(201);
    String location = resp.getHeader("Location");
    return location.substring(location.lastIndexOf('/') + 1);
  }

  private static void registerOrgScopedCapability(String orgId, String name, String visibility) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Phase 1 feature-off org-tagged test cap",
              "visibility": "%s",
              "requires_approval": false,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, name, visibility, name))
        .when()
        .post("/organizations/" + orgId + "/capabilities")
        .then()
        .statusCode(201);
  }

  @Test
  void authenticatedCallerSeesNullGateCap() {
    String jwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + jwt)
        .when()
        .get("/capability/list")
        .then()
        .statusCode(200)
        .body("capabilities.name", hasItem(nullGateCap));
  }

  @Test
  void authenticatedCallerDoesNotSeeOrgGatedCapWhenOrgsDisabled() {
    String jwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + jwt)
        .when()
        .get("/capability/list")
        .then()
        .statusCode(200)
        .body("capabilities.name", not(hasItem(orgGatedCap)));
  }

  @Test
  void anonymousSeesPublicCap() {
    given()
        .baseUri(issuerUrl())
        .when()
        .get("/capability/list")
        .then()
        .statusCode(200)
        .body("capabilities.name", hasItem(publicCap));
  }

  /**
   * When Organizations is disabled on the realm, every {@code /organizations/{orgId}/...} admin
   * endpoint must return 501 Not Implemented with a structured
   * {@code organizations_feature_disabled} error — distinct from 404 (org-not-found) so clients can
   * tell the difference between "feature off" and "wrong orgId."
   */
  @Test
  void orgScopedCapabilityEndpointReturns501WhenOrgsDisabled() {
    given()
        .baseUri(KEYCLOAK.getAuthServerUrl() + "/admin/realms/" + REALM + "/agent-auth")
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body("{\"name\":\"x\",\"visibility\":\"authenticated\","
            + "\"requires_approval\":false,\"location\":\"https://x/x\","
            + "\"input\":{\"type\":\"object\"},\"output\":{\"type\":\"object\"}}")
        .when()
        .post("/organizations/00000000-0000-0000-0000-000000000000/capabilities")
        .then()
        .statusCode(501)
        .body("error", org.hamcrest.Matchers.equalTo("organizations_feature_disabled"));
  }

  @Test
  void orgScopedHostEndpointReturns501WhenOrgsDisabled() {
    OctetKeyPair k = TestKeys.generateEd25519();
    given()
        .baseUri(KEYCLOAK.getAuthServerUrl() + "/admin/realms/" + REALM + "/agent-auth")
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of(
            "host_public_key", k.toPublicJWK().toJSONObject(),
            "client_id", "irrelevant"))
        .when()
        .post("/organizations/00000000-0000-0000-0000-000000000000/hosts")
        .then()
        .statusCode(501)
        .body("error", org.hamcrest.Matchers.equalTo("organizations_feature_disabled"));
  }

  // --- helpers ---

  private static void disableOrganizationsOnRealm() {
    String token = adminAccessToken();
    given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("organizationsEnabled", false))
        .when()
        .put("/admin/realms/" + REALM)
        .then()
        .statusCode(204);
  }

  private static String createTestUser(String username) {
    String token = adminAccessToken();
    Response resp = given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("username", username, "enabled", true))
        .when()
        .post("/admin/realms/" + REALM + "/users");
    resp.then().statusCode(201);
    String location = resp.getHeader("Location");
    return location.substring(location.lastIndexOf('/') + 1);
  }

  private static void registerCapability(String name, String visibility, String organizationId) {
    if (organizationId != null) {
      throw new IllegalArgumentException(
          "AAP-ADMIN-005: realm POST /capabilities no longer accepts body organization_id; "
              + "use registerOrgScopedCapability() with a real org id instead.");
    }
    StringBuilder body = new StringBuilder();
    body.append("{")
        .append("\"name\":\"").append(name).append("\",")
        .append("\"description\":\"Phase 1 feature-off test cap\",")
        .append("\"visibility\":\"").append(visibility).append("\",")
        .append("\"requires_approval\":false,")
        .append("\"location\":\"https://resource.example.test/").append(name).append("\",")
        .append("\"input\":{\"type\":\"object\"},")
        .append("\"output\":{\"type\":\"object\"}")
        .append("}");
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(body.toString())
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);
  }

  private static String registerDelegatedAgent(
      OctetKeyPair hostKeyArg, OctetKeyPair agentKeyArg, String capability) {
    String regJwt = TestJwts.hostJwtForRegistration(hostKeyArg, agentKeyArg, issuerUrl());
    return given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Feature-off test agent",
              "host_name": "nofeat-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "Phase 1 feature-off test"
            }
            """, capability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");
  }

  private static void linkHostToUser(String hostId, String linkedUserId) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of("user_id", linkedUserId))
        .when()
        .post("/hosts/" + hostId + "/link")
        .then()
        .statusCode(200);
  }
}
