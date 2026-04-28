package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;

import com.github.chh.keycloak.agentauth.support.BaseKeycloakIT;
import com.github.chh.keycloak.agentauth.support.TestJwts;
import com.github.chh.keycloak.agentauth.support.TestKeys;
import com.nimbusds.jose.jwk.OctetKeyPair;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Phase 1 of the multi-tenant authz plan: verifies the user-entitlement gate on
 * {@code /capability/list} and {@code /capability/describe}. Capabilities can carry an
 * {@code organization_id} (KC org membership required) and/or a {@code required_role} (KC
 * realm-role required). When both gates are NULL, the cap is the realm-wide common pool — visible
 * to all authenticated users.
 *
 * <p>
 * Tests use {@code agent+jwt} rather than {@code host+jwt} for principal-resolution clarity (the
 * caller is unambiguously the agent's owning user). The §5.2 host-defaults listing filter was
 * removed during the post-Phase-1 reconciliation, so host+jwt would also work here — agent+jwt just
 * keeps the "isolate the new gate" framing one step removed from host pre-approval state.
 *
 * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#52-list-capabilities">§5.2
 *      List Capabilities — host-JWT mode "capabilities available to the host's linked user"</a>
 */
class AgentAuthMultiTenantCapabilityIT extends BaseKeycloakIT {

  private static String suffix;
  private static String acmeOrgId;
  private static String globexOrgId;
  private static String aliceUserId;
  private static String bobUserId;

  private static String realmCap;
  private static String acmeCap;
  private static String globexCap;
  private static String roleGatedCap;
  private static String publicCap;
  private static final String ROLE_NAME = "accountant";

  private static OctetKeyPair aliceHostKey;
  private static OctetKeyPair aliceAgentKey;
  private static String aliceAgentId;
  private static OctetKeyPair bobHostKey;
  private static OctetKeyPair bobAgentKey;
  private static String bobAgentId;

  @BeforeAll
  static void setUp() {
    suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    aliceUserId = createTestUser("alice-" + suffix);
    bobUserId = createTestUser("bob-" + suffix);

    acmeOrgId = createOrganization("acme-" + suffix);
    globexOrgId = createOrganization("globex-" + suffix);
    addUserToOrganization(acmeOrgId, aliceUserId);
    addUserToOrganization(globexOrgId, bobUserId);

    createRealmRole(ROLE_NAME);
    // Neither alice nor bob hold the accountant role in this test fixture.

    realmCap = "phase1_realm_" + suffix;
    acmeCap = "phase1_acme_" + suffix;
    globexCap = "phase1_globex_" + suffix;
    roleGatedCap = "phase1_role_" + suffix;
    publicCap = "phase1_public_" + suffix;

    registerCapability(realmCap, "authenticated", null, null);
    registerCapability(acmeCap, "authenticated", acmeOrgId, null);
    registerCapability(globexCap, "authenticated", globexOrgId, null);
    registerCapability(roleGatedCap, "authenticated", null, ROLE_NAME);
    registerCapability(publicCap, "public", null, null);

    // Pre-register hosts bound directly to their user (Wave 5 AAP-ADMIN-001: default
    // preRegisterHost binds to admin; subsequent linkHostToUser to a different user would 409).
    aliceHostKey = TestKeys.generateEd25519();
    aliceAgentKey = TestKeys.generateEd25519();
    preRegisterHostForUser(aliceHostKey, aliceUserId);
    aliceAgentId = registerDelegatedAgent(aliceHostKey, aliceAgentKey, realmCap);

    bobHostKey = TestKeys.generateEd25519();
    bobAgentKey = TestKeys.generateEd25519();
    preRegisterHostForUser(bobHostKey, bobUserId);
    bobAgentId = registerDelegatedAgent(bobHostKey, bobAgentKey, realmCap);
  }

  @Test
  void listWithAliceAgentJwtShowsAcmeAndRealmButNotGlobexOrRoleGated() {
    String jwt = TestJwts.agentJwt(aliceHostKey, aliceAgentKey, aliceAgentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + jwt)
        .when()
        .get("/capability/list")
        .then()
        .statusCode(200)
        .body("capabilities.name", hasItems(realmCap, acmeCap, publicCap))
        .body("capabilities.name", org.hamcrest.Matchers.not(hasItem(globexCap)))
        .body("capabilities.name", org.hamcrest.Matchers.not(hasItem(roleGatedCap)));
  }

  @Test
  void listWithBobAgentJwtShowsGlobexAndRealmButNotAcmeOrRoleGated() {
    String jwt = TestJwts.agentJwt(bobHostKey, bobAgentKey, bobAgentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + jwt)
        .when()
        .get("/capability/list")
        .then()
        .statusCode(200)
        .body("capabilities.name", hasItems(realmCap, globexCap, publicCap))
        .body("capabilities.name", org.hamcrest.Matchers.not(hasItem(acmeCap)))
        .body("capabilities.name", org.hamcrest.Matchers.not(hasItem(roleGatedCap)));
  }

  @Test
  void listAnonymousShowsPublicCapRegardlessOfOrgId() {
    given()
        .baseUri(issuerUrl())
        .when()
        .get("/capability/list")
        .then()
        .statusCode(200)
        .body("capabilities.name", hasItem(publicCap))
        .body("capabilities.name", org.hamcrest.Matchers.not(hasItem(acmeCap)))
        .body("capabilities.name", org.hamcrest.Matchers.not(hasItem(globexCap)));
  }

  @Test
  void describeOrgGatedCapReturns404ForNonMember() {
    String jwt = TestJwts.agentJwt(aliceHostKey, aliceAgentKey, aliceAgentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + jwt)
        .queryParam("name", globexCap)
        .when()
        .get("/capability/describe")
        .then()
        .statusCode(404)
        .body("error", equalTo("capability_not_found"));
  }

  @Test
  void describeRoleGatedCapReturns404WithoutRequiredRole() {
    String jwt = TestJwts.agentJwt(aliceHostKey, aliceAgentKey, aliceAgentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + jwt)
        .queryParam("name", roleGatedCap)
        .when()
        .get("/capability/describe")
        .then()
        .statusCode(404)
        .body("error", equalTo("capability_not_found"));
  }

  @Test
  void describeOrgGatedCapReturns200ForMember() {
    String jwt = TestJwts.agentJwt(aliceHostKey, aliceAgentKey, aliceAgentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + jwt)
        .queryParam("name", acmeCap)
        .when()
        .get("/capability/describe")
        .then()
        .statusCode(200)
        .body("name", equalTo(acmeCap));
  }

  // --- helpers ---

  private static String createTestUser(String username) {
    String token = adminAccessToken(); // triggers ensureStarted()
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

  private static String createOrganization(String alias) {
    String token = adminAccessToken();
    Response resp = given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of(
            "name", alias,
            "alias", alias,
            "domains", List.of(Map.of("name", alias + ".test"))))
        .when()
        .post("/admin/realms/" + REALM + "/organizations");
    resp.then().statusCode(201);
    String location = resp.getHeader("Location");
    return location.substring(location.lastIndexOf('/') + 1);
  }

  private static void addUserToOrganization(String orgId, String userId) {
    String token = adminAccessToken();
    given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(userId)
        .when()
        .post("/admin/realms/" + REALM + "/organizations/" + orgId + "/members")
        .then()
        .statusCode(org.hamcrest.Matchers.anyOf(equalTo(201), equalTo(204)));
  }

  private static void createRealmRole(String roleName) {
    String token = adminAccessToken();
    given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("name", roleName))
        .when()
        .post("/admin/realms/" + REALM + "/roles")
        .then()
        .statusCode(org.hamcrest.Matchers.anyOf(equalTo(201), equalTo(409)));
  }

  private static void registerCapability(
      String name, String visibility, String organizationId, String requiredRole) {
    StringBuilder body = new StringBuilder();
    body.append("{")
        .append("\"name\":\"").append(name).append("\",")
        .append("\"description\":\"Phase 1 multi-tenant test cap\",")
        .append("\"visibility\":\"").append(visibility).append("\",")
        .append("\"requires_approval\":false,")
        .append("\"location\":\"https://resource.example.test/").append(name).append("\",")
        .append("\"input\":{\"type\":\"object\"},")
        .append("\"output\":{\"type\":\"object\"}");
    if (requiredRole != null) {
      body.append(",\"required_role\":\"").append(requiredRole).append("\"");
    }
    body.append("}");
    // AAP-ADMIN-005: realm POST /capabilities rejects body `organization_id`. Org-tagged caps
    // route through /organizations/{orgId}/capabilities; null-org caps stay on the realm path.
    String url = organizationId != null
        ? "/organizations/" + organizationId + "/capabilities"
        : "/capabilities";
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(body.toString())
        .when()
        .post(url)
        .then()
        .statusCode(201);
  }

  private static String registerDelegatedAgent(
      OctetKeyPair hostKey, OctetKeyPair agentKey, String capability) {
    String regJwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl());
    return given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Multi-tenant test agent",
              "host_name": "mt-test-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "Phase 1 multi-tenant test"
            }
            """, capability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");
  }

  private static void linkHostToUser(String hostId, String userId) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of("user_id", userId))
        .when()
        .post("/hosts/" + hostId + "/link")
        .then()
        .statusCode(200);
  }
}
