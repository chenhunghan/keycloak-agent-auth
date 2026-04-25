package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;

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
 * Phase 5 of the multi-tenant authz plan: org-admin self-service capability registration via
 * {@code /admin/.../organizations/{orgId}/capabilities}, plus the SA-as-host pattern on the
 * existing pre-register {@code POST /admin/.../hosts}.
 *
 * <p>
 * Realm-admin is a privileged super-user that can hit the org-scoped endpoints regardless of org
 * membership — that's the path tested here. The org-admin-only-but-not-realm-admin flow (caller has
 * {@code manage-organization} role + org membership but NOT {@code manage-realm}) exercises the
 * same code branch with one extra check; an end-to-end IT for that path requires provisioning a
 * non-admin user with realm-management client roles, which is left to Phase 5b.
 */
class AgentAuthOrgAdminCapabilityIT extends BaseKeycloakIT {

  private static String suffix;
  private static String acmeOrgId;
  private static String globexOrgId;

  @BeforeAll
  static void setUp() {
    suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    acmeOrgId = createOrganization("acmep5-" + suffix);
    globexOrgId = createOrganization("globexp5-" + suffix);
  }

  @Test
  void registerOrgScopedCapabilityForcesOrgIdFromPath() {
    String name = "p5_acme_" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    // Body claims a different org_id; the path's org_id must win.
    Response resp = given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Phase 5 org-admin test",
              "visibility": "authenticated",
              "requires_approval": false,
              "location": "https://x/%s",
              "input": {"type": "object"},
              "output": {"type": "object"},
              "organization_id": "%s"
            }
            """, name, name, globexOrgId))
        .when()
        .post("/organizations/" + acmeOrgId + "/capabilities");
    resp.then().statusCode(201);
    // Path wins.
    assertThat(resp.jsonPath().getString("organization_id")).isEqualTo(acmeOrgId);
  }

  @Test
  void listOrgScopedCapabilitiesShowsOnlyMatchingOrg() {
    String acmeCap = "p5_list_acme_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    String globexCap = "p5_list_globex_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    createOrgScopedCap(acmeOrgId, acmeCap);
    createOrgScopedCap(globexOrgId, globexCap);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/organizations/" + acmeOrgId + "/capabilities")
        .then()
        .statusCode(200)
        .body("capabilities.name",
            org.hamcrest.Matchers.hasItem(acmeCap))
        .body("capabilities.name",
            org.hamcrest.Matchers.not(org.hamcrest.Matchers.hasItem(globexCap)));
  }

  @Test
  void updateOrgScopedCapabilityFromOtherOrgPathReturns404() {
    String name = "p5_update_" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    createOrgScopedCap(acmeOrgId, name);

    // Try to update Acme's cap via Globex's path — must 404 (cap doesn't belong to that org).
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of("description", "Hijacked"))
        .when()
        .put("/organizations/" + globexOrgId + "/capabilities/" + name)
        .then()
        .statusCode(404)
        .body("error", equalTo("capability_not_found"));
  }

  @Test
  void deleteOrgScopedCapabilityFromOtherOrgPathReturns404() {
    String name = "p5_delete_" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    createOrgScopedCap(acmeOrgId, name);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .delete("/organizations/" + globexOrgId + "/capabilities/" + name)
        .then()
        .statusCode(404)
        .body("error", equalTo("capability_not_found"));

    // Acme's cap still exists.
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/organizations/" + acmeOrgId + "/capabilities")
        .then()
        .statusCode(200)
        .body("capabilities.name", org.hamcrest.Matchers.hasItem(name));
  }

  @Test
  void registerOrgScopedCapabilityFor404OrgReturns404() {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "p5_404org_%s",
              "description": "Phase 5 missing-org test",
              "visibility": "authenticated",
              "requires_approval": false,
              "location": "https://x/x",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, suffix))
        .when()
        .post("/organizations/00000000-0000-0000-0000-000000000000/capabilities")
        .then()
        .statusCode(404);
  }

  @Test
  void preRegisterHostWithClientIdSetsServiceAccountUserId() {
    String clientId = "p5sa-client-"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    createConfidentialClientWithSA(clientId);

    OctetKeyPair hostKey = com.github.chh.keycloak.agentauth.support.TestKeys.generateEd25519();
    Map<String, Object> hostPublicKey = hostKey.toPublicJWK().toJSONObject();

    Response resp = given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of(
            "host_public_key", hostPublicKey,
            "client_id", clientId,
            "name", "Phase 5 SA host"))
        .when()
        .post("/hosts");
    resp.then().statusCode(201);
    String userId = resp.jsonPath().getString("user_id");
    String reportedClientId = resp.jsonPath().getString("service_account_client_id");
    assertThat(userId).isNotNull();
    assertThat(reportedClientId).isEqualTo(clientId);
  }

  @Test
  void preRegisterHostWithUnknownClientIdReturns400() {
    OctetKeyPair hostKey = com.github.chh.keycloak.agentauth.support.TestKeys.generateEd25519();
    Map<String, Object> hostPublicKey = hostKey.toPublicJWK().toJSONObject();

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of(
            "host_public_key", hostPublicKey,
            "client_id", "client-that-does-not-exist-" + suffix))
        .when()
        .post("/hosts")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  /**
   * SA-hosts have no human consent channel, so a delegated-mode registration would never receive a
   * usable approval (CIBA email goes to a service-account user with no inbox; no realm user can
   * post a device-flow user_code on its behalf). Reject at register time with a clear error rather
   * than letting the agent stall in {@code pending} forever.
   */
  @Test
  void registerDelegatedAgentUnderSAHostIsRejected() {
    String clientId = "p5sa-deleg-"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    createConfidentialClientWithSA(clientId);

    OctetKeyPair hostKey = TestKeys.generateEd25519();
    Map<String, Object> hostPublicKey = hostKey.toPublicJWK().toJSONObject();
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of(
            "host_public_key", hostPublicKey,
            "client_id", clientId,
            "name", "SA host for delegated guard"))
        .when()
        .post("/hosts")
        .then()
        .statusCode(201);

    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "delegated-under-sa",
              "host_name": "sa-host",
              "capabilities": [],
              "mode": "delegated"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_mode_for_sa_host"));
  }

  /**
   * Companion to the reject test: autonomous-mode agents under an SA-host must register cleanly
   * (active immediately, no approval flow). Locks in the intended path so a future change to the
   * guard can't accidentally tighten past mode=delegated.
   */
  @Test
  void registerAutonomousAgentUnderSAHostSucceeds() {
    String clientId = "p5sa-auton-"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    createConfidentialClientWithSA(clientId);

    OctetKeyPair hostKey = TestKeys.generateEd25519();
    Map<String, Object> hostPublicKey = hostKey.toPublicJWK().toJSONObject();
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of(
            "host_public_key", hostPublicKey,
            "client_id", clientId,
            "name", "SA host for autonomous"))
        .when()
        .post("/hosts")
        .then()
        .statusCode(201);

    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "autonomous-under-sa",
              "host_name": "sa-host",
              "capabilities": [],
              "mode": "autonomous"
            }
            """)
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("mode", equalTo("autonomous"))
        .body("status", equalTo("active"));
  }

  /**
   * Org-scoped SA-host pre-registration succeeds when the SA user is already a member of the path's
   * org. Mirrors {@link #preRegisterHostWithClientIdSetsServiceAccountUserId} but exercises the
   * org-self-service path: org admins can stand up SA-hosts without realm-admin once the SA is in
   * the org.
   */
  @Test
  void registerOrgHostBindsSAWhenSAIsOrgMember() {
    String clientId = "p5orgsa-ok-"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    createConfidentialClientWithSA(clientId);
    String saUserId = serviceAccountUserId(clientId);
    addUserToOrganization(acmeOrgId, saUserId);

    OctetKeyPair hostKey = TestKeys.generateEd25519();
    Map<String, Object> hostPublicKey = hostKey.toPublicJWK().toJSONObject();

    Response resp = given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of(
            "host_public_key", hostPublicKey,
            "client_id", clientId,
            "name", "Org-scoped SA host"))
        .when()
        .post("/organizations/" + acmeOrgId + "/hosts");
    resp.then().statusCode(201);
    assertThat(resp.jsonPath().getString("user_id")).isEqualTo(saUserId);
    assertThat(resp.jsonPath().getString("service_account_client_id")).isEqualTo(clientId);
  }

  /**
   * The org-scoped endpoint requires {@code client_id} — without it, the path makes no sense
   * (org-self-service exists specifically to bind hosts to SA users).
   */
  @Test
  void registerOrgHostMissingClientIdReturns400() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    Map<String, Object> hostPublicKey = hostKey.toPublicJWK().toJSONObject();
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of("host_public_key", hostPublicKey))
        .when()
        .post("/organizations/" + acmeOrgId + "/hosts")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  /**
   * SA-belongs-to-org gate: an SA user that isn't a member of the path's org can't be bound through
   * the org-scoped endpoint. Without this, an org admin could bind hosts to any client's SA in the
   * realm — including SAs operated by an unrelated tenant.
   */
  @Test
  void registerOrgHostWithSANotInOrgReturns400() {
    String clientId = "p5orgsa-noorg-"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    createConfidentialClientWithSA(clientId);
    // Deliberately skip addUserToOrganization — the SA is not in any org.

    OctetKeyPair hostKey = TestKeys.generateEd25519();
    Map<String, Object> hostPublicKey = hostKey.toPublicJWK().toJSONObject();
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of(
            "host_public_key", hostPublicKey,
            "client_id", clientId))
        .when()
        .post("/organizations/" + acmeOrgId + "/hosts")
        .then()
        .statusCode(400)
        .body("error", equalTo("sa_not_in_org"));
  }

  /**
   * Cross-tenant safety: even with the SA enrolled in Globex, Acme's path can't bind it. Together
   * with the previous test this confirms membership is checked against the path's org specifically,
   * not "any org."
   */
  @Test
  void registerOrgHostWithSAInDifferentOrgReturns400() {
    String clientId = "p5orgsa-xorg-"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    createConfidentialClientWithSA(clientId);
    String saUserId = serviceAccountUserId(clientId);
    addUserToOrganization(globexOrgId, saUserId);

    OctetKeyPair hostKey = TestKeys.generateEd25519();
    Map<String, Object> hostPublicKey = hostKey.toPublicJWK().toJSONObject();
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of(
            "host_public_key", hostPublicKey,
            "client_id", clientId))
        .when()
        .post("/organizations/" + acmeOrgId + "/hosts")
        .then()
        .statusCode(400)
        .body("error", equalTo("sa_not_in_org"));
  }

  /**
   * Path's {@code orgId} must resolve to a real org — handled by
   * {@link AgentAuthAdminResourceProvider#requireOrgAdmin}, returning 404.
   */
  @Test
  void registerOrgHostFor404OrgReturns404() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    Map<String, Object> hostPublicKey = hostKey.toPublicJWK().toJSONObject();
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of(
            "host_public_key", hostPublicKey,
            "client_id", "irrelevant"))
        .when()
        .post("/organizations/00000000-0000-0000-0000-000000000000/hosts")
        .then()
        .statusCode(404);
  }

  // --- helpers ---

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

  private static void createOrgScopedCap(String orgId, String name) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Phase 5 org-scoped test cap",
              "visibility": "authenticated",
              "requires_approval": false,
              "location": "https://x/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, name, name))
        .when()
        .post("/organizations/" + orgId + "/capabilities")
        .then()
        .statusCode(201);
  }

  private static String serviceAccountUserId(String clientId) {
    return given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .queryParam("username", "service-account-" + clientId.toLowerCase(java.util.Locale.ROOT))
        .queryParam("exact", true)
        .when()
        .get("/admin/realms/" + REALM + "/users")
        .then()
        .statusCode(200)
        .extract()
        .jsonPath()
        .getString("[0].id");
  }

  private static void addUserToOrganization(String orgId, String userId) {
    given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(userId)
        .when()
        .post("/admin/realms/" + REALM + "/organizations/" + orgId + "/members")
        .then()
        .statusCode(org.hamcrest.Matchers.anyOf(equalTo(201), equalTo(204)));
  }

  private static void createConfidentialClientWithSA(String clientId) {
    given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of(
            "clientId", clientId,
            "enabled", true,
            "publicClient", false,
            "serviceAccountsEnabled", true,
            "standardFlowEnabled", false,
            "directAccessGrantsEnabled", false,
            "secret", "secret"))
        .when()
        .post("/admin/realms/" + REALM + "/clients")
        .then()
        .statusCode(201);
  }
}
