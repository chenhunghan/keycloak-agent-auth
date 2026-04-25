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
 * Org-self-serve agent-environment provisioning. Each test exercises the full chain: org-admin call
 * → KC client creation (locked-down) → SA bound to org → host pre-registered.
 *
 * <p>
 * The realm-admin token stands in for an org admin in these ITs because the {@code requireOrgAdmin}
 * gate accepts realm-admin as a super-user. Pure org-admin auth (manage-organization without
 * manage-realm) is exercised by {@link AgentAuthOrgAdminCapabilityIT} on shared logic; not
 * duplicating it here.
 */
class AgentAuthOrgAgentEnvironmentIT extends BaseKeycloakIT {

  private static String suffix;
  private static String acmeOrgId;
  private static String globexOrgId;

  @BeforeAll
  static void setUp() {
    suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    acmeOrgId = createOrganization("acmeenv-" + suffix);
    globexOrgId = createOrganization("globexenv-" + suffix);
  }

  /**
   * Happy path: one call provisions client + SA-in-org + host. Verifies the response shape and that
   * the secret is returned exactly once.
   */
  @Test
  void createEnvironmentReturnsClientSecretAndHostId() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();

    Response resp = given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of(
            "host_public_key", hostKey.toPublicJWK().toJSONObject(),
            "name", "Acme nightly worker"))
        .when()
        .post("/organizations/" + acmeOrgId + "/agent-environments");
    resp.then().statusCode(201);
    assertThat(resp.jsonPath().getString("client_id")).startsWith("agentauth-");
    assertThat(resp.jsonPath().getString("client_secret")).isNotBlank();
    assertThat(resp.jsonPath().getString("host_id")).isNotBlank();
    assertThat(resp.jsonPath().getString("service_account_user_id")).isNotBlank();
    assertThat(resp.jsonPath().getString("organization_id")).isEqualTo(acmeOrgId);
  }

  /**
   * Defense-in-depth: the created client must have OIDC flows disabled so org admins can't
   * repurpose it for browser/auth flows or escalate privilege. Re-fetches the client via KC's
   * native admin API and asserts every lockdown flag.
   */
  @Test
  void createdClientHasLockdownFlagsAllFalse() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    Response create = given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of("host_public_key", hostKey.toPublicJWK().toJSONObject()))
        .when()
        .post("/organizations/" + acmeOrgId + "/agent-environments");
    create.then().statusCode(201);
    String clientId = create.jsonPath().getString("client_id");

    // Re-fetch via KC admin API
    Response client = given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/admin/realms/" + REALM + "/clients?clientId=" + clientId);
    client.then().statusCode(200);

    // KC may omit default-false flags in the JSON; treat null and false as equivalent for
    // disabled flags. The lockdown contract is "this flag is not enabled," not "this flag is
    // serialized as the literal false."
    assertNotEnabled(client, "[0].publicClient");
    assertThat(client.jsonPath().getBoolean("[0].serviceAccountsEnabled")).isTrue();
    assertNotEnabled(client, "[0].standardFlowEnabled");
    assertNotEnabled(client, "[0].implicitFlowEnabled");
    assertNotEnabled(client, "[0].directAccessGrantsEnabled");
    assertNotEnabled(client, "[0].authorizationServicesEnabled");
    // Tag attributes wire up audit/cleanup
    assertThat(client.jsonPath().getString("[0].attributes.agent_auth_managed"))
        .isEqualTo("true");
    assertThat(client.jsonPath().getString("[0].attributes.agent_auth_organization_id"))
        .isEqualTo(acmeOrgId);
  }

  /**
   * The SA user is added to the path's org as part of provisioning; the host record carries the
   * SA's user_id. Without this, the new SA-host wouldn't satisfy the {@code sa_not_in_org} gate
   * downstream.
   */
  @Test
  void createdEnvironmentBindsSAToOrgAndHost() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    Response create = given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of("host_public_key", hostKey.toPublicJWK().toJSONObject()))
        .when()
        .post("/organizations/" + acmeOrgId + "/agent-environments");
    String hostId = create.jsonPath().getString("host_id");
    String saUserId = create.jsonPath().getString("service_account_user_id");

    // Host record
    Response host = given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/hosts/" + hostId);
    host.then().statusCode(200);
    assertThat(host.jsonPath().getString("user_id")).isEqualTo(saUserId);
    assertThat(host.jsonPath().getString("service_account_client_id"))
        .startsWith("agentauth-");

    // Org membership
    Response members = given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/admin/realms/" + REALM + "/organizations/" + acmeOrgId + "/members");
    members.then().statusCode(200);
    assertThat(members.jsonPath().getList("id"))
        .as("SA must appear in the org's member list")
        .contains(saUserId);
  }

  /**
   * End-to-end smoke: the workload can register an autonomous agent under the freshly provisioned
   * SA-host. Confirms the chain is wired up correctly — without this the endpoint could return a
   * 201 that doesn't actually let an agent run.
   */
  @Test
  void autonomousAgentRegistersUnderProvisionedEnvironment() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    Response create = given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of("host_public_key", hostKey.toPublicJWK().toJSONObject()))
        .when()
        .post("/organizations/" + acmeOrgId + "/agent-environments");
    create.then().statusCode(201);

    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "auton-under-managed-env",
              "host_name": "managed-env",
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
   * Cross-tenant safety: a client managed by Globex must not be deletable through Acme's path.
   * Returns 404 (don't leak existence of clients in other orgs).
   */
  @Test
  void deleteEnvironmentFromOtherOrgPathReturns404() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    Response create = given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of("host_public_key", hostKey.toPublicJWK().toJSONObject()))
        .when()
        .post("/organizations/" + globexOrgId + "/agent-environments");
    String clientId = create.jsonPath().getString("client_id");

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .delete("/organizations/" + acmeOrgId + "/agent-environments/" + clientId)
        .then()
        .statusCode(404)
        .body("error", equalTo("environment_not_found"));
  }

  /**
   * Defense-in-depth: an unmanaged client (one this endpoint did not create) cannot be deleted via
   * this endpoint, even by realm-admin — the tag attributes act as a scoped-DELETE guardrail.
   */
  @Test
  void deleteUnmanagedClientReturns404() {
    String unmanagedClientId = "unmanaged-" + suffix;
    given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of(
            "clientId", unmanagedClientId,
            "enabled", true,
            "publicClient", false,
            "serviceAccountsEnabled", true,
            "standardFlowEnabled", false,
            "directAccessGrantsEnabled", false,
            "secret", "x"))
        .when()
        .post("/admin/realms/" + REALM + "/clients")
        .then()
        .statusCode(201);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .delete("/organizations/" + acmeOrgId + "/agent-environments/" + unmanagedClientId)
        .then()
        .statusCode(404)
        .body("error", equalTo("environment_not_found"));
  }

  /**
   * Delete cascades: removing the managed environment deletes the client → SA user, which fires
   * UserRemovedEvent → handleUserRemoved revokes the host. The host's status flips to revoked.
   */
  @Test
  void deleteEnvironmentCascadesHostRevocation() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    Response create = given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of("host_public_key", hostKey.toPublicJWK().toJSONObject()))
        .when()
        .post("/organizations/" + acmeOrgId + "/agent-environments");
    String clientId = create.jsonPath().getString("client_id");
    String hostId = create.jsonPath().getString("host_id");

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .delete("/organizations/" + acmeOrgId + "/agent-environments/" + clientId)
        .then()
        .statusCode(204);

    // Client should be gone
    given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/admin/realms/" + REALM + "/clients?clientId=" + clientId)
        .then()
        .statusCode(200)
        .body("size()", equalTo(0));

    // Host should be revoked (UserRemovedEvent → handleUserRemoved)
    Response host = given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/hosts/" + hostId);
    host.then().statusCode(200);
    assertThat(host.jsonPath().getString("status")).isEqualTo("revoked");
  }

  /**
   * Body must include host_public_key. Without it the endpoint returns 400 — the rest of the body
   * shape is intentionally minimal so org admins can't pass extra fields that bypass lockdown.
   */
  @Test
  void createEnvironmentMissingHostPublicKeyReturns400() {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of("name", "no key here"))
        .when()
        .post("/organizations/" + acmeOrgId + "/agent-environments")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  // --- helpers ---

  private static void assertNotEnabled(Response clientResponse, String path) {
    Object value = clientResponse.jsonPath().get(path);
    assertThat(value == null || Boolean.FALSE.equals(value))
        .as("expected %s to be null or false, got %s", path, value)
        .isTrue();
  }

  private static String createOrganization(String alias) {
    // Touch adminAccessToken() first so the shared container is started before we read KEYCLOAK
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
}
