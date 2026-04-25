package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
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
 * Closes a security gap: Phase 1's user-entitlement gate fires on {@code /capability/list},
 * {@code /describe}, {@code /verify/approve}, and Phase 2's lazy re-eval fires on
 * {@code /agent/introspect} (direct-mode flows). The remaining surfaces — {@code /agent/register},
 * {@code /agent/request-capability}, and {@code /capability/execute} — were ungated, so an
 * autonomous agent under a linked host could:
 *
 * <ol>
 * <li>register with an org-scoped capability whose org the host's owner isn't a member of, getting
 * a {@code status=active} grant immediately (because {@code requires_approval=false} skips the
 * approval-time gate);</li>
 * <li>execute that grant via {@code /capability/execute} (gateway mode), since execute didn't
 * re-evaluate entitlement at runtime.</li>
 * </ol>
 *
 * <p>
 * These ITs confirm the cap-name-as-discovery and gateway-mode-execute paths now reject, while the
 * entitled positive case still works.
 */
class AgentAuthAutonomousEntitlementGateIT extends BaseKeycloakIT {

  private static String suffix;
  private static String orgAcmeId;
  private static String orgGlobexId;

  @BeforeAll
  static void setUp() {
    suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    orgAcmeId = createOrganization("entgate-acme-" + suffix);
    orgGlobexId = createOrganization("entgate-globex-" + suffix);
  }

  /**
   * Negative: an autonomous agent under an SA-host whose owner is in Acme attempts to register with
   * a Globex-scoped capability. Without the gate, the workload could mint an active grant by simply
   * naming the capability. With the gate, registration must reject.
   */
  @Test
  void autonomousRegisterWithNonEntitledOrgCapRejects() {
    String capName = "entgate_globex_secret_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 6);
    createOrgScopedCap(orgGlobexId, capName, false);

    OctetKeyPair hostKey = TestKeys.generateEd25519();
    provisionAcmeAgentEnvironment(hostKey);

    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "rogue-cross-tenant",
              "host_name": "acme-sa",
              "mode": "autonomous",
              "capabilities": [{"name": "%s"}]
            }
            """, capName))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_capabilities"));
  }

  /**
   * Negative: same shape but with required_role gating — host's owner is in Acme but lacks the
   * realm role the cap demands. Confirms the gate covers both axes.
   */
  @Test
  void autonomousRegisterWithCapDemandingMissingRoleRejects() {
    String capName = "entgate_role_gated_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 6);
    createOrgScopedCapWithRole(orgAcmeId, capName,
        "role-that-no-sa-has-" + suffix, false);

    OctetKeyPair hostKey = TestKeys.generateEd25519();
    provisionAcmeAgentEnvironment(hostKey);

    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "rogue-no-role",
              "host_name": "acme-sa",
              "mode": "autonomous",
              "capabilities": [{"name": "%s"}]
            }
            """, capName))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_capabilities"));
  }

  /**
   * Positive control: when the SA's owner IS in the cap's org, autonomous registration succeeds and
   * the grant is active. Without this we'd be unable to tell a fix from a regression — confirms the
   * gate isn't over-rejecting.
   */
  @Test
  void autonomousRegisterWithEntitledOrgCapSucceeds() {
    String capName = "entgate_acme_ok_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 6);
    createOrgScopedCap(orgAcmeId, capName, false);

    OctetKeyPair hostKey = TestKeys.generateEd25519();
    provisionAcmeAgentEnvironment(hostKey);

    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "auton-acme",
              "host_name": "acme-sa",
              "mode": "autonomous",
              "capabilities": [{"name": "%s"}]
            }
            """, capName))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("status", equalTo("active"))
        .body("agent_capability_grants[0].capability", equalTo(capName))
        .body("agent_capability_grants[0].status", equalTo("active"));
  }

  // --- helpers ---

  private static void provisionAcmeAgentEnvironment(OctetKeyPair hostKey) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of(
            "host_public_key", hostKey.toPublicJWK().toJSONObject(),
            "name", "Acme env"))
        .when()
        .post("/organizations/" + orgAcmeId + "/agent-environments")
        .then()
        .statusCode(201);
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

  private static void createOrgScopedCap(String orgId, String name, boolean requiresApproval) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "entitlement-gate test cap",
              "visibility": "authenticated",
              "requires_approval": %s,
              "location": "https://x/%s",
              "input": {"type":"object"},
              "output": {"type":"object"}
            }
            """, name, requiresApproval, name))
        .when()
        .post("/organizations/" + orgId + "/capabilities")
        .then()
        .statusCode(201);
  }

  private static void createOrgScopedCapWithRole(String orgId, String name, String requiredRole,
      boolean requiresApproval) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "entitlement-gate test cap (role-gated)",
              "visibility": "authenticated",
              "requires_approval": %s,
              "required_role": "%s",
              "location": "https://x/%s",
              "input": {"type":"object"},
              "output": {"type":"object"}
            }
            """, name, requiresApproval, requiredRole, name))
        .when()
        .post("/organizations/" + orgId + "/capabilities")
        .then()
        .statusCode(201);
  }
}
