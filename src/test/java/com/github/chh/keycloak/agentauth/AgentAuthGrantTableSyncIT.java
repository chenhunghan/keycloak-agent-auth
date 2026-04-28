package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import com.github.chh.keycloak.agentauth.support.BaseKeycloakIT;
import com.github.chh.keycloak.agentauth.support.TestJwts;
import com.github.chh.keycloak.agentauth.support.TestKeys;
import com.nimbusds.jose.jwk.OctetKeyPair;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Phase 3 of the multi-tenant authz plan: verifies the new {@code AGENT_AUTH_AGENT_GRANT} table
 * stays in sync with the per-agent grants array nested in the JSON payload. The blob remains the
 * source of truth for application reads in this phase; this test asserts the secondary index
 * mirrors it after register / approve / deny / revoke.
 *
 * <p>
 * The admin-only {@code GET /agents/{id}/grants} endpoint exposes the table directly so the test
 * can compare the two sides without depending on Phase 4's cascade flow.
 */
class AgentAuthGrantTableSyncIT extends BaseKeycloakIT {

  @Test
  void grantTableMirrorsBlobAfterRegisterAndApprove() {
    String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    String capA = registerAuthCapability("p3sync_a_" + suffix);
    String capB = registerAuthCapability("p3sync_b_" + suffix);

    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    // AAP-ADMIN-001: admin grant approval on a delegated agent now requires the host be linked
    // to a realm user. Pre-register the host bound to the test admin so the subsequent admin
    // approve call below succeeds. This test only cares that the secondary index mirrors the
    // blob, not how the host got linked.
    preRegisterHost(hostKey);
    String agentId = registerDelegatedAgent(hostKey, agentKey, List.of(capA, capB));

    // After register, both grants should be in pending state in the table.
    List<Map<String, Object>> rowsAfterRegister = fetchGrantTableRows(agentId);
    assertThat(rowsAfterRegister).hasSize(2);
    assertThat(rowsAfterRegister)
        .extracting(g -> g.get("capability") + ":" + g.get("status"))
        .containsExactlyInAnyOrder(capA + ":pending", capB + ":pending");

    // Approve capA via admin path. The blob flips capA to active and leaves capB pending. The
    // grants table must mirror that exactly after the putAgent sync.
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .post("/agents/" + agentId + "/capabilities/" + capA + "/approve")
        .then()
        .statusCode(200);

    List<Map<String, Object>> rowsAfterApprove = fetchGrantTableRows(agentId);
    Map<String, String> statusByCap = new java.util.HashMap<>();
    for (Map<String, Object> row : rowsAfterApprove) {
      statusByCap.put((String) row.get("capability"), (String) row.get("status"));
    }
    assertThat(statusByCap).containsEntry(capA, "active");
    assertThat(statusByCap).containsEntry(capB, "pending");
  }

  @Test
  void grantTableClearsWhenPendingAgentSweptUp() {
    // Pending-cleanup uses a JPQL bulk delete that bypasses JPA cascade, so the new grants
    // table needs an explicit delete-by-agent before the agent rows go. Verify both sides.
    String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    String cap = registerAuthCapability("p3sync_sweep_" + suffix);

    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String agentId = registerDelegatedAgent(hostKey, agentKey, List.of(cap));

    // Confirm grants exist before sweep.
    assertThat(fetchGrantTableRows(agentId)).hasSize(1);

    // Sweep all pending agents (threshold=0 catches everything pending).
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .queryParam("olderThanSeconds", 0)
        .when()
        .post("/pending-agents/cleanup")
        .then()
        .statusCode(200);

    // Both the agent AND its grants are gone.
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/agents/" + agentId)
        .then()
        .statusCode(404);
    assertThat(fetchGrantTableRows(agentId)).isEmpty();
  }

  // --- helpers ---

  private static String registerAuthCapability(String name) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Phase 3 grant-sync test cap",
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

  private static String registerDelegatedAgent(
      OctetKeyPair hostKey, OctetKeyPair agentKey, List<String> capabilities) {
    String regJwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl());
    String capsArray = capabilities.stream()
        .map(c -> "\"" + c + "\"")
        .collect(java.util.stream.Collectors.joining(","));
    return given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Phase 3 grant-sync agent",
              "host_name": "p3-host",
              "capabilities": [%s],
              "mode": "delegated",
              "reason": "Phase 3 sync test"
            }
            """, capsArray))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");
  }

  private static List<Map<String, Object>> fetchGrantTableRows(String agentId) {
    Response resp = given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .get("/agents/" + agentId + "/grants");
    resp.then().statusCode(200);
    return resp.jsonPath().getList("grants");
  }

}
