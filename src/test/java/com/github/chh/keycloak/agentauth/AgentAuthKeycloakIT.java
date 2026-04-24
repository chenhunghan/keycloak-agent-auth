package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.github.chh.keycloak.agentauth.support.BaseKeycloakIT;
import io.restassured.response.Response;
import org.junit.jupiter.api.Test;

/**
 * Smoke test that boots Keycloak with the extension loaded and verifies the health endpoint is
 * reachable.
 */
class AgentAuthKeycloakIT extends BaseKeycloakIT {

  @Test
  void healthEndpointReturnsOk() {
    Response response = given()
        .baseUri(issuerUrl())
        .when()
        .get("/health");

    assertEquals(200, response.statusCode(), response.asString() + "\n\n" + KEYCLOAK.getLogs());
    assertEquals("ok", response.jsonPath().getString("status"));
    assertEquals("agent-auth", response.jsonPath().getString("provider"));
  }
}
