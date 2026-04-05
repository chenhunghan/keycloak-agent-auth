package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.github.chh.keycloak.agentauth.support.TestcontainersSupport;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.restassured.response.Response;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Integration test that boots a real Keycloak instance with the extension JAR loaded and verifies
 * the REST endpoints are reachable.
 */
@Testcontainers
class AgentAuthKeycloakIT {

  @Container
  static final KeycloakContainer KEYCLOAK = TestcontainersSupport.newKeycloakContainer();

  @Test
  void healthEndpointReturnsOk() {
    Response response = given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .when()
        .get("/realms/master/agent-auth/health");

    assertEquals(200, response.statusCode(), response.asString() + "\n\n" + KEYCLOAK.getLogs());
    assertEquals("ok", response.jsonPath().getString("status"));
    assertEquals("agent-auth", response.jsonPath().getString("provider"));
  }
}
