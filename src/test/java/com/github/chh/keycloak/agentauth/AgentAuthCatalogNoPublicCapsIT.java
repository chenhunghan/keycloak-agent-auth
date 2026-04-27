package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;

import com.github.chh.keycloak.agentauth.support.BaseKeycloakIT;
import io.restassured.http.ContentType;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Spec compliance test for §5.2 "no public capabilities" branch.
 *
 * <p>
 * Per the AAP v1.0-draft §5.2 spec, servers whose capabilities depend entirely on user context MAY
 * return {@code 401 Unauthorized} when an unauthenticated caller hits {@code /capability/list} — as
 * opposed to returning an empty array. Our implementation returns {@code 401
 * authentication_required} with a human-readable message in this case.
 *
 * <p>
 * This class lives separately from {@link AgentAuthCapabilityCatalogIT} because the latter's shared
 * {@code @BeforeAll} fixture registers a public capability, which would short-circuit the branch
 * under test. Each IT class gets a fresh Keycloak container per the {@link BaseKeycloakIT}
 * lifecycle, so storage starts empty here regardless of what the catalog suite registers.
 *
 * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#52-list-capabilities">§5.2
 *      List Capabilities — 401 when no public capabilities and unauthenticated</a>
 * @see <a href=
 *      "https://agent-auth-protocol.com/specification/v1.0-draft#514-www-authenticate">§5.14
 *      WWW-Authenticate AgentAuth challenge with discovery URL</a>
 */
class AgentAuthCatalogNoPublicCapsIT extends BaseKeycloakIT {

  private static String authOnlyCapability;

  @BeforeAll
  static void setUp() {
    String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    authOnlyCapability = "auth_only_" + suffix;
    registerAuthenticatedCapability(authOnlyCapability);
  }

  @Test
  void listCapabilitiesUnauthenticatedWithOnlyAuthenticatedCapsReturns401() {
    given()
        .baseUri(issuerUrl())
        .when()
        .get("/capability/list")
        .then()
        .statusCode(401)
        .header("WWW-Authenticate", startsWith("AgentAuth discovery=\""))
        .header("WWW-Authenticate",
            containsString("/.well-known/agent-configuration"))
        .body("error", equalTo("authentication_required"));
  }

  private static void registerAuthenticatedCapability(String name) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Auth-only capability for §5.2 no-public-caps test",
              "visibility": "authenticated",
              "requires_approval": false,
              "location": "https://resource.example.test/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, name, name))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);
  }
}
