package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;

import com.github.chh.keycloak.agentauth.support.BaseKeycloakIT;
import io.restassured.http.ContentType;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Integration tests for the Keycloak-specific admin API that manages centralized capability
 * registration.
 *
 * <p>
 * Spec sections covered:
 * <ul>
 * <li>§2.12 Capabilities — capability object shape, required fields ({@code name},
 * {@code description}), optional fields ({@code location}, {@code input}, {@code output}):
 * <a href="https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities">
 * §2.12</a></li>
 * <li>§2.14 Capability Naming — {@code name} must match {@code [a-z0-9_]+}, snake_case, opaque at
 * protocol layer:
 * <a href="https://agent-auth-protocol.com/specification/v1.0-draft#214-capability-naming">
 * §2.14</a></li>
 * <li>§5.2 List Capabilities — registration precondition for capabilities appearing in the public
 * listing: <a href="https://agent-auth-protocol.com/specification/v1.0-draft#52-list-capabilities">
 * §5.2</a></li>
 * <li>Capability fields reference:
 * <a href="https://agent-auth-protocol.com/docs/capabilities#capability-fields">
 * capability-fields</a></li>
 * <li>Capability location field:
 * <a href="https://agent-auth-protocol.com/docs/capabilities#capability-location">
 * capability-location</a></li>
 * <li>Capability naming rules:
 * <a href="https://agent-auth-protocol.com/docs/capabilities#capability-naming">
 * capability-naming</a></li>
 * </ul>
 *
 * <p>
 * The tests below also include a few historical TODO-shaped methods that now serve as direct
 * executable coverage for additional spec behavior.
 */
class AgentAuthAdminCapabilityRegistrationIT extends BaseKeycloakIT {

  /**
   * Verifies that a Keycloak admin can register a new capability with all required and optional
   * fields, and that the server responds with HTTP 201 and echoes back the registered values.
   *
   * <p>
   * Per §2.12, a capability object must carry a stable {@code name}, a human-readable
   * {@code description}, and an optional {@code location} URL against which the JWT {@code aud}
   * claim is validated during execution.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities"> §2.12
   *      Capabilities</a>
   * @see <a href="https://agent-auth-protocol.com/docs/capabilities#capability-fields"> Capability
   *      Fields</a>
   * @see <a href="https://agent-auth-protocol.com/docs/capabilities#capability-location">
   *      Capability Location</a>
   */
  @Test
  void adminCanRegisterCapability() {
    String name = "admin_capability_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Admin registered capability",
              "visibility": "public",
              "requires_approval": false,
              "location": "https://resource.example.test/capabilities/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, name, name))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201)
        .body("name", equalTo(name))
        .body("description", equalTo("Admin registered capability"))
        .body("location", equalTo("https://resource.example.test/capabilities/" + name));
  }

  /**
   * Verifies that registering two capabilities with the same {@code name} is rejected with HTTP 409
   * and an {@code error} of {@code capability_exists}.
   *
   * <p>
   * Per §2.12, the {@code name} is a stable, unique identifier within the realm. Allowing duplicate
   * names would break the contract that clients treat the name as an opaque but globally unique
   * reference.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities"> §2.12
   *      Capabilities</a>
   * @see <a href="https://agent-auth-protocol.com/docs/capabilities#capability-naming"> Capability
   *      Naming</a>
   */
  @Test
  void duplicateCapabilityNameReturns409() {
    String name = "duplicate_capability_" + UUID.randomUUID().toString().replace("-", "")
        .substring(0, 8);
    String token = adminAccessToken();

    String request = String.format("""
        {
          "name": "%s",
          "description": "Duplicate capability",
          "visibility": "authenticated",
          "requires_approval": false,
          "location": "https://resource.example.test/capabilities/%s",
          "input": {"type": "object"},
          "output": {"type": "object"}
        }
        """, name, name);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(request)
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(request)
        .when()
        .post("/capabilities")
        .then()
        .statusCode(409)
        .body("error", equalTo("capability_exists"))
        .body("message", notNullValue());
  }

  /**
   * Verifies that a registration request omitting the required {@code name} field is rejected with
   * HTTP 400 and an {@code error} of {@code invalid_request}.
   *
   * <p>
   * Per §2.12, {@code name} and {@code description} are required fields on every capability object.
   * A server must reject payloads that are missing required fields rather than silently defaulting
   * them.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities"> §2.12
   *      Capabilities</a>
   * @see <a href="https://agent-auth-protocol.com/docs/capabilities#capability-fields"> Capability
   *      Fields</a>
   */
  @Test
  void invalidCapabilityRegistrationPayloadReturns400() {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body("""
            {
              "description": "Missing name and location"
            }
            """)
        .when()
        .post("/capabilities")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"))
        .body("message", notNullValue());
  }

  /**
   * Verifies that providing an unrecognised {@code visibility} value (e.g. {@code "private"}) is
   * rejected with HTTP 400 and an {@code error} of {@code invalid_request}.
   *
   * <p>
   * Per §2.12 and the capability-fields reference, the only valid visibility values are
   * {@code "public"} and {@code "authenticated"}. Any other value must be treated as a malformed
   * request.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities"> §2.12
   *      Capabilities</a>
   * @see <a href="https://agent-auth-protocol.com/docs/capabilities#capability-fields"> Capability
   *      Fields</a>
   */
  @Test
  void invalidVisibilityValueReturns400() {
    String name = "invalid_visibility_capability_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Invalid visibility test",
              "visibility": "private",
              "requires_approval": false,
              "location": "https://resource.example.test/capabilities/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, name, name))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"))
        .body("message", notNullValue());
  }

  /**
   * Verifies that the admin capability registration endpoint requires a valid admin bearer token,
   * returning HTTP 401 when the request is made without any {@code Authorization} header.
   *
   * <p>
   * Per §5.2, endpoints that mutate server state must enforce authentication. An unauthenticated
   * request to register a capability must be rejected with {@code 401 Unauthorized} so that
   * arbitrary callers cannot pollute the capability catalog.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#52-list-capabilities">
   *      §5.2 List Capabilities</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities"> §2.12
   *      Capabilities</a>
   */
  @Test
  void adminCapabilityRegistrationRequiresAdminAuth() {
    given()
        .baseUri(adminApiUrl())
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "unauthorized_capability",
              "description": "No admin token",
              "location": "https://resource.example.test/capabilities/unauthorized_capability"
            }
            """)
        .when()
        .post("/capabilities")
        .then()
        .statusCode(401);
  }

  // ---------------------------------------------------------------------------
  // TODO stubs — spec requirements not yet covered by implemented tests
  // ---------------------------------------------------------------------------

  /**
   * TODO: Verify that {@code input} and {@code output} JSON Schema objects provided at registration
   * are stored verbatim and returned unchanged in the capability response body.
   *
   * <p>
   * Per §2.12, the {@code input} and {@code output} fields carry JSON Schema definitions that
   * agents use to understand execution parameters and response shape. Round-tripping fidelity is
   * required so agents can rely on the schemas they discover.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities"> §2.12
   *      Capabilities</a>
   * @see <a href="https://agent-auth-protocol.com/docs/capabilities#capability-fields"> Capability
   *      Fields</a>
   */
  @Test
  void inputOutputSchemasRoundTripped() {
    String name = "schema_cap_" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format(
            """
                {
                  "name": "%s",
                  "description": "Schema round-trip capability",
                  "visibility": "public",
                  "requires_approval": false,
                  "location": "https://resource.example.test/capabilities/%s",
                  "input": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
                  "output": {"type": "object", "properties": {"result": {"type": "string"}}}
                }
                """,
            name, name))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    given()
        .baseUri(realmUrl() + "/agent-auth")
        .when()
        .get("/capability/describe?name=" + name)
        .then()
        .statusCode(200)
        .body("input.type", equalTo("object"))
        .body("input.properties.query.type", equalTo("string"))
        .body("output.type", equalTo("object"))
        .body("output.properties.result.type", equalTo("string"));
  }

  /**
   * TODO: Verify that a capability {@code name} containing characters outside {@code [a-z0-9_]+}
   * (e.g. uppercase letters, hyphens, or spaces) is rejected with HTTP 400.
   *
   * <p>
   * Per §2.14, capability names should only include lowercase ASCII alphanumeric characters and
   * underscores. The server must enforce this constraint at registration time so that names remain
   * opaque, stable, and portable identifiers.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#214-capability-naming">
   *      §2.14 Capability Naming</a>
   * @see <a href="https://agent-auth-protocol.com/docs/capabilities#capability-naming"> Capability
   *      Naming</a>
   */
  @Test
  void invalidCapabilityNamePatternReturns400() {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "MyCapability-v2",
              "description": "Invalid name pattern",
              "visibility": "public",
              "requires_approval": false,
              "location": "https://resource.example.test/capabilities/MyCapability-v2"
            }
            """)
        .when()
        .post("/capabilities")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"))
        .body("message", notNullValue());
  }

  /**
   * TODO: Verify that a capability registered with {@code visibility: "public"} appears in the
   * unauthenticated {@code GET /capability/list} response.
   *
   * <p>
   * Per §5.2, servers must return public capabilities to unauthenticated callers. Confirming this
   * end-to-end ensures that admin registration and the discovery listing are correctly linked.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#52-list-capabilities">
   *      §5.2 List Capabilities</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities"> §2.12
   *      Capabilities</a>
   */
  @Test
  void publicCapabilityAppearsInUnauthenticatedListing() {
    String name = "pub_list_cap_" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format(
            """
                {
                  "name": "%s",
                  "description": "Public listing test capability",
                  "visibility": "public",
                  "requires_approval": false,
                  "location": "https://resource.example.test/capabilities/%s"
                }
                """,
            name, name))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    given()
        .baseUri(realmUrl() + "/agent-auth")
        .when()
        .get("/capability/list")
        .then()
        .statusCode(200)
        .body("capabilities.name", hasItem(name));
  }

  /**
   * TODO: Verify that a capability registered with {@code visibility: "authenticated"} does NOT
   * appear in the unauthenticated {@code GET /capability/list} response.
   *
   * <p>
   * Per §5.2, unauthenticated requests must only receive public capabilities. Authenticated-only
   * capabilities must be withheld to avoid leaking the existence of restricted functionality.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#52-list-capabilities">
   *      §5.2 List Capabilities</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities"> §2.12
   *      Capabilities</a>
   */
  @Test
  void authenticatedCapabilityHiddenFromUnauthenticatedListing() {
    String name = "auth_hidden_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format(
            """
                {
                  "name": "%s",
                  "description": "Authenticated-only capability hidden from unauthenticated listing",
                  "visibility": "authenticated",
                  "requires_approval": false,
                  "location": "https://resource.example.test/capabilities/%s"
                }
                """,
            name, name))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    given()
        .baseUri(realmUrl() + "/agent-auth")
        .when()
        .get("/capability/list")
        .then()
        .statusCode(200)
        .body("capabilities.name", not(hasItem(name)));
  }

  /**
   * TODO: Verify that a registered capability can be updated (e.g. description changed) via an
   * admin PUT or PATCH request and that the updated fields are reflected in subsequent responses.
   *
   * <p>
   * Per §2.12, servers may rename or update capabilities. The admin API should provide a mutation
   * endpoint so operators can correct metadata without deleting and re-registering.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities"> §2.12
   *      Capabilities</a>
   * @see <a href="https://agent-auth-protocol.com/docs/capabilities#capability-fields"> Capability
   *      Fields</a>
   */
  @Test
  void adminCanUpdateRegisteredCapability() {
    String name = "update_cap_" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    String token = adminAccessToken();

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Original description",
              "visibility": "public",
              "requires_approval": false,
              "location": "https://resource.example.test/capabilities/%s"
            }
            """, name, name))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Updated description",
              "visibility": "public",
              "requires_approval": false,
              "location": "https://resource.example.test/capabilities/%s"
            }
            """, name, name))
        .when()
        .put("/capabilities/" + name)
        .then()
        .statusCode(200)
        .body("description", equalTo("Updated description"));

    given()
        .baseUri(realmUrl() + "/agent-auth")
        .when()
        .get("/capability/describe?name=" + name)
        .then()
        .statusCode(200)
        .body("description", equalTo("Updated description"));
  }

  /**
   * TODO: Verify that a registered capability can be deleted via an admin DELETE request and
   * subsequently disappears from the capability listing.
   */
  @Test
  void adminCanDeleteRegisteredCapability() {
    String name = "delete_cap_" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    String token = adminAccessToken();

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Capability to be deleted",
              "visibility": "public",
              "requires_approval": false,
              "location": "https://resource.example.test/capabilities/%s"
            }
            """, name, name))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + token)
        .when()
        .delete("/capabilities/" + name)
        .then()
        .statusCode(204);

    given()
        .baseUri(realmUrl() + "/agent-auth")
        .when()
        .get("/capability/describe?name=" + name)
        .then()
        .statusCode(404);
  }

  /**
   * Verifies that the {@code location} URL stored during registration is echoed back in the
   * capability response body.
   */
  @Test
  void locationFieldRoundTrippedAndUsedAsJwtAud() {
    String name = "location_round_trip_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Location round-trip capability",
              "visibility": "public",
              "requires_approval": false,
              "location": "https://resource.example.test/capabilities/%s",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, name, name))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    given()
        .baseUri(realmUrl() + "/agent-auth")
        .queryParam("name", name)
        .when()
        .get("/capability/describe")
        .then()
        .statusCode(200)
        .body("location", equalTo("https://resource.example.test/capabilities/" + name));
  }

  @Test
  void registerCapabilityWithNullNameReturns400() {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body("""
            {
              "description": "Missing name",
              "visibility": "public",
              "requires_approval": false,
              "location": "https://resource.example.test/capabilities/no_name"
            }
            """)
        .when()
        .post("/capabilities")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  @Test
  void registerCapabilityWithoutLocationIsAccepted() {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "no_location_cap",
              "description": "Missing location",
              "visibility": "public",
              "requires_approval": false
            }
            """)
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201)
        .body("name", equalTo("no_location_cap"));
  }

  @Test
  void registerCapabilityWithEmptyNameReturns400() {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "",
              "description": "Empty name",
              "visibility": "public",
              "requires_approval": false,
              "location": "https://resource.example.test/capabilities/empty"
            }
            """)
        .when()
        .post("/capabilities")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  /**
   * Verifies that attempting to DELETE a capability name that was never registered returns HTTP
   * 404.
   *
   * <p>
   * Per §2.12, the server must distinguish between a successful deletion and a request targeting a
   * name that does not exist.
   */
  @Test
  void deleteNonexistentCapabilityReturns404() {
    String name = "nonexistent_del_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .delete("/capabilities/" + name)
        .then()
        .statusCode(404);
  }

  /**
   * Verifies that attempting to PUT a capability name that was never registered returns HTTP 404.
   *
   * <p>
   * Per §2.12, an update to a nonexistent capability is not a registration — it must not create a
   * new entry silently. The server must return 404 to indicate the target resource does not exist.
   */
  @Test
  void updateNonexistentCapabilityReturns404() {
    String name = "nonexistent_upd_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Updated description for nonexistent capability",
              "visibility": "public",
              "requires_approval": false,
              "location": "https://resource.example.test/capabilities/%s"
            }
            """, name, name))
        .when()
        .put("/capabilities/" + name)
        .then()
        .statusCode(404);
  }

  /**
   * Verifies that a DELETE request without an Authorization header is rejected with HTTP 401.
   *
   * <p>
   * Per §5.2, endpoints that mutate server state must enforce authentication. An unauthenticated
   * caller must not be able to remove capabilities from the catalog.
   */
  @Test
  void deleteCapabilityWithoutAdminAuthReturns401() {
    given()
        .baseUri(adminApiUrl())
        .when()
        .delete("/capabilities/some_capability")
        .then()
        .statusCode(401);
  }

  /**
   * Verifies that a PUT request without an Authorization header is rejected with HTTP 401.
   *
   * <p>
   * Per §5.2, endpoints that mutate server state must enforce authentication. An unauthenticated
   * caller must not be able to modify capability metadata.
   */
  @Test
  void updateCapabilityWithoutAdminAuthReturns401() {
    given()
        .baseUri(adminApiUrl())
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "some_capability",
              "description": "Unauthorized update attempt",
              "visibility": "public",
              "requires_approval": false,
              "location": "https://resource.example.test/capabilities/some_capability"
            }
            """)
        .when()
        .put("/capabilities/some_capability")
        .then()
        .statusCode(401);
  }

  /**
   * Verifies that after deleting a public capability it no longer appears in the unauthenticated
   * {@code GET /capability/list} response.
   *
   * <p>
   * Per §5.2, the public listing must only reflect currently registered capabilities. A deleted
   * capability must be removed from the listing immediately so agents do not discover stale
   * entries.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#52-list-capabilities">
   *      §5.2 List Capabilities</a>
   */
  @Test
  void deletedCapabilityDoesNotAppearInList() {
    String name = "deleted_pub_cap_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    String token = adminAccessToken();

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Public capability to be deleted",
              "visibility": "public",
              "requires_approval": false,
              "location": "https://resource.example.test/capabilities/%s"
            }
            """, name, name))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + token)
        .when()
        .delete("/capabilities/" + name)
        .then()
        .statusCode(204);

    given()
        .baseUri(realmUrl() + "/agent-auth")
        .when()
        .get("/capability/list")
        .then()
        .statusCode(200)
        .body("capabilities.name", not(hasItem(name)));
  }
}
