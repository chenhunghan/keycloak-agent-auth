package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.chh.keycloak.agentauth.support.BaseKeycloakIT;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Integration tests for the Agent Auth Protocol discovery endpoint
 * ({@code GET /.well-known/agent-configuration}).
 *
 * <p>
 * In our Keycloak integration this endpoint is mounted at:
 * {@code /realms/{realm}/.well-known/agent-configuration} via the WellKnownProvider SPI.
 *
 * <h2>Spec sections covered</h2>
 * <ul>
 * <li>§5.1 Discovery — endpoint location, required response fields, unauthenticated access,
 * caching: {@code https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery}</li>
 * <li>§5.1.1 Versioning — version string format, major-version enforcement:
 * {@code https://agent-auth-protocol.com/specification/v1.0-draft#511-versioning}</li>
 * <li>Configuration Fields reference:
 * {@code https://agent-auth-protocol.com/docs/discovery#configuration-fields}</li>
 * <li>Versioning reference: {@code https://agent-auth-protocol.com/docs/discovery#versioning}</li>
 * </ul>
 *
 * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
 *      Discovery</a>
 * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-versioning">§5.1.1
 *      Versioning</a>
 * @see <a href="https://agent-auth-protocol.com/docs/discovery">Discovery docs</a>
 */
class AgentAuthDiscoveryIT extends BaseKeycloakIT {

  /**
   * The discovery response MUST include a {@code version} field identifying the protocol version,
   * and for this implementation it MUST equal {@code "1.0-draft"}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
   *      Discovery — required response fields</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-versioning">§5.1.1
   *      Versioning — version field semantics</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/discovery#configuration-fields">Configuration Fields
   *      — version</a>
   */
  @Test
  void discoveryEndpointReturnsProtocolVersion() {
    given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .contentType("application/json")
        .body("version", equalTo("1.0-draft"));
  }

  /**
   * The discovery response MUST include a {@code provider_name} field containing the unique
   * provider identifier for the authorization server.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
   *      Discovery — required response fields</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/discovery#configuration-fields">Configuration Fields
   *      — provider_name</a>
   */
  @Test
  void discoveryEndpointReturnsProviderName() {
    given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .body("provider_name", notNullValue());
  }

  /**
   * The discovery response MUST include a {@code description} field containing a human-readable
   * description of the service.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
   *      Discovery — required response fields</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/discovery#configuration-fields">Configuration Fields
   *      — description</a>
   */
  @Test
  void discoveryEndpointReturnsDescription() {
    given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .body("description", notNullValue());
  }

  /**
   * The discovery response MUST include an {@code issuer} field whose value is the base URL of the
   * authorization server; for Keycloak this MUST contain the realm path segment.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
   *      Discovery — required response fields</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/discovery#configuration-fields">Configuration Fields
   *      — issuer</a>
   */
  @Test
  void discoveryEndpointReturnsIssuerMatchingRealmUrl() {
    given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .body("issuer", containsString("/realms/" + REALM));
  }

  /**
   * The discovery response MUST include an {@code algorithms} array, and Ed25519 MUST be the first
   * (and only currently defined) algorithm; conformant servers MUST support it.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
   *      Discovery — algorithms field</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/discovery#configuration-fields">Configuration Fields
   *      — algorithms</a>
   */
  @Test
  void discoveryEndpointReturnsEd25519Algorithm() {
    given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .body("algorithms[0]", equalTo("Ed25519"));
  }

  /**
   * The discovery response MUST include a non-empty {@code modes} array listing at least one
   * supported agent interaction mode ({@code delegated} or {@code autonomous}).
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
   *      Discovery — modes field</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/discovery#configuration-fields">Configuration Fields
   *      — modes</a>
   */
  @Test
  void discoveryEndpointReturnsAtLeastOneSupportedMode() {
    given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .body("modes.size()", greaterThanOrEqualTo(1));
  }

  /**
   * The discovery response MUST include an {@code approval_methods} array listing the
   * human-approval flows supported by this server.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
   *      Discovery — approval_methods field</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/discovery#configuration-fields">Configuration Fields
   *      — approval_methods</a>
   */
  @Test
  void discoveryEndpointReturnsApprovalMethodsArray() {
    given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .body("approval_methods", notNullValue());
  }

  /**
   * The discovery response MUST include an {@code endpoints} object containing all required
   * protocol endpoint paths ({@code register}, {@code capabilities}, {@code describe_capability},
   * {@code execute}, {@code request_capability}, {@code status}, {@code reactivate},
   * {@code revoke}, {@code revoke_host}, {@code rotate_key}, {@code rotate_host_key},
   * {@code introspect}).
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
   *      Discovery — endpoints field</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/discovery#configuration-fields">Configuration Fields
   *      — endpoints</a>
   */
  @Test
  void discoveryEndpointReturnsProtocolEndpointMap() {
    given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .body("endpoints", hasKey("register"))
        .body("endpoints.register", notNullValue())
        .body("endpoints.capabilities", notNullValue())
        .body("endpoints.describe_capability", notNullValue())
        .body("endpoints.execute", notNullValue())
        .body("endpoints.request_capability", notNullValue())
        .body("endpoints.status", notNullValue())
        .body("endpoints.reactivate", notNullValue())
        .body("endpoints.revoke", notNullValue())
        .body("endpoints.revoke_host", notNullValue())
        .body("endpoints.rotate_key", notNullValue())
        .body("endpoints.rotate_host_key", notNullValue())
        .body("endpoints.introspect", notNullValue());
  }

  /**
   * The discovery response MUST include a {@code default_location} field indicating the server's
   * default agent registration location.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
   *      Discovery — required response fields</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/discovery#configuration-fields">Configuration
   *      Fields</a>
   */
  @Test
  void discoveryEndpointReturnsDefaultLocation() {
    given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .body("default_location", notNullValue());
  }

  /**
   * The {@code issuer} field in the discovery response MUST exactly equal the canonical base URL of
   * the authorization server (i.e. the full realm URL with no trailing slash variation).
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
   *      Discovery — issuer field</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/discovery#configuration-fields">Configuration Fields
   *      — issuer</a>
   */
  @Test
  void discoveryEndpointReturnsExactIssuerUrl() {
    given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .body("issuer", equalTo(issuerUrl()));
  }

  /**
   * The discovery endpoint MUST be accessible without authentication; no credentials or tokens are
   * required to retrieve the server configuration document.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
   *      Discovery — unauthenticated access</a>
   * @see <a href="https://agent-auth-protocol.com/docs/discovery">Discovery docs</a>
   */
  @Test
  void discoveryEndpointAllowsUnauthenticatedAccess() {
    // Per spec: "No authentication required" for discovery
    given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200);
  }

  /**
   * The {@code modes} array MUST advertise both {@code "delegated"} and {@code "autonomous"} when
   * the server supports the full Agent Auth Protocol feature set.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
   *      Discovery — modes field</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/discovery#configuration-fields">Configuration Fields
   *      — modes (valid values: delegated, autonomous)</a>
   */
  @Test
  void discoveryEndpointAdvertisesBothAgentModes() {
    given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .body("modes", hasItems("delegated", "autonomous"));
  }

  /**
   * The {@code approval_methods} array MUST contain at least one supported method. In addition to
   * the spec-defined device authorization and CIBA methods, §5.1 permits custom extension methods;
   * this implementation advertises admin-mediated HTTP approval as {@code "admin"}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
   *      Discovery — approval_methods field</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/discovery#configuration-fields">Configuration Fields
   *      — approval_methods</a>
   */
  @Test
  void discoveryEndpointAdvertisesApprovalMethodValues() {
    given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .body("approval_methods", hasItem(equalTo("admin")));
  }

  /**
   * Servers SHOULD include a {@code Cache-Control} header on the discovery response; a
   * {@code max-age} of 3600 seconds is RECOMMENDED for most deployments.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
   *      Discovery — Cache-Control SHOULD / max-age=3600 RECOMMENDED</a>
   * @see <a href="https://agent-auth-protocol.com/docs/discovery">Discovery docs — caching</a>
   */
  @Test
  void discoveryEndpointReturnsCacheControlHeader() {
    // Per spec: Servers SHOULD include Cache-Control headers, max-age of 3600 is RECOMMENDED.
    given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .header("Cache-Control", containsString("max-age=3600"));
  }

  /**
   * The discovery response MAY include an optional {@code jwks_uri} field for server-signed
   * responses. This implementation does not sign responses, so it MUST NOT advertise a placeholder
   * server JWKS.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
   *      Discovery — optional fields</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/discovery#configuration-fields">Configuration Fields
   *      — jwks_uri (optional)</a>
   */
  @Test
  void discoveryEndpointOmitsServerJwksUriWhenResponsesAreUnsigned() {
    given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .body("jwks_uri", nullValue());
  }

  // ---------------------------------------------------------------------------
  // Spec compliance tests — filled from TODO stubs
  // ---------------------------------------------------------------------------

  /**
   * The {@code version} field MUST conform to the {@code MAJOR.MINOR[-label]} format defined by
   * §5.1.1; values that deviate from this pattern are non-conformant and clients MUST reject them.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-versioning">§5.1.1
   *      Versioning — version string format (MAJOR.MINOR with optional -draft suffix)</a>
   * @see <a href="https://agent-auth-protocol.com/docs/discovery#versioning">Versioning docs —
   *      format</a>
   */
  @Test
  void todoVersionFieldConformsToMajorMinorFormat() {
    // Per spec §5.1.1: version MUST be MAJOR.MINOR[-label] where MAJOR and MINOR are integers.
    String version = given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .extract()
        .path("version");
    assertTrue(version.matches("\\d+\\.\\d+(-[a-zA-Z0-9]+)?"),
        "version must match MAJOR.MINOR[-label] but was: " + version);
  }

  /**
   * When a client encounters a discovery document whose major version is not supported, the client
   * MUST stop and report the incompatibility rather than proceeding with an incompatible server.
   * From the server side, this means the server MUST advertise major version 1 (the only currently
   * defined major version).
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-versioning">§5.1.1
   *      Versioning — client MUST stop on unsupported major version</a>
   * @see <a href="https://agent-auth-protocol.com/docs/discovery#versioning">Versioning docs —
   *      major version mismatch</a>
   */
  @Test
  void todoClientMustRejectUnsupportedMajorVersion() {
    // Per spec §5.1.1: clients MUST stop on unsupported major version. The server MUST advertise
    // major version 1 — the only currently defined major version — so conformant clients can
    // proceed. A version starting with anything other than "1." would be a breaking change.
    String version = given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .extract()
        .path("version");
    assertTrue(version.startsWith("1."),
        "server must advertise major version 1 but was: " + version);
  }

  /**
   * The {@code algorithms} array MUST contain Ed25519 (the only algorithm defined in the current
   * spec), and the array MUST NOT be empty; conformant servers MUST support Ed25519.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
   *      Discovery — algorithms MUST include Ed25519</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/discovery#configuration-fields">Configuration Fields
   *      — algorithms (only Ed25519 is defined)</a>
   */
  @Test
  void todoAlgorithmsArrayContainsEd25519AndIsNonEmpty() {
    // Per spec: algorithms array MUST be non-empty and MUST contain "Ed25519".
    given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .body("algorithms.size()", greaterThanOrEqualTo(1))
        .body("algorithms", hasItem(equalTo("Ed25519")));
  }

  /**
   * Every value in the {@code modes} array MUST be one of the spec-defined strings
   * ({@code "delegated"}, {@code "autonomous"}); no implementation-defined or unknown modes are
   * permitted in a conformant response.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
   *      Discovery — modes valid values</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/discovery#configuration-fields">Configuration Fields
   *      — modes</a>
   */
  @Test
  void todoModesArrayContainsOnlySpecDefinedValues() {
    // Per spec: modes values are restricted to "delegated" and "autonomous".
    List<String> modes = given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .extract()
        .path("modes");
    for (String mode : modes) {
      assertTrue(mode.equals("delegated") || mode.equals("autonomous"),
          "Unexpected mode value: " + mode);
    }
  }

  /**
   * Every value in the {@code approval_methods} array MUST be either one of the spec-defined
   * strings or a custom extension method. This implementation intentionally supports only the
   * custom admin-mediated method.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
   *      Discovery — approval_methods valid values</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/discovery#configuration-fields">Configuration Fields
   *      — approval_methods</a>
   */
  @Test
  void todoApprovalMethodsArrayContainsOnlySupportedValues() {
    List<String> methods = given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .extract()
        .path("approval_methods");
    for (String method : methods) {
      // §5.1 core values are "device_authorization" and "ciba"; this server additionally exposes
      // the "admin" extension method for admin-mediated capability approvals.
      assertTrue(
          method.equals("device_authorization") || method.equals("ciba")
              || method.equals("admin"),
          "Unexpected approval_method value: " + method);
    }
  }

  /**
   * The discovery response MUST be served with {@code Content-Type: application/json} so that
   * clients can unambiguously parse the configuration document.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
   *      Discovery — response format</a>
   * @see <a href="https://agent-auth-protocol.com/docs/discovery">Discovery docs</a>
   */
  @Test
  void todoDiscoveryResponseContentTypeIsApplicationJson() {
    // Per spec: the discovery response MUST be Content-Type: application/json.
    given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .header("Content-Type", containsString("application/json"));
  }

  /**
   * Clients SHOULD ignore unrecognized fields in the discovery response to ensure forward
   * compatibility as the protocol evolves; the server MUST NOT require clients to understand
   * extension fields.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-versioning">§5.1.1
   *      Versioning — clients SHOULD ignore unrecognized fields</a>
   * @see <a href="https://agent-auth-protocol.com/docs/discovery#versioning">Versioning docs —
   *      forward compatibility</a>
   */
  @Test
  @SuppressWarnings("unchecked")
  void todoDiscoveryResponseWithExtraFieldsDoesNotBreakParsing() {
    // Per spec §5.1.1: clients MUST ignore unrecognized fields for forward compatibility.
    // Verify the response can be parsed as a generic Map (simulating a client that only reads
    // known fields) and that all required fields are present regardless of any extra fields.
    Map<String, Object> config = given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .extract()
        .as(Map.class);
    assertNotNull(config.get("version"), "required field 'version' must be present");
    assertNotNull(config.get("issuer"), "required field 'issuer' must be present");
  }

  // ---------------------------------------------------------------------------
  // Zero-coverage gap tests
  // ---------------------------------------------------------------------------

  /**
   * The spec mandates Ed25519 as the first entry in the {@code algorithms} array so that conformant
   * clients can assume index 0 is always the primary algorithm without scanning the full list.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
   *      Discovery — algorithms MUST list Ed25519 first</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/discovery#configuration-fields">Configuration Fields
   *      — algorithms</a>
   */
  @Test
  void discoveryAlgorithmsArrayHasEd25519First() {
    // Per spec: Ed25519 MUST be the first entry in the algorithms array.
    List<String> algorithms = given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .extract()
        .path("algorithms");
    assertFalse(algorithms.isEmpty(), "algorithms array must not be empty");
    assertEquals("Ed25519", algorithms.get(0),
        "Ed25519 must be the first entry in the algorithms array");
  }

  /**
   * Every URL in the {@code endpoints} map MUST be a valid absolute path (starting with {@code /})
   * so that clients can construct fully-qualified endpoint URLs by prepending the issuer base URL;
   * garbage or empty values would silently produce broken requests.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
   *      Discovery — endpoints field</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/discovery#configuration-fields">Configuration Fields
   *      — endpoints</a>
   */
  @Test
  @SuppressWarnings("unchecked")
  void discoveryEndpointUrlsPointToValidPaths() {
    // Each endpoint value must be a non-empty path starting with "/" so that clients can
    // safely prefix it with the issuer URL to form a fully-qualified request URL.
    Map<String, Object> config = given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .extract()
        .as(Map.class);
    Map<String, String> endpoints = (Map<String, String>) config.get("endpoints");
    assertNotNull(endpoints, "endpoints map must be present");
    assertFalse(endpoints.isEmpty(), "endpoints map must not be empty");
    for (Map.Entry<String, String> entry : endpoints.entrySet()) {
      String path = entry.getValue();
      assertNotNull(path, "endpoint '" + entry.getKey() + "' must not be null");
      assertFalse(path.isBlank(), "endpoint '" + entry.getKey() + "' must not be blank");
      assertTrue(path.startsWith("/"),
          "endpoint '" + entry.getKey() + "' must be an absolute path starting with '/' but was: "
              + path);
    }
  }

  // ---------------------------------------------------------------------------
  // Server JWKS publication tests — §5.1 Discovery
  // ---------------------------------------------------------------------------

  /**
   * Since this implementation does not sign protocol responses, §5.1 does not require a server
   * {@code jwks_uri}. The old placeholder JWKS endpoint must remain unpublished.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
   *      Discovery — jwks_uri</a>
   */
  @Test
  void discoveryDoesNotAdvertiseServerJwksUriWithoutServerSigning() {
    given()
        .baseUri(realmUrl())
        .when()
        .get("/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .body("jwks_uri", nullValue());
  }

  /**
   * The removed placeholder server JWKS endpoint should not be reachable directly.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#51-discovery">§5.1
   *      Discovery — jwks_uri</a>
   */
  @Test
  void serverJwksEndpointIsNotPublishedWithoutServerSigning() {
    given()
        .baseUri(issuerUrl())
        .when()
        .get("/jwks")
        .then()
        .statusCode(404);
  }
}
