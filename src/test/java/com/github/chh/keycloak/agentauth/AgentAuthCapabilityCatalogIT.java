package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import com.github.chh.keycloak.agentauth.support.BaseKeycloakIT;
import com.github.chh.keycloak.agentauth.support.TestJwts;
import com.github.chh.keycloak.agentauth.support.TestKeys;
import com.nimbusds.jose.jwk.OctetKeyPair;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Integration tests for the capability discovery endpoints ({@code GET /capability/list} and
 * {@code GET /capability/describe}) backed by Keycloak's centralized capability registry.
 *
 * <p>
 * Spec sections covered:
 * <ul>
 * <li>§2.12 Capabilities — core fields, visibility, grant_status semantics {@link <a href=
 * "https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities">§2.12</a>}
 * <li>§2.14 Capability Naming — {@code [a-z0-9_]+} snake_case format, opaque-identifier rule
 * {@link <a href=
 * "https://agent-auth-protocol.com/specification/v1.0-draft#214-capability-naming">§2.14</a>}
 * <li>§5.2 List Capabilities — public unauthenticated / host-JWT / agent-JWT response variants,
 * {@code query} / {@code cursor} / {@code limit} parameters, {@code next_cursor} / {@code has_more}
 * pagination fields {@link <a href=
 * "https://agent-auth-protocol.com/specification/v1.0-draft#52-list-capabilities">§5.2</a>}
 * <li>§5.2.1 Describe Capability — {@code name} query parameter, full schema fields, 404
 * {@code capability_not_found}, 400 {@code invalid_request} {@link <a href=
 * "https://agent-auth-protocol.com/specification/v1.0-draft#521-describe-capability">§5.2.1</a>}
 * <li>Capabilities doc — field reference, constraint operators, pagination cursor semantics
 * {@link <a href="https://agent-auth-protocol.com/docs/capabilities">capabilities doc</a>}
 * </ul>
 *
 * <p>
 * These tests exercise the public, authenticated, and paginated catalog views that the current
 * implementation exposes.
 */
class AgentAuthCapabilityCatalogIT extends BaseKeycloakIT {

  private static String publicCapability;
  private static String authenticatedCapability;
  private static OctetKeyPair hostKey;
  private static OctetKeyPair agentKey;
  private static String agentId;

  @BeforeAll
  static void setUpCatalog() {
    String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    publicCapability = "public_balance_" + suffix;
    authenticatedCapability = "private_transfer_" + suffix;

    registerCapability(publicCapability, "Public balance lookup", "public", false);
    registerCapability(authenticatedCapability, "Private transfer", "authenticated", false);

    hostKey = TestKeys.generateEd25519();
    agentKey = TestKeys.generateEd25519();
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl());

    agentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Catalog Agent",
              "host_name": "catalog-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "Capability catalog test"
            }
            """, authenticatedCapability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");
  }

  private static void registerCapability(
      String name, String description, String visibility, boolean requiresApproval) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "%s",
              "visibility": "%s",
              "requires_approval": %s,
              "location": "https://resource.example.test/capabilities/%s",
              "input": {
                "type": "object",
                "required": ["account_id"],
                "properties": {
                  "account_id": {"type": "string"}
                }
              },
              "output": {
                "type": "object",
                "properties": {
                  "balance": {"type": "number"}
                }
              }
            }
            """, name, description, visibility, requiresApproval, name))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);
  }

  /**
   * Verifies that an unauthenticated {@code GET /capability/list} request returns only capabilities
   * whose visibility is {@code public} and omits the {@code grant_status} field, as required when
   * no authentication is supplied.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#52-list-capabilities">§5.2 List
   *      Capabilities — unauthenticated mode</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities">§2.12
   *      Capabilities — visibility semantics</a>
   */
  @Test
  void listCapabilitiesWithoutAuthReturnsOnlyPublicCapabilities() {
    given()
        .baseUri(issuerUrl())
        .when()
        .get("/capability/list")
        .then()
        .statusCode(200)
        .body("capabilities.name", hasItem(publicCapability))
        .body("capabilities.name", org.hamcrest.Matchers.not(hasItem(authenticatedCapability)))
        .body("capabilities[0].grant_status", nullValue());
  }

  /**
   * Verifies that a {@code GET /capability/list} request authenticated with a host JWT returns all
   * capabilities available to the linked user, including both public and authenticated
   * capabilities, along with their {@code name} and {@code description} fields.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#52-list-capabilities">§5.2 List
   *      Capabilities — host-JWT mode</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities">§2.12
   *      Capabilities — required fields: name, description</a>
   */
  @Test
  void listCapabilitiesWithHostJwtReturnsCapabilityMetadata() {
    String hostJwt = TestJwts.hostJwt(hostKey, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .when()
        .get("/capability/list")
        .then()
        .statusCode(200)
        .body("capabilities.name", hasItems(publicCapability, authenticatedCapability))
        .body("capabilities.description", hasItems("Public balance lookup", "Private transfer"));
  }

  /**
   * Verifies that a {@code GET /capability/list} request authenticated with an agent JWT returns
   * per-capability {@code grant_status} values of {@code "granted"} for capabilities the agent
   * holds and {@code "not_granted"} for those it does not.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#52-list-capabilities">§5.2 List
   *      Capabilities — agent-JWT mode</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities">§2.12
   *      Capabilities — grant_status field</a>
   */
  @Test
  void listCapabilitiesWithAgentJwtReturnsGrantStatusPerCapability() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .when()
        .get("/capability/list")
        .then()
        .statusCode(200)
        .body("capabilities.find { it.name == '" + authenticatedCapability + "' }.grant_status",
            equalTo("granted"))
        .body("capabilities.find { it.name == '" + publicCapability + "' }.grant_status",
            equalTo("not_granted"));
  }

  /**
   * Verifies that {@code GET /capability/describe?name=} returns a capability object containing the
   * required fields {@code name}, {@code description}, {@code input}, and {@code output} (JSON
   * Schema objects), as specified in §5.2.1.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#521-describe-capability">§5.2.1
   *      Describe Capability — response fields</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities">§2.12
   *      Capabilities — input/output schema fields</a>
   * @see <a href="https://agent-auth-protocol.com/docs/capabilities">Capabilities doc — field
   *      reference</a>
   */
  @Test
  void describeCapabilityReturnsSchemas() {
    given()
        .baseUri(issuerUrl())
        .queryParam("name", publicCapability)
        .when()
        .get("/capability/describe")
        .then()
        .statusCode(200)
        .body("name", equalTo(publicCapability))
        .body("description", equalTo("Public balance lookup"))
        .body("input.type", equalTo("object"))
        .body("output.type", equalTo("object"));
  }

  /**
   * Verifies that {@code GET /capability/describe?name=} authenticated with an agent JWT includes a
   * {@code grant_status} of {@code "granted"} for a capability that has been granted to that agent,
   * as specified in §5.2.1.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#521-describe-capability">§5.2.1
   *      Describe Capability — agent-JWT mode and grant_status</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities">§2.12
   *      Capabilities — grant_status field</a>
   */
  @Test
  void describeCapabilityWithAgentJwtReturnsGrantStatus() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .queryParam("name", authenticatedCapability)
        .when()
        .get("/capability/describe")
        .then()
        .statusCode(200)
        .body("name", equalTo(authenticatedCapability))
        .body("grant_status", equalTo("granted"));
  }

  /**
   * Verifies that {@code GET /capability/describe?name=} for an {@code authenticated}-visibility
   * capability without any authorization token returns {@code 403} or {@code 404}, preventing
   * information leakage about non-public capabilities to unauthenticated callers.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#521-describe-capability">§5.2.1
   *      Describe Capability — unauthenticated access to non-public capability</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities">§2.12
   *      Capabilities — visibility semantics</a>
   */
  @Test
  void describeAuthenticatedCapabilityWithoutAuthReturns403Or404() {
    given()
        .baseUri(issuerUrl())
        .queryParam("name", authenticatedCapability)
        .when()
        .get("/capability/describe")
        .then()
        .statusCode(anyOf(equalTo(403), equalTo(404)));
  }

  /**
   * Verifies that {@code GET /capability/describe?name=} with an unknown capability name returns
   * {@code 404} with error code {@code capability_not_found} and a human-readable {@code message},
   * as required by §5.2.1.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#521-describe-capability">§5.2.1
   *      Describe Capability — 404 capability_not_found error</a>
   */
  @Test
  void describeUnknownCapabilityReturns404() {
    given()
        .baseUri(issuerUrl())
        .queryParam("name", "missing_capability")
        .when()
        .get("/capability/describe")
        .then()
        .statusCode(404)
        .body("error", equalTo("capability_not_found"))
        .body("message", notNullValue());
  }

  /**
   * Verifies that {@code GET /capability/describe} with no {@code name} query parameter returns
   * {@code 400} with error code {@code invalid_request} and a human-readable {@code message}, as
   * required by §5.2.1.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#521-describe-capability">§5.2.1
   *      Describe Capability — 400 invalid_request when name is absent</a>
   */
  @Test
  void describeCapabilityWithoutNameReturns400() {
    given()
        .baseUri(issuerUrl())
        .when()
        .get("/capability/describe")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"))
        .body("message", notNullValue());
  }

  /**
   * Verifies that the {@code requires_approval} field is {@code false} in a
   * {@code GET /capability/describe} response for a capability registered without approval
   * requirements, as specified in the capability fields reference.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#521-describe-capability">§5.2.1
   *      Describe Capability — requires_approval field</a>
   * @see <a href="https://agent-auth-protocol.com/docs/capabilities">Capabilities doc —
   *      requires_approval field</a>
   */
  @Test
  void describeCapabilityReturnsRequiresApprovalFalse() {
    given()
        .baseUri(issuerUrl())
        .queryParam("name", publicCapability)
        .when()
        .get("/capability/describe")
        .then()
        .statusCode(200)
        .body("requires_approval", equalTo(false));
  }

  /**
   * Verifies that the {@code requires_approval} field is {@code true} in a
   * {@code GET /capability/describe} response for a capability registered with approval required,
   * as specified in the capability fields reference.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#521-describe-capability">§5.2.1
   *      Describe Capability — requires_approval field</a>
   * @see <a href="https://agent-auth-protocol.com/docs/capabilities">Capabilities doc —
   *      requires_approval field</a>
   */
  @Test
  void describeApprovalRequiredCapabilityReturnsRequiresApprovalTrue() {
    String name = "approval_required_describe_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    registerCapability(name, "Approval required capability", "public", true);

    given()
        .baseUri(issuerUrl())
        .queryParam("name", name)
        .when()
        .get("/capability/describe")
        .then()
        .statusCode(200)
        .body("requires_approval", equalTo(true));
  }

  /**
   * Verifies that {@code GET /capability/list} applies cursor pagination when {@code limit} is
   * provided, returning a {@code next_cursor} token and {@code has_more: true} on the first page,
   * then advancing to the next page without duplicates when the cursor is followed.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#52-list-capabilities">§5.2 List
   *      Capabilities — cursor-based pagination</a>
   * @see <a href="https://agent-auth-protocol.com/docs/capabilities#pagination">Capabilities doc —
   *      pagination</a>
   */
  @Test
  void listCapabilitiesPaginationCursorAdvancesPage() {
    String tag = "pagination_" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    String firstName = tag + "_alpha";
    String secondName = tag + "_beta";
    String thirdName = tag + "_gamma";

    registerCapability(firstName, "Pagination token " + tag + " alpha", "public", false);
    registerCapability(secondName, "Pagination token " + tag + " beta", "public", false);
    registerCapability(thirdName, "Pagination token " + tag + " gamma", "public", false);

    Response firstPage = given()
        .baseUri(issuerUrl())
        .queryParam("query", tag)
        .queryParam("limit", 2)
        .when()
        .get("/capability/list")
        .then()
        .statusCode(200)
        .body("capabilities.size()", equalTo(2))
        .body("has_more", equalTo(true))
        .body("next_cursor", notNullValue())
        .extract()
        .response();

    List<String> firstPageNames = firstPage.path("capabilities.name");
    String nextCursor = firstPage.path("next_cursor");
    assertEquals(Set.of(firstName, secondName), new HashSet<>(firstPageNames));

    Response secondPage = given()
        .baseUri(issuerUrl())
        .queryParam("query", tag)
        .queryParam("cursor", nextCursor)
        .queryParam("limit", 2)
        .when()
        .get("/capability/list")
        .then()
        .statusCode(200)
        .body("capabilities.size()", equalTo(1))
        .body("has_more", equalTo(false))
        .body("next_cursor", nullValue())
        .extract()
        .response();

    List<String> secondPageNames = secondPage.path("capabilities.name");
    assertEquals(Set.of(thirdName), new HashSet<>(secondPageNames));
  }

  /**
   * Verifies that {@code GET /capability/list?query=} filters returned capabilities by the search
   * term and does not leak unrelated capability names.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#52-list-capabilities">§5.2 List
   *      Capabilities — query parameter</a>
   */
  @Test
  void listCapabilitiesQueryParameterFiltersResults() {
    String tag = "query_" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    String matchingName = tag + "_match";
    String unrelatedName = tag + "_other";

    registerCapability(matchingName, "Capability " + tag + " match target", "public", false);
    registerCapability(unrelatedName, "Capability without the magic phrase", "public", false);

    given()
        .baseUri(issuerUrl())
        .queryParam("query", tag + " match")
        .when()
        .get("/capability/list")
        .then()
        .statusCode(200)
        .body("capabilities.name", hasItem(matchingName))
        .body("capabilities.name", org.hamcrest.Matchers.not(hasItem(unrelatedName)));
  }

  /**
   * TODO: Verify that {@code GET /capability/describe} returns the {@code location} field when the
   * capability was registered with a custom execution URL, as specified in §2.12 and the
   * capabilities field reference.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities">§2.12
   *      Capabilities — location field</a>
   * @see <a href="https://agent-auth-protocol.com/docs/capabilities">Capabilities doc — location
   *      field</a>
   */
  @Test
  void todoDescribeCapabilityReturnsLocationField() {
    // publicCapability was registered with location
    // "https://resource.example.test/capabilities/<name>"
    given()
        .baseUri(issuerUrl())
        .queryParam("name", publicCapability)
        .when()
        .get("/capability/describe")
        .then()
        .statusCode(200)
        .body("location",
            equalTo("https://resource.example.test/capabilities/" + publicCapability));
  }

  /**
   * TODO: Verify that capability names conform to the {@code [a-z0-9_]+} snake_case format required
   * by §2.14, and that attempting to register a capability with an invalid name (e.g., containing
   * uppercase letters or hyphens) is rejected.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#214-capability-naming">§2.14
   *      Capability Naming — [a-z0-9_]+ format requirement</a>
   */
  @Test
  void todoRegisterCapabilityWithInvalidNameIsRejected() {
    // Names with uppercase letters, hyphens, or spaces violate the [a-z0-9_]+ rule (§2.14).
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body("""
            {
              "name": "Invalid-Name",
              "description": "Bad name",
              "visibility": "public",
              "requires_approval": false,
              "location": "https://resource.example.test/capabilities/invalid"
            }
            """)
        .when()
        .post("/capabilities")
        .then()
        .statusCode(400);
  }

  /**
   * TODO: Verify that {@code GET /capability/describe} with an agent JWT returns
   * {@code grant_status: "not_granted"} for a capability that exists but has not been granted to
   * the requesting agent, as specified in §2.12.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities">§2.12
   *      Capabilities — grant_status "not_granted" value</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#521-describe-capability">§5.2.1
   *      Describe Capability — agent-JWT mode</a>
   */
  @Test
  void todoDescribeCapabilityWithAgentJwtReturnsNotGrantedForUngrantedCapability() {
    // The agent registered in @BeforeAll holds authenticatedCapability but not publicCapability.
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .queryParam("name", publicCapability)
        .when()
        .get("/capability/describe")
        .then()
        .statusCode(200)
        .body("grant_status", equalTo("not_granted"));
  }

  /**
   * Verifies that a malformed (non-JWT) Bearer token on {@code GET /capability/list} is treated as
   * unauthenticated rather than returning 401, and that only {@code public} capabilities appear in
   * the response, consistent with the graceful-degradation behaviour in the production code.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#52-list-capabilities">§5.2 List
   *      Capabilities — unauthenticated mode</a>
   */
  @Test
  void listCapabilitiesWithMalformedBearerTokenTreatedAsUnauthenticated() {
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer not.a.valid.jwt.token")
        .when()
        .get("/capability/list")
        .then()
        .statusCode(200)
        .body("capabilities.name", hasItem(publicCapability))
        .body("capabilities.name", org.hamcrest.Matchers.not(hasItem(authenticatedCapability)));
  }

  /**
   * Verifies that {@code GET /capability/describe?name=} returns both the {@code name} and
   * {@code description} fields with the exact values supplied at registration time.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#521-describe-capability">§5.2.1
   *      Describe Capability — name and description fields</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#212-capabilities">§2.12
   *      Capabilities — required fields: name, description</a>
   */
  @Test
  void describeCapabilityReturnsNameAndDescription() {
    given()
        .baseUri(issuerUrl())
        .queryParam("name", publicCapability)
        .when()
        .get("/capability/describe")
        .then()
        .statusCode(200)
        .body("name", equalTo(publicCapability))
        .body("description", equalTo("Public balance lookup"));
  }

  /**
   * Verifies §5.2 host+jwt signature verification: a {@code host+jwt} whose typ header is correct
   * but whose signature does not verify against the embedded {@code host_public_key} must be
   * treated as unauthenticated. The previous header-tag-only check accepted any token claiming
   * {@code typ=host+jwt}, exposing every {@code authenticated}-visibility capability to forged
   * tokens.
   */
  @Test
  void listCapabilitiesWithTamperedHostJwtTreatedAsUnauthenticated() {
    String validJwt = TestJwts.hostJwt(hostKey, issuerUrl());
    int lastDot = validJwt.lastIndexOf('.');
    int sigLen = validJwt.length() - lastDot - 1;
    String tamperedJwt = validJwt.substring(0, lastDot + 1) + "A".repeat(sigLen);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + tamperedJwt)
        .when()
        .get("/capability/list")
        .then()
        .statusCode(200)
        .body("capabilities.name", hasItem(publicCapability))
        .body("capabilities.name", org.hamcrest.Matchers.not(hasItem(authenticatedCapability)));
  }

  /**
   * Same §5.2 hardening applied to {@code GET /capability/describe}: a tampered {@code host+jwt}
   * must not unlock the authenticated-visibility capability. The describe endpoint returns 403 to
   * unauthenticated callers asking for an authenticated cap.
   */
  @Test
  void describeAuthenticatedCapabilityWithTamperedHostJwtReturns403() {
    String validJwt = TestJwts.hostJwt(hostKey, issuerUrl());
    int lastDot = validJwt.lastIndexOf('.');
    int sigLen = validJwt.length() - lastDot - 1;
    String tamperedJwt = validJwt.substring(0, lastDot + 1) + "A".repeat(sigLen);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + tamperedJwt)
        .queryParam("name", authenticatedCapability)
        .when()
        .get("/capability/describe")
        .then()
        .statusCode(403)
        .body("error", equalTo("access_denied"));
  }

  /**
   * Verifies §5.2 host-linked-user filtering: when a host+jwt comes from a host whose {@code
   * user_id} is set and whose {@code default_capability_grants} pre-approve a specific subset of
   * authenticated-visibility capabilities, the response must include only those caps (plus all
   * public caps), excluding other authenticated-visibility caps in the registry.
   *
   * <p>
   * This is the layer-1 narrowing toward the spec's "capabilities available to the host's linked
   * user" wording — implemented as host-pre-approval filtering until full user-entitlement gating
   * (authz Q3 in TODO.md) lands.
   */
  @Test
  void listCapabilitiesWithLinkedHostJwtFiltersByHostDefaults() {
    String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    String extraAuthCap = "extra_filter_target_" + suffix;
    registerCapability(extraAuthCap, "Extra auth cap not in host defaults", "authenticated", false);

    OctetKeyPair freshHostKey = TestKeys.generateEd25519();
    OctetKeyPair freshAgentKey = TestKeys.generateEd25519();
    String regJwt = TestJwts.hostJwtForRegistration(freshHostKey, freshAgentKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Filter Test Agent",
              "host_name": "filter-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "B-filter test"
            }
            """, authenticatedCapability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200);

    String hostId = TestKeys.thumbprint(freshHostKey);
    String userId = createTestUser("filter-test-user-" + suffix);
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(Map.of("user_id", userId))
        .when()
        .post("/hosts/" + hostId + "/link")
        .then()
        .statusCode(200);

    String hostJwt = TestJwts.hostJwt(freshHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .when()
        .get("/capability/list")
        .then()
        .statusCode(200)
        .body("capabilities.name", hasItems(publicCapability, authenticatedCapability))
        .body("capabilities.name", org.hamcrest.Matchers.not(hasItem(extraAuthCap)));
  }

  private static String createTestUser(String username) {
    String token = adminAccessToken();
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
}
