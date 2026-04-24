package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;

import com.github.chh.keycloak.agentauth.support.BasePostgresE2E;
import com.github.chh.keycloak.agentauth.support.TestJwts;
import com.github.chh.keycloak.agentauth.support.TestKeys;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.sun.net.httpserver.HttpServer;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.Testcontainers;

/**
 * End-to-end user-journey tests that walk the entire protocol sequence in one pass for both
 * {@code delegated} and {@code autonomous} modes:
 *
 * <ul>
 * <li>delegated: register capability (approval-required) → register agent (pending) →
 * status=pending → admin approve → status=active → execute → introspect → revoke → execute rejected
 * → introspect inactive</li>
 * <li>autonomous: register capability (auto-approved) → register agent (active immediately) →
 * execute → introspect → revoke → execute rejected → introspect inactive</li>
 * </ul>
 *
 * <p>
 * Unlike the per-endpoint ITs, each test runs the full sequence; a failure at any step aborts the
 * rest, and AssertJ descriptions identify which step broke.
 */
class AgentAuthFullJourneyE2E extends BasePostgresE2E {

  private static HttpServer backend;
  private static int backendPort;
  private static final AtomicInteger backendHits = new AtomicInteger();

  @BeforeAll
  static void startBackend() throws IOException {
    backend = HttpServer.create(new InetSocketAddress(0), 0);
    backend.createContext("/execute", exchange -> {
      backendHits.incrementAndGet();
      exchange.getRequestBody().readAllBytes();
      byte[] body = "{\"data\":{\"balance\":4280.13,\"currency\":\"USD\"}}"
          .getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().add("Content-Type", "application/json");
      exchange.sendResponseHeaders(200, body.length);
      exchange.getResponseBody().write(body);
      exchange.close();
    });
    backend.start();
    backendPort = backend.getAddress().getPort();
    Testcontainers.exposeHostPorts(backendPort);
  }

  @AfterAll
  static void stopBackend() {
    if (backend != null) {
      backend.stop(0);
    }
  }

  @Test
  void delegatedJourneyPendingUntilApproved() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String capability = "check_balance_delegated_" + uniqueSuffix();

    // 1. admin registers capability requiring approval
    registerCapability(capability, true);

    // 2. agent registers in delegated mode — lands in pending
    String agentId = registerAgent(hostKey, agentKey, capability, "delegated");
    assertThat(statusOf(agentId, hostKey)).as("step 2: status after register").isEqualTo("pending");

    // 3. admin approves the grant — agent flips to active
    approveCapability(agentId, capability);
    assertThat(statusOf(agentId, hostKey)).as("step 3: status after approve").isEqualTo("active");

    // 4. execute succeeds and hits the backend
    int before = backendHits.get();
    execute(hostKey, agentKey, agentId, capability)
        .then()
        .statusCode(200)
        .body("data.balance", equalTo(4280.13f));
    assertThat(backendHits.get() - before).as("step 4: backend invocations").isEqualTo(1);

    // 5. introspect reports active
    introspect(hostKey, agentKey, agentId)
        .then()
        .statusCode(200)
        .body("active", equalTo(true))
        .body("agent_id", equalTo(agentId));

    // 6. revoke
    revoke(hostKey, agentId);

    // 7. post-revoke execute is rejected (and backend is not hit)
    int afterRevokeBefore = backendHits.get();
    execute(hostKey, agentKey, agentId, capability)
        .then()
        .statusCode(403);
    assertThat(backendHits.get() - afterRevokeBefore)
        .as("step 7: backend must not be invoked after revoke")
        .isZero();

    // 8. post-revoke introspect reports inactive
    introspect(hostKey, agentKey, agentId)
        .then()
        .statusCode(200)
        .body("active", equalTo(false));
  }

  @Test
  void autonomousJourneyActiveImmediately() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String capability = "check_balance_autonomous_" + uniqueSuffix();

    // 1. admin registers auto-approved capability
    registerCapability(capability, false);

    // 2. agent registers in autonomous mode — active immediately, no approve step
    String agentId = registerAgent(hostKey, agentKey, capability, "autonomous");
    assertThat(statusOf(agentId, hostKey)).as("step 2: status after register").isEqualTo("active");

    // 3. execute succeeds and hits the backend
    int before = backendHits.get();
    execute(hostKey, agentKey, agentId, capability)
        .then()
        .statusCode(200)
        .body("data.balance", equalTo(4280.13f));
    assertThat(backendHits.get() - before).as("step 3: backend invocations").isEqualTo(1);

    // 4. introspect reports active
    introspect(hostKey, agentKey, agentId)
        .then()
        .statusCode(200)
        .body("active", equalTo(true))
        .body("agent_id", equalTo(agentId));

    // 5. revoke
    revoke(hostKey, agentId);

    // 6. post-revoke execute rejected
    int afterRevokeBefore = backendHits.get();
    execute(hostKey, agentKey, agentId, capability)
        .then()
        .statusCode(403);
    assertThat(backendHits.get() - afterRevokeBefore)
        .as("step 6: backend must not be invoked after revoke")
        .isZero();

    // 7. post-revoke introspect inactive
    introspect(hostKey, agentKey, agentId)
        .then()
        .statusCode(200)
        .body("active", equalTo(false));
  }

  private static String uniqueSuffix() {
    return UUID.randomUUID().toString().replace("-", "").substring(0, 8);
  }

  private static void registerCapability(String name, boolean requiresApproval) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Full-journey capability",
              "visibility": "authenticated",
              "requires_approval": %s,
              "location": "http://127.0.0.1:%d/execute",
              "input": { "type": "object" },
              "output": { "type": "object" }
            }
            """, name, requiresApproval, backendPort))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);
  }

  private static String registerAgent(
      OctetKeyPair hostKey, OctetKeyPair agentKey, String capability, String mode) {
    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl());
    return given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Journey agent",
              "host_name": "journey-host",
              "capabilities": ["%s"],
              "mode": "%s",
              "reason": "Full-journey E2E"
            }
            """, capability, mode))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");
  }

  private static String statusOf(String agentId, OctetKeyPair hostKey) {
    return given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .queryParam("agent_id", agentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(200)
        .extract()
        .path("status");
  }

  private static void approveCapability(String agentId, String capability) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .when()
        .post("/agents/" + agentId + "/capabilities/" + capability + "/approve")
        .then()
        .statusCode(200);
  }

  private static Response execute(
      OctetKeyPair hostKey, OctetKeyPair agentKey, String agentId, String capability) {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        issuerUrl() + "/capability/execute");
    return given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": { "account_id": "acc_123" }
            }
            """, capability))
        .when()
        .post("/capability/execute");
  }

  private static Response introspect(
      OctetKeyPair hostKey, OctetKeyPair agentKey, String agentId) {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());
    return given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "token": "%s"
            }
            """, agentJwt))
        .when()
        .post("/agent/introspect");
  }

  private static void revoke(OctetKeyPair hostKey, String agentId) {
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s"
            }
            """, agentId))
        .when()
        .post("/agent/revoke")
        .then()
        .statusCode(200);
  }
}
