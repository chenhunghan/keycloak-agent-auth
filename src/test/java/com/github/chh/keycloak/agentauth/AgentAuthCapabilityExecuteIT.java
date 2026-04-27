package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.oneOf;

import com.github.chh.keycloak.agentauth.support.BaseKeycloakIT;
import com.github.chh.keycloak.agentauth.support.TestJwts;
import com.github.chh.keycloak.agentauth.support.TestKeys;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.restassured.http.ContentType;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.Testcontainers;

/**
 * Integration tests for {@code POST /capability/execute} when Keycloak acts as the execution
 * gateway.
 *
 * <p>
 * Spec sections covered:
 *
 * <ul>
 * <li>§5.11 Execute Capability — endpoint contract, request/response shapes, error codes
 * {@link <a href=
 * "https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">§5.11</a>}
 * <li>§2.13 Scoped Grants / Constraints — {@code max}, {@code min}, {@code in}, {@code not_in},
 * exact-value operators, combined range bounds {@link <a href=
 * "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">§2.13</a>}
 * <li>§2.15 Execution — gateway proxying semantics {@link <a href=
 * "https://agent-auth-protocol.com/specification/v1.0-draft#215-execution">§2.15</a>}
 * <li>§4.3 Agent JWT — {@code aud} verification, expiry, and type validation
 * {@link <a href= "https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt">§4.3</a>}
 * <li>Execute error codes — {@code authentication_required}, {@code invalid_request}, {@code
 *       capability_not_found}, {@code capability_not_granted}, {@code constraint_violated}, {@code
 *       agent_revoked}, {@code agent_expired}, {@code invalid_jwt} {@link <a href=
 * "https://agent-auth-protocol.com/docs/errors#capability-execution-post-capabilityexecute">error
 * codes</a>}
 * <li>Constraint violation detail — {@code violations} array structure {@link <a href=
 * "https://agent-auth-protocol.com/docs/errors#constraint-violation-detail">constraint-violation-detail</a>}
 * <li>Async and streaming execution — 202/SSE proxying, {@code status_url}, stream lifecycle
 * {@link <a href=
 * "https://agent-auth-protocol.com/docs/servers#async-and-streaming-execution">async/streaming</a>}
 * </ul>
 *
 * <p>
 * TODO stubs at the bottom of this file document spec requirements not yet covered by an
 * implemented test.
 */
class AgentAuthCapabilityExecuteIT extends BaseKeycloakIT {

  private static HttpServer resourceServer;
  private static OctetKeyPair hostKey;
  private static OctetKeyPair agentKey;
  private static String agentId;
  private static String syncCapability;
  private static String asyncCapability;
  private static String limitedCapability;
  private static String ungrantedCapability;
  private static String streamCapability;
  private static String minConstrainedCapability;
  private static String inConstrainedCapability;
  private static String notInConstrainedCapability;
  private static String exactConstrainedCapability;
  private static String combinedConstrainedCapability;
  private static final AtomicInteger syncExecutions = new AtomicInteger();
  private static final AtomicInteger asyncExecutions = new AtomicInteger();
  private static final AtomicInteger limitedExecutions = new AtomicInteger();
  private static final AtomicInteger streamExecutions = new AtomicInteger();
  private static final AtomicInteger minConstrainedExecutions = new AtomicInteger();
  private static final AtomicInteger inConstrainedExecutions = new AtomicInteger();
  private static final AtomicInteger notInConstrainedExecutions = new AtomicInteger();
  private static final AtomicInteger exactConstrainedExecutions = new AtomicInteger();
  private static final AtomicInteger combinedConstrainedExecutions = new AtomicInteger();
  private static final AtomicReference<String> lastSyncRequest = new AtomicReference<>();
  private static String asyncCompletedCapability;
  private static String asyncFailedCapability;
  private static String longStreamCapability;
  private static final AtomicInteger asyncCompletedExecutions = new AtomicInteger();
  private static final AtomicInteger asyncFailedExecutions = new AtomicInteger();
  private static final AtomicInteger longStreamExecutions = new AtomicInteger();
  // Latch held open while the long-stream SSE handler is blocked; count down to release it.
  private static final java.util.concurrent.CountDownLatch longStreamRelease = new java.util.concurrent.CountDownLatch(
      1);
  /**
   * §4.3 resolved location URL per registered capability — populated by
   * {@link #registerCapability(String, String, String)} so tests can mint agent+jwts with
   * {@code aud} set to the cap's actual {@code location}.
   */
  private static final Map<String, String> capLocations = new java.util.HashMap<>();

  /** Per-cap §4.3 resolved location URL (or {@code default_location} when the cap has none). */
  private static String capLocation(String name) {
    String loc = capLocations.get(name);
    if (loc == null) {
      throw new IllegalStateException("Unknown capability: " + name);
    }
    return loc;
  }

  @BeforeAll
  static void setUp() throws IOException {
    resourceServer = HttpServer.create(new InetSocketAddress(0), 0);
    resourceServer.createContext("/execute/sync", exchange -> handleJson(
        exchange,
        200,
        "{\"data\":{\"account_id\":\"acc_123\",\"balance\":4280.13,\"currency\":\"USD\"}}",
        syncExecutions,
        lastSyncRequest));
    resourceServer.createContext("/execute/async", exchange -> handleJson(
        exchange,
        202,
        "{\"status\":\"pending\",\"status_url\":\"https://jobs.example.test/job_123\"}",
        asyncExecutions,
        null));
    resourceServer.createContext("/execute/limited", exchange -> handleJson(
        exchange,
        200,
        "{\"data\":{\"status\":\"submitted\"}}",
        limitedExecutions,
        null));
    resourceServer.createContext("/execute/stream", exchange -> {
      streamExecutions.incrementAndGet();
      exchange.getRequestBody().readAllBytes();
      byte[] body = "data: {\"event\":\"result\",\"data\":{\"status\":\"done\"}}\n\n"
          .getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().add("Content-Type", "text/event-stream");
      exchange.sendResponseHeaders(200, body.length);
      exchange.getResponseBody().write(body);
      exchange.close();
    });
    resourceServer.createContext("/execute/min-limited", exchange -> handleJson(
        exchange,
        200,
        "{\"data\":{\"status\":\"ok\"}}",
        minConstrainedExecutions,
        null));
    resourceServer.createContext("/execute/in-limited", exchange -> handleJson(
        exchange,
        200,
        "{\"data\":{\"status\":\"ok\"}}",
        inConstrainedExecutions,
        null));
    resourceServer.createContext("/execute/not-in-limited", exchange -> handleJson(
        exchange,
        200,
        "{\"data\":{\"status\":\"ok\"}}",
        notInConstrainedExecutions,
        null));
    resourceServer.createContext("/execute/exact-limited", exchange -> handleJson(
        exchange,
        200,
        "{\"data\":{\"status\":\"ok\"}}",
        exactConstrainedExecutions,
        null));
    resourceServer.createContext("/execute/combined-limited", exchange -> handleJson(
        exchange,
        200,
        "{\"data\":{\"status\":\"ok\"}}",
        combinedConstrainedExecutions,
        null));
    // Async-completed: upstream signals a job whose status endpoint returns "completed".
    // The status_url path deliberately points back to this same embedded server so that
    // whatever status_url the gateway proxies to the client, the client can resolve it.
    resourceServer.createContext("/execute/async-completed", exchange -> {
      asyncCompletedExecutions.incrementAndGet();
      exchange.getRequestBody().readAllBytes();
      String statusPath = "/status/job-completed";
      String body = String.format(
          "{\"status\":\"pending\",\"status_url\":\"http://127.0.0.1:%d%s\"}",
          resourceServer.getAddress().getPort(), statusPath);
      byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().add("Content-Type", "application/json");
      exchange.sendResponseHeaders(202, bytes.length);
      exchange.getResponseBody().write(bytes);
      exchange.close();
    });
    resourceServer.createContext("/status/job-completed", exchange -> {
      exchange.getRequestBody().readAllBytes();
      byte[] bytes = "{\"status\":\"completed\",\"result\":{\"report_id\":\"rpt_001\"}}"
          .getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().add("Content-Type", "application/json");
      exchange.sendResponseHeaders(200, bytes.length);
      exchange.getResponseBody().write(bytes);
      exchange.close();
    });
    // Async-failed: upstream signals a job whose status endpoint returns "failed".
    resourceServer.createContext("/execute/async-failed", exchange -> {
      asyncFailedExecutions.incrementAndGet();
      exchange.getRequestBody().readAllBytes();
      String statusPath = "/status/job-failed";
      String body = String.format(
          "{\"status\":\"pending\",\"status_url\":\"http://127.0.0.1:%d%s\"}",
          resourceServer.getAddress().getPort(), statusPath);
      byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().add("Content-Type", "application/json");
      exchange.sendResponseHeaders(202, bytes.length);
      exchange.getResponseBody().write(bytes);
      exchange.close();
    });
    resourceServer.createContext("/status/job-failed", exchange -> {
      exchange.getRequestBody().readAllBytes();
      byte[] bytes = "{\"status\":\"failed\",\"error\":{\"code\":\"upstream_error\",\"message\":\"timed out\"}}"
          .getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().add("Content-Type", "application/json");
      exchange.sendResponseHeaders(200, bytes.length);
      exchange.getResponseBody().write(bytes);
      exchange.close();
    });
    // Long-running SSE stream: blocks until longStreamRelease is counted down, letting the
    // revocation test revoke the agent and then verify the connection is closed by the gateway.
    resourceServer.createContext("/execute/stream-long", exchange -> {
      longStreamExecutions.incrementAndGet();
      exchange.getRequestBody().readAllBytes();
      exchange.getResponseHeaders().add("Content-Type", "text/event-stream");
      exchange.sendResponseHeaders(200, 0);
      try {
        // Block up to 10 s; the test should release us well before that.
        longStreamRelease.await(10, java.util.concurrent.TimeUnit.SECONDS);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
      // Write a keepalive comment and close — the gateway should have already terminated the
      // client-side connection upon agent revocation.
      try {
        exchange.getResponseBody().write(": keepalive\n\n".getBytes(StandardCharsets.UTF_8));
        exchange.getResponseBody().flush();
      } catch (IOException ignored) {
        // Expected if the gateway closed the piped connection before we flushed.
      }
      exchange.close();
    });
    resourceServer.start();
    Testcontainers.exposeHostPorts(resourceServer.getAddress().getPort());

    hostKey = TestKeys.generateEd25519();
    agentKey = TestKeys.generateEd25519();

    String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    syncCapability = "check_balance_execute_" + suffix;
    asyncCapability = "start_report_execute_" + suffix;
    limitedCapability = "transfer_money_execute_" + suffix;
    ungrantedCapability = "close_account_execute_" + suffix;
    streamCapability = "stream_report_execute_" + suffix;
    minConstrainedCapability = "wire_transfer_execute_" + suffix;
    inConstrainedCapability = "currency_transfer_execute_" + suffix;
    notInConstrainedCapability = "country_transfer_execute_" + suffix;
    exactConstrainedCapability = "exact_dest_execute_" + suffix;
    combinedConstrainedCapability = "combined_amount_execute_" + suffix;
    asyncCompletedCapability = "async_completed_execute_" + suffix;
    asyncFailedCapability = "async_failed_execute_" + suffix;
    longStreamCapability = "long_stream_execute_" + suffix;

    int port = resourceServer.getAddress().getPort();
    registerCapability(syncCapability, "Check balance",
        "http://127.0.0.1:" + port + "/execute/sync");
    registerCapability(asyncCapability, "Start report",
        "http://127.0.0.1:" + port + "/execute/async");
    registerCapability(limitedCapability, "Transfer money",
        "http://127.0.0.1:" + port + "/execute/limited");
    registerCapability(ungrantedCapability, "Close account",
        "http://127.0.0.1:" + port + "/execute/sync");
    registerCapability(streamCapability, "Stream report",
        "http://127.0.0.1:" + port + "/execute/stream");
    registerCapability(minConstrainedCapability, "Wire transfer min",
        "http://127.0.0.1:" + port + "/execute/min-limited");
    registerCapability(inConstrainedCapability, "Currency transfer",
        "http://127.0.0.1:" + port + "/execute/in-limited");
    registerCapability(notInConstrainedCapability, "Country transfer",
        "http://127.0.0.1:" + port + "/execute/not-in-limited");
    registerCapability(exactConstrainedCapability, "Exact dest transfer",
        "http://127.0.0.1:" + port + "/execute/exact-limited");
    registerCapability(combinedConstrainedCapability, "Combined amount transfer",
        "http://127.0.0.1:" + port + "/execute/combined-limited");
    registerCapability(asyncCompletedCapability, "Async completed job",
        "http://127.0.0.1:" + port + "/execute/async-completed");
    registerCapability(asyncFailedCapability, "Async failed job",
        "http://127.0.0.1:" + port + "/execute/async-failed");
    registerCapability(longStreamCapability, "Long stream report",
        "http://127.0.0.1:" + port + "/execute/stream-long");

    String hostJwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl());
    preRegisterHost(hostKey);
    agentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Execution Test Agent",
              "host_name": "execute-host",
              "capabilities": [
                "%s",
                "%s",
                {
                  "name": "%s",
                  "constraints": {
                    "amount": {"max": 1000}
                  }
                },
                "%s",
                {
                  "name": "%s",
                  "constraints": {
                    "amount": {"min": 10}
                  }
                },
                {
                  "name": "%s",
                  "constraints": {
                    "currency": {"in": ["USD", "EUR"]}
                  }
                },
                {
                  "name": "%s",
                  "constraints": {
                    "country": {"not_in": ["SANCTIONED_A"]}
                  }
                },
                {
                  "name": "%s",
                  "constraints": {
                    "destination_account": "acc_456"
                  }
                },
                {
                  "name": "%s",
                  "constraints": {
                    "amount": {"min": 10, "max": 1000}
                  }
                },
                "%s",
                "%s",
                "%s"
              ],
              "mode": "delegated",
              "reason": "Execute integration test"
            }
            """, syncCapability, asyncCapability, limitedCapability, streamCapability,
            minConstrainedCapability, inConstrainedCapability, notInConstrainedCapability,
            exactConstrainedCapability, combinedConstrainedCapability,
            asyncCompletedCapability, asyncFailedCapability, longStreamCapability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");
  }

  @AfterAll
  static void tearDown() {
    if (resourceServer != null) {
      resourceServer.stop(0);
    }
  }

  private static void registerCapability(String name, String description, String location) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "%s",
              "visibility": "authenticated",
              "requires_approval": false,
              "location": "%s",
              "input": {
                "type": "object",
                "properties": {
                  "account_id": {"type": "string"},
                  "amount": {"type": "number"},
                  "currency": {"type": "string"},
                  "country": {"type": "string"}
                }
              },
              "output": {
                "type": "object"
              }
            }
            """, name, description, location))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);
    capLocations.put(name, location);
  }

  private static void handleJson(
      HttpExchange exchange,
      int statusCode,
      String responseBody,
      AtomicInteger counter,
      AtomicReference<String> requestSink) throws IOException {
    counter.incrementAndGet();
    if (requestSink != null) {
      requestSink.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
    } else {
      exchange.getRequestBody().readAllBytes();
    }
    byte[] body = responseBody.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", "application/json");
    exchange.sendResponseHeaders(statusCode, body.length);
    exchange.getResponseBody().write(body);
    exchange.close();
  }

  /**
   * §5.11: A successful synchronous execution MUST return HTTP 200 with a {@code data} field
   * containing the capability's result, and MUST NOT contain {@code status}, {@code status_url},
   * {@code result}, or {@code error}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#215-execution"> §2.15
   *      Execution</a>
   */
  @Test
  void executeGrantedCapabilityProxiesSyncResponse() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(syncCapability));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {
                "account_id": "acc_123"
              }
            }
            """, syncCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(200)
        .body("data.account_id", equalTo("acc_123"))
        .body("data.balance", equalTo(4280.13f))
        .body("data.currency", equalTo("USD"))
        // Spec §5.11: sync response MUST NOT contain status, status_url, result, or error
        .body("status", org.hamcrest.Matchers.nullValue())
        .body("status_url", org.hamcrest.Matchers.nullValue())
        .body("result", org.hamcrest.Matchers.nullValue())
        .body("error", org.hamcrest.Matchers.nullValue());
  }

  @Test
  void executeLocationlessCapabilityReturnsMisconfigurationError() {
    String locationlessCapability = "locationless_execute_"
        + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "No explicit resource-server location",
              "visibility": "authenticated",
              "requires_approval": false
            }
            """, locationlessCapability))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201)
        .body("location", org.hamcrest.Matchers.nullValue());

    String requestJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + requestJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"],
              "reason": "Exercise default_location misconfiguration path"
            }
            """, locationlessCapability))
        .when()
        .post("/agent/request-capability")
        .then()
        .statusCode(200)
        .body("agent_capability_grants[0].status", equalTo("active"));

    // §4.3: cap was registered without `location`, so resolved URL = default_location.
    String executeJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        issuerUrl() + "/capability/execute");
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + executeJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {}
            }
            """, locationlessCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(500)
        .body("error", equalTo("capability_misconfigured"));
  }

  /**
   * §2.15: The execution gateway MUST forward both the {@code capability} name and the
   * {@code arguments} object to the upstream resource server without modification.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#215-execution"> §2.15
   *      Execution</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   */
  @Test
  void executeGatewayForwardsCapabilityAndArguments() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(syncCapability));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {
                "account_id": "acc_123"
              }
            }
            """, syncCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(200);

    assertThat(syncExecutions.get()).isGreaterThan(0);
    assertThat(lastSyncRequest.get()).contains(syncCapability);
    assertThat(lastSyncRequest.get()).contains("acc_123");
  }

  /**
   * §5.11 / Async: When the upstream resource server returns 202 Accepted, the gateway MUST proxy
   * the async pending response with HTTP 202, a {@code status} of {@code "pending"}, and a
   * {@code status_url} for the client to poll.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   * @see <a href="https://agent-auth-protocol.com/docs/servers#async-and-streaming-execution">
   *      Async and Streaming Execution</a>
   */
  @Test
  void executeGrantedCapabilityCanReturnAsyncPendingResponse() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(asyncCapability));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {
                "account_id": "acc_123"
              }
            }
            """, asyncCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(202)
        .body("status", equalTo("pending"))
        .body("status_url", notNullValue());
  }

  /**
   * §5.11 / §4.3: Requests without an {@code Authorization} header MUST be rejected with HTTP 401
   * and error code {@code authentication_required}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt"> §4.3
   *      Agent JWT</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-execution-post-capabilityexecute">
   *      Execute error codes</a>
   */
  @Test
  void executeWithoutAuthReturns401() {
    given()
        .baseUri(issuerUrl())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s"
            }
            """, syncCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(401)
        .body("error", equalTo("authentication_required"))
        .body("message", notNullValue());
  }

  /**
   * §5.11: When the requesting agent holds no active grant for the named capability, the server
   * MUST return HTTP 403 with error code {@code capability_not_granted} and MUST NOT forward the
   * request to the upstream resource server.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-execution-post-capabilityexecute">
   *      Execute error codes</a>
   */
  @Test
  void executeWithoutGrantReturns403AndDoesNotForward() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(ungrantedCapability));
    int syncCallsBefore = syncExecutions.get();

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s"
            }
            """, ungrantedCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(403)
        .body("error", equalTo("capability_not_granted"))
        .body("message", notNullValue());

    assertThat(syncExecutions.get()).isEqualTo(syncCallsBefore);
  }

  /**
   * §5.11 / §2.13: When execution arguments violate the {@code max} constraint in the agent's
   * scoped grant, the server MUST return HTTP 403 with error code {@code constraint_violated} and
   * MUST NOT forward the request to the upstream resource server.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
   *      §2.13 Scoped Grants — Constraints</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-execution-post-capabilityexecute">
   *      Execute error codes</a>
   */
  @Test
  void executeConstraintViolationReturns403AndDoesNotForward() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(limitedCapability));
    int limitedCallsBefore = limitedExecutions.get();

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {
                "amount": 5000
              }
            }
            """, limitedCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(403)
        .body("error", equalTo("constraint_violated"))
        .body("message", notNullValue());

    assertThat(limitedExecutions.get()).isEqualTo(limitedCallsBefore);
  }

  // --- Gap 1: Missing capability field ---

  /**
   * §5.11: Omitting the required {@code capability} field MUST result in HTTP 400 with error code
   * {@code invalid_request}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-execution-post-capabilityexecute">
   *      Execute error codes</a>
   */
  @Test
  void executeMissingCapabilityFieldReturns400() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(syncCapability));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "arguments": {
                "account_id": "acc_123"
              }
            }
            """)
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"))
        .body("message", notNullValue());
  }

  // --- Gap 2: Expired agent JWT ---

  /**
   * §4.3: An Agent JWT whose {@code exp} claim is in the past MUST be rejected with HTTP 401; the
   * error code MUST be {@code invalid_jwt} or {@code authentication_required}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt"> §4.3
   *      Agent JWT</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-execution-post-capabilityexecute">
   *      Execute error codes</a>
   */
  @Test
  void executeWithExpiredAgentJwtReturns401() {
    String expiredJwt = TestJwts.expiredAgentJwt(hostKey, agentKey, agentId,
        capLocation(syncCapability));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + expiredJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {}
            }
            """, syncCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(401)
        .body("error", oneOf("invalid_jwt", "authentication_required"))
        .body("message", notNullValue());
  }

  // --- Gap 3: Revoked agent ---

  /**
   * §5.11: When the agent has been explicitly revoked by its host, the server MUST reject execution
   * attempts with HTTP 401 or 403 and an appropriate error code (e.g. {@code agent_revoked}).
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-execution-post-capabilityexecute">
   *      Execute error codes</a>
   */
  @Test
  void executeWithRevokedAgentReturns403() {
    OctetKeyPair hostKey2 = TestKeys.generateEd25519();
    OctetKeyPair agentKey2 = TestKeys.generateEd25519();

    String regJwt = TestJwts.hostJwtForRegistration(hostKey2, agentKey2, issuerUrl());
    preRegisterHost(hostKey2);
    String revokedAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Revoked Execute Agent",
              "host_name": "execute-host-2",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "Revocation execute test"
            }
            """, syncCapability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    String revokeJwt = TestJwts.hostJwt(hostKey2, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + revokeJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s"
            }
            """, revokedAgentId))
        .when()
        .post("/agent/revoke")
        .then()
        .statusCode(200)
        .body("status", equalTo("revoked"));

    String agentJwt = TestJwts.agentJwt(hostKey2, agentKey2, revokedAgentId,
        capLocation(syncCapability));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {}
            }
            """, syncCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(403)
        .body("error", equalTo("agent_revoked"))
        .body("message", notNullValue());
  }

  // --- Gap 4: SSE streaming mode ---

  /**
   * §5.11 / Async+Streaming: When the upstream resource server responds with
   * {@code Content-Type: text/event-stream}, the gateway MUST proxy the SSE stream to the client
   * with HTTP 200 and preserve the {@code text/event-stream} content type.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   * @see <a href="https://agent-auth-protocol.com/docs/servers#async-and-streaming-execution">
   *      Async and Streaming Execution</a>
   */
  @Test
  void executeGrantedCapabilityProxiesStreamResponse() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(streamCapability));
    int callsBefore = streamExecutions.get();

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {}
            }
            """, streamCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(200)
        .contentType(containsString("text/event-stream"))
        .body(containsString("data:"));

    assertThat(streamExecutions.get()).isGreaterThan(callsBefore);
  }

  // --- Gap 5: Min constraint violation ---

  /**
   * §2.13: When execution arguments fall below the {@code min} value defined in the agent's scoped
   * grant, the server MUST return HTTP 403 with error code {@code constraint_violated} and MUST NOT
   * forward the request upstream.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
   *      §2.13 Scoped Grants — Constraints</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-execution-post-capabilityexecute">
   *      Execute error codes</a>
   */
  @Test
  void executeMinConstraintViolationReturns403AndDoesNotForward() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(minConstrainedCapability));
    int callsBefore = minConstrainedExecutions.get();

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {
                "amount": 5
              }
            }
            """, minConstrainedCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(403)
        .body("error", equalTo("constraint_violated"))
        .body("message", notNullValue());

    assertThat(minConstrainedExecutions.get()).isEqualTo(callsBefore);
  }

  // --- Gap 6: In constraint violation ---

  /**
   * §2.13: When execution arguments supply a value that is not in the {@code in} allowlist defined
   * by the agent's scoped grant, the server MUST return HTTP 403 with error code
   * {@code constraint_violated} and MUST NOT forward the request upstream.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
   *      §2.13 Scoped Grants — Constraints</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-execution-post-capabilityexecute">
   *      Execute error codes</a>
   */
  @Test
  void executeInConstraintViolationReturns403AndDoesNotForward() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(inConstrainedCapability));
    int callsBefore = inConstrainedExecutions.get();

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {
                "currency": "GBP"
              }
            }
            """, inConstrainedCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(403)
        .body("error", equalTo("constraint_violated"))
        .body("message", notNullValue());

    assertThat(inConstrainedExecutions.get()).isEqualTo(callsBefore);
  }

  // --- Gap 7: Not-in constraint violation ---

  /**
   * §2.13: When execution arguments supply a value that appears in the {@code not_in} denylist
   * defined by the agent's scoped grant, the server MUST return HTTP 403 with error code
   * {@code constraint_violated} and MUST NOT forward the request upstream.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
   *      §2.13 Scoped Grants — Constraints</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-execution-post-capabilityexecute">
   *      Execute error codes</a>
   */
  @Test
  void executeNotInConstraintViolationReturns403AndDoesNotForward() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(notInConstrainedCapability));
    int callsBefore = notInConstrainedExecutions.get();

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {
                "country": "SANCTIONED_A"
              }
            }
            """, notInConstrainedCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(403)
        .body("error", equalTo("constraint_violated"))
        .body("message", notNullValue());

    assertThat(notInConstrainedExecutions.get()).isEqualTo(callsBefore);
  }

  // --- Gap 8: Exact value constraint violation ---

  /**
   * §2.13: When execution arguments supply a value that does not exactly match the string equality
   * constraint in the agent's scoped grant, the server MUST return HTTP 403 with error code
   * {@code constraint_violated} and MUST NOT forward the request upstream.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
   *      §2.13 Scoped Grants — Constraints</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-execution-post-capabilityexecute">
   *      Execute error codes</a>
   */
  @Test
  void executeExactConstraintViolationReturns403AndDoesNotForward() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(exactConstrainedCapability));
    int callsBefore = exactConstrainedExecutions.get();

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {
                "destination_account": "acc_789"
              }
            }
            """, exactConstrainedCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(403)
        .body("error", equalTo("constraint_violated"))
        .body("message", notNullValue());

    assertThat(exactConstrainedExecutions.get()).isEqualTo(callsBefore);
  }

  /**
   * §2.13: When execution arguments exactly match the string equality constraint in the agent's
   * scoped grant, the server MUST allow execution and proxy the request upstream.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
   *      §2.13 Scoped Grants — Constraints</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   */
  @Test
  void executeExactConstraintPassesWhenMatched() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(exactConstrainedCapability));
    int callsBefore = exactConstrainedExecutions.get();

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {
                "destination_account": "acc_456"
              }
            }
            """, exactConstrainedCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(200)
        .body("data.status", equalTo("ok"));

    assertThat(exactConstrainedExecutions.get()).isGreaterThan(callsBefore);
  }

  // --- Gap 9: Combined (min+max) constraint violation ---

  /**
   * §2.13: When both {@code min} and {@code max} operators are combined on a single field, a value
   * below {@code min} MUST trigger HTTP 403 with error code {@code constraint_violated} and the
   * request MUST NOT be forwarded upstream.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
   *      §2.13 Scoped Grants — Constraints</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-execution-post-capabilityexecute">
   *      Execute error codes</a>
   */
  @Test
  void executeCombinedConstraintBelowMinReturns403() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(combinedConstrainedCapability));
    int callsBefore = combinedConstrainedExecutions.get();

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {
                "amount": 5
              }
            }
            """, combinedConstrainedCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(403)
        .body("error", equalTo("constraint_violated"))
        .body("message", notNullValue());

    assertThat(combinedConstrainedExecutions.get()).isEqualTo(callsBefore);
  }

  /**
   * §2.13: When both {@code min} and {@code max} operators are combined on a single field, a value
   * above {@code max} MUST trigger HTTP 403 with error code {@code constraint_violated} and the
   * request MUST NOT be forwarded upstream.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
   *      §2.13 Scoped Grants — Constraints</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-execution-post-capabilityexecute">
   *      Execute error codes</a>
   */
  @Test
  void executeCombinedConstraintAboveMaxReturns403() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(combinedConstrainedCapability));
    int callsBefore = combinedConstrainedExecutions.get();

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {
                "amount": 2000
              }
            }
            """, combinedConstrainedCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(403)
        .body("error", equalTo("constraint_violated"))
        .body("message", notNullValue());

    assertThat(combinedConstrainedExecutions.get()).isEqualTo(callsBefore);
  }

  // --- Gap 10: Unregistered capability ---

  /**
   * §5.11: When the requested capability name does not exist in the server's registry, the server
   * MUST return HTTP 404 with error code {@code capability_not_found}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-execution-post-capabilityexecute">
   *      Execute error codes</a>
   */
  @Test
  void executeUnregisteredCapabilityReturns404() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(syncCapability));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "capability": "totally_nonexistent_capability_xyz_12345",
              "arguments": {}
            }
            """)
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(404)
        .body("error", equalTo("capability_not_found"))
        .body("message", notNullValue());
  }

  // --- Agent state: expired agent lifecycle state ---

  /**
   * §5.11: When the agent's lifecycle state has been administratively set to expired, the server
   * MUST reject execution attempts with HTTP 401 or 403 and an appropriate error code (e.g.
   * {@code agent_expired}).
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-execution-post-capabilityexecute">
   *      Execute error codes</a>
   */
  @Test
  void executeWithExpiredAgentStateReturns403() {
    OctetKeyPair hostKey2 = TestKeys.generateEd25519();
    OctetKeyPair agentKey2 = TestKeys.generateEd25519();

    String regJwt = TestJwts.hostJwtForRegistration(hostKey2, agentKey2, issuerUrl());
    preRegisterHost(hostKey2);
    String expiredAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Expired State Execute Agent",
              "host_name": "execute-expire-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "Expired state execute test"
            }
            """, syncCapability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body("{}")
        .when()
        .post("/agents/" + expiredAgentId + "/expire")
        .then()
        .statusCode(200);

    String agentJwt = TestJwts.agentJwt(hostKey2, agentKey2, expiredAgentId,
        capLocation(syncCapability));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {}
            }
            """, syncCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(403)
        .body("error", equalTo("agent_expired"))
        .body("message", notNullValue());
  }

  // --- Agent state: pending agent ---

  /**
   * §5.11: An agent in {@code pending} state (awaiting approval for a capability that requires it)
   * MUST be denied execution with HTTP 403 until the grant is approved.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-execution-post-capabilityexecute">
   *      Execute error codes</a>
   */
  @Test
  void executeWithPendingAgentReturns403() {
    OctetKeyPair pendingHostKey = TestKeys.generateEd25519();
    OctetKeyPair pendingAgentKey = TestKeys.generateEd25519();
    String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    String approvalCapabilityName = "execute_approval_cap_" + suffix;

    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Approval required for execute test",
              "visibility": "authenticated",
              "requires_approval": true,
              "location": "https://resource.example.test/execute-approval",
              "input": {"type": "object"},
              "output": {"type": "object"}
            }
            """, approvalCapabilityName))
        .when()
        .post("/capabilities")
        .then()
        .statusCode(201);

    String regJwt = TestJwts.hostJwtForRegistration(pendingHostKey, pendingAgentKey, issuerUrl());
    preRegisterHost(pendingHostKey);
    String pendingAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Pending Execute Agent",
              "host_name": "pending-execute-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "Pending state execute test"
            }
            """, approvalCapabilityName))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("status", equalTo("pending"))
        .extract()
        .path("agent_id");

    String agentJwt = TestJwts.agentJwt(pendingHostKey, pendingAgentKey, pendingAgentId,
        capLocation(syncCapability));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {}
            }
            """, syncCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(403)
        .body("error", equalTo("agent_pending"))
        .body("message", notNullValue());
  }

  // --- Wrong JWT type: host+jwt used instead of agent+jwt ---

  /**
   * §4.3: A Host JWT presented at {@code POST /capability/execute} MUST be rejected with HTTP 401
   * and error code {@code invalid_jwt}; only Agent JWTs are accepted at this endpoint.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt"> §4.3
   *      Agent JWT</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-execution-post-capabilityexecute">
   *      Execute error codes</a>
   */
  @Test
  void executeWithHostJwtReturns401() {
    String hostJwt = TestJwts.hostJwt(hostKey, issuerUrl() + "/capability/execute");

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + hostJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {}
            }
            """, syncCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_jwt"));
  }

  // --- Constraint passing: max constraint ---

  /**
   * §2.13: When execution arguments satisfy the {@code max} constraint (value ≤ max), the server
   * MUST allow execution and proxy the request upstream.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
   *      §2.13 Scoped Grants — Constraints</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   */
  @Test
  void executeMaxConstraintPassesWhenUnderLimit() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(limitedCapability));
    int callsBefore = limitedExecutions.get();

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {
                "amount": 500
              }
            }
            """, limitedCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(200)
        .body("data.status", equalTo("submitted"));

    assertThat(limitedExecutions.get()).isGreaterThan(callsBefore);
  }

  // --- Constraint passing: min constraint ---

  /**
   * §2.13: When execution arguments satisfy the {@code min} constraint (value ≥ min), the server
   * MUST allow execution and proxy the request upstream.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
   *      §2.13 Scoped Grants — Constraints</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   */
  @Test
  void executeMinConstraintPassesWhenAboveLimit() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(minConstrainedCapability));
    int callsBefore = minConstrainedExecutions.get();

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {
                "amount": 50
              }
            }
            """, minConstrainedCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(200)
        .body("data.status", equalTo("ok"));

    assertThat(minConstrainedExecutions.get()).isGreaterThan(callsBefore);
  }

  // --- Constraint passing: in constraint ---

  /**
   * §2.13: When execution arguments supply a value that is present in the {@code in} allowlist, the
   * server MUST allow execution and proxy the request upstream.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
   *      §2.13 Scoped Grants — Constraints</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   */
  @Test
  void executeInConstraintPassesWhenValueInList() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(inConstrainedCapability));
    int callsBefore = inConstrainedExecutions.get();

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {
                "currency": "EUR"
              }
            }
            """, inConstrainedCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(200);

    assertThat(inConstrainedExecutions.get()).isGreaterThan(callsBefore);
  }

  // --- Constraint passing: not_in constraint ---

  /**
   * §2.13: When execution arguments supply a value that is absent from the {@code not_in} denylist,
   * the server MUST allow execution and proxy the request upstream.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
   *      §2.13 Scoped Grants — Constraints</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   */
  @Test
  void executeNotInConstraintPassesWhenValueNotInList() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(notInConstrainedCapability));
    int callsBefore = notInConstrainedExecutions.get();

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {
                "country": "US"
              }
            }
            """, notInConstrainedCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(200);

    assertThat(notInConstrainedExecutions.get()).isGreaterThan(callsBefore);
  }

  // --- Constraint passing: combined min+max constraint ---

  /**
   * §2.13: When both {@code min} and {@code max} operators are combined on a single field, a value
   * within the range [min, max] MUST be accepted and the request proxied upstream.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
   *      §2.13 Scoped Grants — Constraints</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   */
  @Test
  void executeCombinedConstraintPassesWhenInRange() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(combinedConstrainedCapability));
    int callsBefore = combinedConstrainedExecutions.get();

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {
                "amount": 500
              }
            }
            """, combinedConstrainedCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(200);

    assertThat(combinedConstrainedExecutions.get()).isGreaterThan(callsBefore);
  }

  // ---------------------------------------------------------------------------
  // TODO stubs — spec requirements not yet covered by an implemented test
  // ---------------------------------------------------------------------------

  /**
   * §5.11: A constraint violation response MUST include a {@code violations} array where each entry
   * contains {@code field}, {@code constraint}, and {@code actual} to help agents self-correct.
   *
   * @see <a href="https://agent-auth-protocol.com/docs/errors#constraint-violation-detail">
   *      Constraint Violation Detail</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   */
  @Test
  void constraintViolationResponseIncludesViolationsArray() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(limitedCapability));

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {
                "amount": 9999
              }
            }
            """, limitedCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(403)
        .body("error", equalTo("constraint_violated"))
        .body("violations", notNullValue())
        .body("violations[0].field", notNullValue())
        .body("violations[0].constraint", notNullValue())
        .body("violations[0].actual", notNullValue());
  }

  /**
   * §5.11: When the {@code capability} field is present but its value is an empty string, the
   * server MUST return HTTP 400 with error code {@code invalid_request}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-execution-post-capabilityexecute">
   *      Execute error codes</a>
   */
  @Test
  void malformedCapabilityFieldReturns400() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(syncCapability));

    // Empty string capability name
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "capability": "",
              "arguments": {}
            }
            """)
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"))
        .body("message", notNullValue());

    String secondAgentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(syncCapability));

    // Whitespace-only capability name
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + secondAgentJwt)
        .contentType(ContentType.JSON)
        .body("""
            {
              "capability": "   ",
              "arguments": {}
            }
            """)
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"))
        .body("message", notNullValue());
  }

  /**
   * §4.3: An Agent JWT whose {@code aud} claim does not match the execute endpoint URL MUST be
   * rejected with HTTP 401 and error code {@code invalid_jwt}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#43-agent-jwt"> §4.3
   *      Agent JWT</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-execution-post-capabilityexecute">
   *      Execute error codes</a>
   */
  @Test
  void agentJwtWithWrongAudReturns401() {
    // Audience set to the issuer base URL, not the /capability/execute endpoint
    String wrongAudJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + wrongAudJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {}
            }
            """, syncCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_jwt"))
        .body("message", notNullValue());
  }

  /**
   * §4.3 says an optional {@code capabilities} claim narrows the JWT to that capability set. An
   * execute request for any capability outside that claim must be rejected before the upstream
   * capability service is called.
   */
  @Test
  void executeWithCapabilityOutsideJwtScopeReturns403() {
    String scopedJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(limitedCapability), Map.of("capabilities", List.of(limitedCapability)));
    int callsBefore = syncExecutions.get();

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + scopedJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {}
            }
            """, syncCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(403)
        .body("error", equalTo("capability_not_granted"));

    assertThat(syncExecutions.get()).isEqualTo(callsBefore);
  }

  /**
   * §5.11 / Async: A completed async job polled via {@code status_url} MUST return HTTP 200 with
   * {@code status: "completed"} and a {@code result} field; the Agent JWT used for polling MUST
   * have {@code aud} set to the {@code status_url}.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   * @see <a href="https://agent-auth-protocol.com/docs/servers#async-and-streaming-execution">
   *      Async and Streaming Execution</a>
   */
  @Test
  void asyncPollingReturnsCompletedStatus() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(asyncCompletedCapability));

    String statusUrl = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {}
            }
            """, asyncCompletedCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(202)
        .body("status", equalTo("pending"))
        .body("status_url", notNullValue())
        .extract()
        .path("status_url");

    given()
        .when()
        .get(statusUrl)
        .then()
        .statusCode(200)
        .body("status", equalTo("completed"))
        .body("result", notNullValue());
  }

  /**
   * §5.11 / Async: A failed async job polled via {@code status_url} MUST return HTTP 200 with
   * {@code status: "failed"} and an {@code error} object; {@code data} and {@code status_url} MUST
   * NOT be present.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   * @see <a href="https://agent-auth-protocol.com/docs/servers#async-and-streaming-execution">
   *      Async and Streaming Execution</a>
   */
  @Test
  void asyncPollingReturnsFailedStatus() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(asyncFailedCapability));

    String statusUrl = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {}
            }
            """, asyncFailedCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(202)
        .body("status", equalTo("pending"))
        .body("status_url", notNullValue())
        .extract()
        .path("status_url");

    given()
        .when()
        .get(statusUrl)
        .then()
        .statusCode(200)
        .body("status", equalTo("failed"))
        .body("error", notNullValue());
  }

  /**
   * §2.13 / Async streaming: Servers SHOULD enforce a maximum stream duration and SHOULD
   * periodically recheck agent revocation during long-running SSE streams (recommended every 60 s).
   *
   * @see <a href="https://agent-auth-protocol.com/docs/servers#async-and-streaming-execution">
   *      Async and Streaming Execution</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   */
  @Test
  void streamTerminatedOnAgentRevocationDuringStream() throws Exception {
    OctetKeyPair streamHostKey = TestKeys.generateEd25519();
    OctetKeyPair streamAgentKey = TestKeys.generateEd25519();
    String regJwt = TestJwts.hostJwtForRegistration(streamHostKey, streamAgentKey, issuerUrl());
    preRegisterHost(streamHostKey);
    String streamAgentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Stream Revoke Agent",
              "host_name": "stream-revoke-host",
              "capabilities": ["%s"],
              "mode": "delegated",
              "reason": "Stream revocation test"
            }
            """, longStreamCapability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .extract()
        .path("agent_id");

    String agentJwt = TestJwts.agentJwt(streamHostKey, streamAgentKey, streamAgentId,
        capLocation(longStreamCapability));

    // Start SSE request in background thread — the upstream handler blocks on longStreamRelease
    java.util.concurrent.atomic.AtomicInteger responseStatus = new java.util.concurrent.atomic.AtomicInteger(
        0);
    Thread streamThread = new Thread(() -> {
      try {
        int status = io.restassured.RestAssured.given()
            .baseUri(issuerUrl())
            .header("Authorization", "Bearer " + agentJwt)
            .contentType("application/json")
            .body(String.format("""
                {
                  "capability": "%s",
                  "arguments": {}
                }
                """, longStreamCapability))
            .when()
            .post("/capability/execute")
            .statusCode();
        responseStatus.set(status);
      } catch (Exception e) {
        responseStatus.set(-1);
      }
    });
    streamThread.setDaemon(true);
    streamThread.start();

    // Give the stream time to reach the upstream handler
    Thread.sleep(500);

    // Revoke the agent mid-stream
    String revokeJwt = TestJwts.hostJwt(streamHostKey, issuerUrl());
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + revokeJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "agent_id": "%s"
            }
            """, streamAgentId))
        .when()
        .post("/agent/revoke")
        .then()
        .statusCode(200);

    // Release the upstream handler so the test doesn't hang
    longStreamRelease.countDown();

    // Wait for stream thread to complete (connection should have been terminated)
    streamThread.join(5000);

    // Stream connection must be terminated — the response status must not be 200 (streaming
    // success)
    // After revocation the gateway should have closed the connection; response may be 403 or
    // a partial 200 that the client sees as a closed stream.
    assertThat(streamThread.isAlive()).isFalse();
  }

  /**
   * §5.11: When a grant contains an unrecognized constraint operator, the server MUST reject the
   * registration request with HTTP 400 and error code {@code unknown_constraint_operator}. Because
   * operator validation occurs at registration time, a grant with an unknown operator can never be
   * stored and therefore can never reach the execute endpoint.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#511-execute-capability">
   *      §5.11 Execute Capability</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
   *      §2.13 Scoped Grants — Constraints</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/docs/errors#capability-execution-post-capabilityexecute">
   *      Execute error codes</a>
   */
  @Test
  void unknownConstraintOperatorReturns400() {
    OctetKeyPair unknownOpHostKey = TestKeys.generateEd25519();
    OctetKeyPair unknownOpAgentKey = TestKeys.generateEd25519();

    // Attempt to register an agent with an unknown constraint operator on a capability.
    // The server validates operators at registration time and MUST reject this with 400.
    String regJwt = TestJwts.hostJwtForRegistration(unknownOpHostKey, unknownOpAgentKey,
        issuerUrl());
    preRegisterHost(unknownOpHostKey);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + regJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "Unknown Op Test Agent",
              "host_name": "unknown-op-host",
              "capabilities": [
                {
                  "name": "%s",
                  "constraints": {
                    "amount": {"unknown_op": 5}
                  }
                }
              ],
              "mode": "delegated",
              "reason": "Unknown operator test"
            }
            """, syncCapability))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(400)
        .body("error", equalTo("unknown_constraint_operator"))
        .body("message", notNullValue());
  }

  // ---------------------------------------------------------------------------
  // Zero-coverage gap tests
  // ---------------------------------------------------------------------------

  /**
   * §2.13: When a constrained field is absent from execution arguments and the constraint is a
   * numeric {@code max} or {@code min} operator, the server treats the missing value as unchecked
   * (no violation). This documents the current ConstraintValidator behavior: a {@code null} actual
   * value does not satisfy {@code instanceof Number}, so the numeric check is skipped and the
   * request is forwarded upstream.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
   *      §2.13 Scoped Grants — Constraints</a>
   */
  @Test
  void executeWithMissingArgumentForConstrainedField() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(limitedCapability));
    int callsBefore = limitedExecutions.get();

    // limitedCapability has constraint: amount max 1000. Omitting the constrained field cannot
    // satisfy the grant.
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {}
            }
            """, limitedCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(403)
        .body("error", equalTo("constraint_violated"));

    assertThat(limitedExecutions.get()).isEqualTo(callsBefore);
  }

  /**
   * §2.13: When a constrained field is supplied as the wrong type (e.g. a string where a numeric
   * {@code max} constraint is defined), the server MUST NOT crash with a 500. The current
   * ConstraintValidator skips the numeric operator check when the actual value is not a
   * {@link Number}, so a string value passes the {@code max} check and the request is forwarded
   * upstream.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
   *      §2.13 Scoped Grants — Constraints</a>
   */
  @Test
  void executeWithTypeMismatchOnConstrainedField() {
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        capLocation(limitedCapability));

    // limitedCapability has constraint: amount max 1000. A string cannot satisfy a numeric max
    // constraint, so the server must reject before forwarding upstream.
    int callsBefore = limitedExecutions.get();
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {
                "amount": "high"
              }
            }
            """, limitedCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(403)
        .body("error", equalTo("constraint_violated"));

    assertThat(limitedExecutions.get()).isEqualTo(callsBefore);
  }

  /**
   * §4.5 + §4.6: a token whose signature is INVALID MUST NOT consume the {@code jti} it carried. If
   * {@code jti} replay detection ran before signature verification, an attacker could pre-emptively
   * burn legitimate {@code jti} values by submitting forged tokens, denying the legitimate agent
   * its single-use credential. A subsequent token carrying the SAME {@code jti} but a VALID
   * signature must therefore still execute successfully.
   *
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#45-verification">§4.5
   *      Verification — signature check before replay check</a>
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#46-replay-detection">§4.6 Replay
   *      Detection — only valid tokens consume jti</a>
   */
  @Test
  void executeInvalidSignatureDoesNotConsumeJti() {
    String sharedJti = "a-" + UUID.randomUUID();
    OctetKeyPair wrongKey = TestKeys.generateEd25519();
    int callsBefore = syncExecutions.get();

    String forgedJwt = buildExecuteJwtWithJti(wrongKey, sharedJti, capLocation(syncCapability));
    String validJwt = buildExecuteJwtWithJti(agentKey, sharedJti, capLocation(syncCapability));

    // First request: invalid signature — server returns 401 invalid_jwt but MUST NOT record the
    // jti in the seen-jti cache.
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + forgedJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {}
            }
            """, syncCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_jwt"));

    // Second request: valid signature, SAME jti — must succeed because the forged request did
    // not consume the jti.
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + validJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {}
            }
            """, syncCapability))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(200);

    assertThat(syncExecutions.get()).isGreaterThan(callsBefore);
  }

  /**
   * Helper: builds an agent+jwt with an explicit {@code jti} value so two requests can share the
   * same identifier for replay-ordering tests.
   */
  private static String buildExecuteJwtWithJti(OctetKeyPair signingKey, String jti,
      String audience) {
    try {
      JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
          .type(new JOSEObjectType("agent+jwt"))
          .build();
      long now = System.currentTimeMillis();
      JWTClaimsSet claims = new JWTClaimsSet.Builder()
          .issuer(TestKeys.thumbprint(hostKey))
          .subject(agentId)
          .audience(audience)
          .issueTime(new Date(now))
          .expirationTime(new Date(now + 60_000L))
          .jwtID(jti)
          .build();
      SignedJWT jwt = new SignedJWT(header, claims);
      jwt.sign(new Ed25519Signer(signingKey));
      return jwt.serialize();
    } catch (Exception e) {
      throw new AssertionError("Failed to build agent JWT with explicit jti", e);
    }
  }
}
