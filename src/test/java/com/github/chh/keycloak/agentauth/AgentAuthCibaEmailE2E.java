package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import com.github.chh.keycloak.agentauth.support.CibaTestHelpers;
import com.github.chh.keycloak.agentauth.support.TestJwts;
import com.github.chh.keycloak.agentauth.support.TestKeys;
import com.nimbusds.jose.jwk.OctetKeyPair;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;

/**
 * AAP §7.2 end-to-end SMTP delivery proof: verifies the CIBA email actually leaves Keycloak's
 * EmailSenderProvider and arrives in a real mailbox. Sister to {@code AgentAuthCibaApprovalIT}
 * (which exercises CIBA shape + the resilience path when SMTP is unreachable); this test instead
 * stands up MailHog as the SMTP target and inspects the captured message.
 *
 * <p>
 * Flow: Network → MailHog (alias {@code mailhog}, ports 1025/8025) → Keycloak (alias
 * {@code keycloak}) → admin sets realm SMTP → create user with email → pre-register + link host →
 * register delegated agent (CIBA fires) → poll MailHog HTTP API → assert subject/body content.
 */
class AgentAuthCibaEmailE2E {

  private static final String MAILHOG_IMAGE = "mailhog/mailhog:latest";
  private static final String MAILHOG_ALIAS = "mailhog";
  private static final int MAILHOG_SMTP_PORT = 1025;
  private static final int MAILHOG_HTTP_PORT = 8025;
  private static final String KEYCLOAK_ALIAS = "keycloak";
  private static final String FROM_ADDR = "noreply@agent-auth.test";

  private static Network network;
  private static GenericContainer<?> mailhog;
  @SuppressWarnings("resource")
  private static KeycloakContainer keycloak;

  @BeforeAll
  @SuppressWarnings("resource")
  static void start() {
    network = Network.newNetwork();
    mailhog = new GenericContainer<>(MAILHOG_IMAGE)
        .withNetwork(network)
        .withNetworkAliases(MAILHOG_ALIAS)
        .withExposedPorts(MAILHOG_SMTP_PORT, MAILHOG_HTTP_PORT)
        .waitingFor(Wait.forHttp("/api/v2/messages").forPort(MAILHOG_HTTP_PORT));
    mailhog.start();

    keycloak = com.github.chh.keycloak.agentauth.support.TestcontainersSupport
        .newKeycloakContainer()
        .withNetwork(network)
        .withNetworkAliases(KEYCLOAK_ALIAS);
    keycloak.start();
  }

  @AfterAll
  static void stop() {
    if (keycloak != null) {
      keycloak.stop();
      keycloak = null;
    }
    if (mailhog != null) {
      mailhog.stop();
      mailhog = null;
    }
    if (network != null) {
      network.close();
      network = null;
    }
  }

  @Test
  void cibaApprovalEmailIsDeliveredViaSmtp() throws InterruptedException {
    String authServerUrl = keycloak.getAuthServerUrl();
    String adminToken = CibaTestHelpers.adminAccessToken(authServerUrl,
        keycloak.getAdminUsername(), keycloak.getAdminPassword());

    // Configure realm SMTP to point at mailhog over the shared docker network.
    CibaTestHelpers.putRealmSmtp(authServerUrl, adminToken, Map.of(
        "host", MAILHOG_ALIAS,
        "port", String.valueOf(MAILHOG_SMTP_PORT),
        "from", FROM_ADDR,
        "fromDisplayName", "Agent Auth",
        "ssl", "false",
        "starttls", "false"));

    String suffix = CibaTestHelpers.randomSuffix();
    String username = "ciba-email-" + suffix;
    String userEmail = username + "@example.test";
    String userId = CibaTestHelpers.createTestUser(authServerUrl, adminToken, username, userEmail);
    String capability = CibaTestHelpers.registerApprovalCap(authServerUrl, adminToken,
        "ciba_email_cap_" + suffix);

    OctetKeyPair hostKey = TestKeys.generateEd25519();
    CibaTestHelpers.preRegisterHost(authServerUrl, adminToken, hostKey, "ciba-email-host");
    CibaTestHelpers.linkHost(authServerUrl, adminToken, TestKeys.thumbprint(hostKey), userId);

    String agentName = "ciba-email-agent-" + suffix;
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    Response regResp = given()
        .baseUri(CibaTestHelpers.issuerUrl(authServerUrl))
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey,
                CibaTestHelpers.issuerUrl(authServerUrl)))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "capabilities": ["%s"],
              "mode": "delegated",
              "binding_message": "Approve via email"
            }
            """, agentName, capability))
        .when()
        .post("/agent/register");
    regResp.then().statusCode(200)
        .body("approval.method", org.hamcrest.Matchers.equalTo("ciba"));
    String agentId = regResp.jsonPath().getString("agent_id");

    Map<String, Object> message = pollForMessage(userEmail);

    @SuppressWarnings("unchecked")
    Map<String, Object> content = (Map<String, Object>) message.get("Content");
    @SuppressWarnings("unchecked")
    Map<String, Object> headers = (Map<String, Object>) content.get("Headers");
    @SuppressWarnings("unchecked")
    List<String> subjectHeader = (List<String>) headers.get("Subject");
    @SuppressWarnings("unchecked")
    List<String> toHeader = (List<String>) headers.get("To");
    String body = (String) content.get("Body");

    assertThat(toHeader).as("To header").contains(userEmail);
    assertThat(subjectHeader).as("Subject header").isNotEmpty();
    // Subject is RFC2047 encoded for non-ASCII but our agent name is ASCII so it appears literally.
    assertThat(subjectHeader.get(0)).as("subject mentions agent name").contains(agentName);
    // Body is raw multipart MIME — link appears in both text and html parts.
    assertThat(body).as("body carries the approval link with the actual agent_id")
        .contains("verify?agent_id=" + agentId);
  }

  /**
   * Poll the MailHog HTTP API for a message addressed to {@code expectedRecipient}. SMTP delivery
   * is async — try ~10 times with 200ms sleeps.
   */
  @SuppressWarnings("unchecked")
  private static Map<String, Object> pollForMessage(String expectedRecipient)
      throws InterruptedException {
    String mailhogApi = "http://" + mailhog.getHost() + ":"
        + mailhog.getMappedPort(MAILHOG_HTTP_PORT);
    Map<String, Object> last = null;
    for (int i = 0; i < 10; i++) {
      Response r = given().baseUri(mailhogApi).when().get("/api/v2/messages");
      r.then().statusCode(200);
      List<Map<String, Object>> items = r.jsonPath().getList("items");
      if (items != null && !items.isEmpty()) {
        for (Map<String, Object> item : items) {
          Map<String, Object> content = (Map<String, Object>) item.get("Content");
          Map<String, Object> headers = (Map<String, Object>) content.get("Headers");
          List<String> to = (List<String>) headers.get("To");
          if (to != null && to.contains(expectedRecipient)) {
            return item;
          }
        }
        last = items.get(0);
      }
      Thread.sleep(200);
    }
    throw new AssertionError(
        "MailHog never received a message for " + expectedRecipient + "; last seen: " + last);
  }
}
