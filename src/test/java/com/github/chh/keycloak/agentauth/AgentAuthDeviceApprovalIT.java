package com.github.chh.keycloak.agentauth;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.matchesPattern;

import com.github.chh.keycloak.agentauth.support.BaseKeycloakIT;
import com.github.chh.keycloak.agentauth.support.TestJwts;
import com.github.chh.keycloak.agentauth.support.TestKeys;
import com.nimbusds.jose.jwk.OctetKeyPair;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Device-authorization approval flow for delegated agent registration (AAP §5.3 + §7.1).
 *
 * <p>
 * Scope for this IT:
 *
 * <ul>
 * <li>§5.1: discovery advertises {@code device_authorization} in {@code approval_methods}.</li>
 * <li>§5.3 + §7.1: registration of a delegated agent under an unlinked host returns
 * {@code status=pending} and an {@code approval} object with {@code method="device_authorization"},
 * a short {@code user_code}, {@code verification_uri}, {@code verification_uri_complete},
 * {@code expires_in} and {@code interval}.</li>
 * <li>§7.1: when a KC user approves via {@code POST /verify/approve}, the agent transitions to
 * {@code active} and the host is linked (host.user_id = approving user's id).</li>
 * <li>§7.1: denial is terminal — {@code POST /verify/deny} transitions the agent to
 * {@code rejected}; re-attempting approve on the same user_code is rejected.</li>
 * <li>§8.11: approval requires a real authenticated Keycloak user identity (not the admin service
 * token). The IT supplies a fresh access token via direct-access grant.</li>
 * </ul>
 *
 * <p>
 * MVP omissions (tracked for follow-up): no HTML verification page, no CIBA, no WebAuthn
 * escalation, no partial per-capability approval.
 */
class AgentAuthDeviceApprovalIT extends BaseKeycloakIT {

  private static final String USER_PASSWORD = "testpass";

  @Test
  void discoveryAdvertisesDeviceAuthorization() {
    // §5.1: `approval_methods` is required and includes core values.
    given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .when()
        .get("/realms/" + REALM + "/.well-known/agent-configuration")
        .then()
        .statusCode(200)
        .body("approval_methods",
            org.hamcrest.Matchers.hasItem("device_authorization"));
  }

  @Test
  void registerDelegatedAgentOnUnlinkedHost_returnsDeviceAuthApprovalObject() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String cap = registerApprovalRequiredCapability("devauth_reg_" + suffix());

    Response resp = registerDelegatedAgent(hostKey, agentKey, cap);
    resp.then()
        .statusCode(200)
        .body("status", org.hamcrest.Matchers.equalTo("pending"))
        .body("approval.method", org.hamcrest.Matchers.equalTo("device_authorization"))
        .body("approval.user_code", matchesPattern("[A-Z]{4}-[A-Z]{4}"))
        .body("approval.verification_uri", org.hamcrest.Matchers.notNullValue())
        .body("approval.expires_in", org.hamcrest.Matchers.greaterThan(0))
        .body("approval.interval", org.hamcrest.Matchers.greaterThan(0));

    String userCode = resp.jsonPath().getString("approval.user_code");
    String vuriComplete = resp.jsonPath().getString("approval.verification_uri_complete");
    assertThat(vuriComplete).contains(userCode);
  }

  @Test
  void approveViaUserCode_activatesAgentAndLinksHostToApprover() {
    // Set up a pending registration.
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String cap = registerApprovalRequiredCapability("devauth_approve_" + suffix());
    Response regResp = registerDelegatedAgent(hostKey, agentKey, cap);
    String agentId = regResp.jsonPath().getString("agent_id");
    String userCode = regResp.jsonPath().getString("approval.user_code");

    // Create a realm user + acquire their access token.
    String username = "approver-" + suffix();
    String userId = createTestUser(username);
    String userAccessToken = realmUserAccessToken(username);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + userAccessToken)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", userCode))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(200);

    // Agent flipped to active.
    Map<String, Object> status = agentStatusBody(agentId, hostKey);
    assertThat(status.get("status")).isEqualTo("active");
    // Host linked to the approving user.
    assertThat(status.get("user_id")).isEqualTo(userId);
  }

  @Test
  void denyViaUserCode_transitionsAgentToRejected() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String cap = registerApprovalRequiredCapability("devauth_deny_" + suffix());
    Response regResp = registerDelegatedAgent(hostKey, agentKey, cap);
    String agentId = regResp.jsonPath().getString("agent_id");
    String userCode = regResp.jsonPath().getString("approval.user_code");

    String username = "denier-" + suffix();
    createTestUser(username);
    String userAccessToken = realmUserAccessToken(username);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + userAccessToken)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", userCode))
        .when()
        .post("/verify/deny")
        .then()
        .statusCode(200);

    assertThat(agentStatusBody(agentId, hostKey).get("status")).isEqualTo("rejected");
  }

  @Test
  void approveAfterDeny_returns410_becauseDenialIsTerminal() {
    // §7.1: "User denial is terminal for that attempt. Client MUST NOT retry." The re-approval
    // attempt must be rejected.
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String cap = registerApprovalRequiredCapability("devauth_denyterm_" + suffix());
    Response regResp = registerDelegatedAgent(hostKey, agentKey, cap);
    String userCode = regResp.jsonPath().getString("approval.user_code");

    String username = "denier-then-approver-" + suffix();
    createTestUser(username);
    String token = realmUserAccessToken(username);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", userCode))
        .when()
        .post("/verify/deny")
        .then()
        .statusCode(200);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", userCode))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(410);
  }

  /**
   * §7.1 expiry: a user_code older than the realm's configured approval window must be rejected
   * with 410 {@code approval_expired}, even if the pending agent still exists in storage (the 24h
   * cleanup is a separate sweep and shouldn't be the only line of defense). The threshold is
   * realm-configurable via the {@code agent_auth_approval_expires_in_seconds} attribute; this test
   * temporarily lowers it to 2s so we can wait past it without slowing the suite.
   */
  @Test
  void approveAfterUserCodeExpired_returns410() throws InterruptedException {
    long previous = currentApprovalExpirySeconds();
    setApprovalExpirySeconds(2L);
    try {
      OctetKeyPair hostKey = TestKeys.generateEd25519();
      OctetKeyPair agentKey = TestKeys.generateEd25519();
      String cap = registerApprovalRequiredCapability("devauth_expiry_" + suffix());
      Response regResp = registerDelegatedAgent(hostKey, agentKey, cap);
      regResp.then().statusCode(200);
      // expires_in must reflect the configured value, not the constant default.
      assertThat(regResp.jsonPath().getInt("approval.expires_in")).isEqualTo(2);
      String userCode = regResp.jsonPath().getString("approval.user_code");

      // Wait past the expiry threshold (with margin for test latency).
      Thread.sleep(3000L);

      String username = "expiry-approver-" + suffix();
      createTestUser(username);
      String token = realmUserAccessToken(username);

      given()
          .baseUri(issuerUrl())
          .header("Authorization", "Bearer " + token)
          .contentType(ContentType.JSON)
          .body(Map.of("user_code", userCode))
          .when()
          .post("/verify/approve")
          .then()
          .statusCode(410)
          .body("error", equalTo("approval_expired"));
    } finally {
      setApprovalExpirySeconds(previous);
    }
  }

  @Test
  void approveUnknownUserCode_returns404() {
    String username = "stranger-" + suffix();
    createTestUser(username);
    String token = realmUserAccessToken(username);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", "ZZZZ-ZZZZ"))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(404);
  }

  @Test
  void capabilityRequestApproval_activatesGrantsWithoutChangingAgentStatus() {
    // §5.4 + §7 + §7.1: a capability-request on an already-active agent that needs user
    // approval MUST go through an approval flow (device_authorization for unlinked hosts, CIBA
    // for linked hosts). The agent stays `active`; only the pending grants flip to `active`.
    // Wave 5 made active+unlinked hosts impossible, so this test exercises the CIBA flow under
    // a linked host — the approval-routing semantics being tested are the same on both flows.
    String autoCap = registerAutoCapability("devauth_capreq_auto_" + suffix());
    String approvalCap = registerApprovalRequiredCapability("devauth_capreq_" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String username = "capreq-approver-" + suffix();
    String userId = createTestUser(username);
    preRegisterHostForUser(hostKey, userId);

    // Register the agent with only the auto-approved capability → status=active straight away.
    String agentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "capreq agent",
              "capabilities": ["%s"],
              "mode": "delegated"
            }
            """, autoCap))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("status", org.hamcrest.Matchers.equalTo("active"))
        .extract()
        .path("agent_id");

    // Agent now requests the approval-required capability.
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());
    Response reqResp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s"]
            }
            """, approvalCap))
        .when()
        .post("/agent/request-capability");
    reqResp.then()
        .statusCode(200)
        .body("approval.method", org.hamcrest.Matchers.equalTo("ciba"));

    // User approves via agent_id (CIBA path).
    String userAccessToken = realmUserAccessToken(username);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + userAccessToken)
        .contentType(ContentType.JSON)
        .body(Map.of("agent_id", agentId))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(200);

    // Agent status remains active; the newly-requested grant is now active too.
    Map<String, Object> status = agentStatusBody(agentId, hostKey);
    assertThat(status.get("status")).isEqualTo("active");
    @SuppressWarnings("unchecked")
    java.util.List<Map<String, Object>> grants = (java.util.List<Map<String, Object>>) status
        .get("agent_capability_grants");
    Map<String, Object> requestedGrant = grants.stream()
        .filter(g -> approvalCap.equals(g.get("capability")))
        .findFirst()
        .orElseThrow(() -> new AssertionError("Requested grant missing"));
    assertThat(requestedGrant.get("status")).isEqualTo("active");
  }

  @Test
  void reactivateApproval_capInDefaultsAutoGrants_capNotInDefaultsRePrompts() {
    // §5.6: "Determine the host's current default capabilities and grant them to the agent,
    // following the same auto-approval logic as registration." Combined with §5.3
    // ("if the capabilities fall within its defaults, auto-approve"), reactivation should:
    // • auto-grant caps already in host.default_capabilities (TOFU — user approved before),
    // • re-prompt approval for caps that haven't been approved on this host yet.
    String approvedCap = registerApprovalRequiredCapability("devauth_react_known_" + suffix());
    String unapprovedCap = registerApprovalRequiredCapability("devauth_react_new_" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();

    // Register requesting BOTH caps; only approve the first → only it lands in host defaults.
    Response regResp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "react agent",
              "capabilities": ["%s", "%s"],
              "mode": "delegated"
            }
            """, approvedCap, unapprovedCap))
        .when()
        .post("/agent/register");
    String agentId = regResp.jsonPath().getString("agent_id");
    String firstUserCode = regResp.jsonPath().getString("approval.user_code");

    String username = "reactivate-approver-" + suffix();
    createTestUser(username);
    String userAccessToken = realmUserAccessToken(username);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + userAccessToken)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", firstUserCode,
            "capabilities", java.util.List.of(approvedCap)))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(200);

    // Force-expire so reactivate has work to do.
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .when()
        .post("/agents/" + agentId + "/expire")
        .then()
        .statusCode(200);

    // Reactivate. host.default_capabilities = [approvedCap], so reactivation auto-grants that
    // one. unapprovedCap is replayed by buildReactivationGrants from default_capability_grants
    // (the constraint-preserving snapshot from first register) but is NOT in host defaults, so
    // it gets re-prompted as pending. Agent itself stays pending until the new approval lands.
    Response reactResp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(Map.of("agent_id", agentId))
        .when()
        .post("/agent/reactivate");
    reactResp.then()
        .statusCode(200)
        .body("status", org.hamcrest.Matchers.equalTo("pending"));
    @SuppressWarnings("unchecked")
    java.util.List<Map<String, Object>> grants = reactResp.jsonPath()
        .getList("agent_capability_grants",
            (Class<Map<String, Object>>) (Class<?>) Map.class);
    Map<String, Object> approvedGrant = grants.stream()
        .filter(g -> approvedCap.equals(g.get("capability")))
        .findFirst()
        .orElseThrow(() -> new AssertionError("approvedCap missing from reactivation grants"));
    assertThat(approvedGrant.get("status"))
        .as("cap in host.default_capabilities reactivates to active without re-prompt")
        .isEqualTo("active");
    Map<String, Object> unapprovedGrant = grants.stream()
        .filter(g -> unapprovedCap.equals(g.get("capability")))
        .findFirst()
        .orElseThrow(() -> new AssertionError("unapprovedCap missing from reactivation grants"));
    assertThat(unapprovedGrant.get("status"))
        .as("cap NOT in host.default_capabilities reactivates as pending (re-prompts)")
        .isEqualTo("pending");
  }

  @Test
  @SuppressWarnings("unchecked")
  void partialApproval_subsetOfCapabilitiesApproved_restDenied() {
    // §5.3: "When a registration requests multiple capabilities, the user MAY approve some and
    // deny others. The server MUST reflect this in the agent_capability_grants array — each
    // grant carries its own status."
    String capA = registerApprovalRequiredCapability("devauth_partial_a_" + suffix());
    String capB = registerApprovalRequiredCapability("devauth_partial_b_" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();

    Response regResp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "partial agent",
              "capabilities": ["%s", "%s"],
              "mode": "delegated"
            }
            """, capA, capB))
        .when()
        .post("/agent/register");
    regResp.then().statusCode(200).body("status", org.hamcrest.Matchers.equalTo("pending"));
    String agentId = regResp.jsonPath().getString("agent_id");
    String userCode = regResp.jsonPath().getString("approval.user_code");

    String username = "partial-approver-" + suffix();
    createTestUser(username);
    String token = realmUserAccessToken(username);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", userCode, "capabilities", java.util.List.of(capA)))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(200);

    Map<String, Object> status = agentStatusBody(agentId, hostKey);
    assertThat(status.get("status")).as("agent becomes active even on partial approval")
        .isEqualTo("active");
    java.util.List<Map<String, Object>> grants = (java.util.List<Map<String, Object>>) status
        .get("agent_capability_grants");
    Map<String, Object> grantA = grants.stream()
        .filter(g -> capA.equals(g.get("capability"))).findFirst().orElseThrow();
    Map<String, Object> grantB = grants.stream()
        .filter(g -> capB.equals(g.get("capability"))).findFirst().orElseThrow();
    assertThat(grantA.get("status")).as("selected capability approved").isEqualTo("active");
    assertThat(grantB.get("status")).as("unselected capability denied").isEqualTo("denied");
  }

  @Test
  @SuppressWarnings("unchecked")
  void partialApproval_emptyCapabilitiesList_deniesAllButLeavesAgentActive() {
    // §5.3: "A fully denied registration (all capabilities denied) sets the agent status to
    // "active" with an empty or all-denied grants array." — this is distinct from /verify/deny
    // which is the explicit "reject the agent entirely" path.
    String capA = registerApprovalRequiredCapability("devauth_emptyapprove_a_" + suffix());
    String capB = registerApprovalRequiredCapability("devauth_emptyapprove_b_" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();

    Response regResp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "empty-approve agent",
              "capabilities": ["%s", "%s"],
              "mode": "delegated"
            }
            """, capA, capB))
        .when()
        .post("/agent/register");
    String agentId = regResp.jsonPath().getString("agent_id");
    String userCode = regResp.jsonPath().getString("approval.user_code");

    String username = "empty-approver-" + suffix();
    createTestUser(username);
    String token = realmUserAccessToken(username);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", userCode, "capabilities", java.util.List.of()))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(200);

    Map<String, Object> status = agentStatusBody(agentId, hostKey);
    assertThat(status.get("status")).isEqualTo("active");
    java.util.List<Map<String, Object>> grants = (java.util.List<Map<String, Object>>) status
        .get("agent_capability_grants");
    assertThat(grants).allSatisfy(g -> assertThat(g.get("status")).isEqualTo("denied"));
  }

  @Test
  @SuppressWarnings("unchecked")
  void partialApproval_onCapabilityRequest_deniesUnselectedGrantsButKeepsAgentActive() {
    String autoCap = registerAutoCapability("devauth_capreq_partial_auto_" + suffix());
    String approvA = registerApprovalRequiredCapability("devauth_capreq_partial_a_" + suffix());
    String approvB = registerApprovalRequiredCapability("devauth_capreq_partial_b_" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    // Wave 5 made active+unlinked hosts impossible: a pre-registered pending host cascades to a
    // pending agent (§2.11 MUST), so the autoCap auto-approval can't raise the agent to active.
    // Active delegated agents now necessarily live under a linked host, which routes the
    // cap-request through CIBA (agent_id-based approve) instead of device_authorization
    // (user_code-based). The partial-approval semantics being tested are identical on both
    // flows; we just key off agent_id and the username we control.
    String username = "partial-capreq-" + suffix();
    String userId = createTestUser(username);
    preRegisterHostForUser(hostKey, userId);

    String agentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "partial cap-req agent",
              "capabilities": ["%s"],
              "mode": "delegated"
            }
            """, autoCap))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("status", org.hamcrest.Matchers.equalTo("active"))
        .extract()
        .path("agent_id");

    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());
    Response reqResp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": ["%s", "%s"]
            }
            """, approvA, approvB))
        .when()
        .post("/agent/request-capability");
    reqResp.then().statusCode(200);

    String token = realmUserAccessToken(username);

    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("agent_id", agentId, "capabilities", java.util.List.of(approvA)))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(200);

    Map<String, Object> status = agentStatusBody(agentId, hostKey);
    assertThat(status.get("status")).isEqualTo("active");
    java.util.List<Map<String, Object>> grants = (java.util.List<Map<String, Object>>) status
        .get("agent_capability_grants");
    assertThat(grants.stream().filter(g -> approvA.equals(g.get("capability"))).findFirst()
        .orElseThrow().get("status")).isEqualTo("active");
    assertThat(grants.stream().filter(g -> approvB.equals(g.get("capability"))).findFirst()
        .orElseThrow().get("status")).isEqualTo("denied");
    // The originally-active auto capability must stay active.
    assertThat(grants.stream().filter(g -> autoCap.equals(g.get("capability"))).findFirst()
        .orElseThrow().get("status")).isEqualTo("active");
  }

  @Test
  void approveWithoutAuth_returns401() {
    given()
        .baseUri(issuerUrl())
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", "AAAA-BBBB"))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(401);
  }

  /**
   * §2.13: when an agent registers with a constrained, approval-required capability, the pending
   * response MUST stay in the compact {@code {capability, status[, status_url]}} shape (the server
   * does not echo the requested scope at registration time). On approval, the originally requested
   * constraint scope MUST be restored onto the active grant — the approver endorses the scope the
   * agent declared, never widening it. After approval, attempting to execute with an argument that
   * violates the restored constraint MUST be rejected with {@code constraint_violated}, proving the
   * constraint survived the pending→active flip.
   *
   * <p>
   * Regression coverage for the bug where pending grants discarded the agent's requested constraint
   * scope and the activation logic produced a constraint-less active grant — silently widening the
   * agent's effective scope beyond what was originally requested.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
   *      §2.13 Scoped Grants (Constraints)</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#53-agent-registration">
   *      §5.3 Agent Registration — pending grant response shape</a>
   */
  @Test
  @SuppressWarnings("unchecked")
  void registrationWithConstraints_pendingCompactResponse_approvalRestoresConstraintsAndExecuteEnforces() {
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    String capName = registerApprovalRequiredCapability(
        "devauth_constrained_reg_" + suffix());

    // Register a delegated agent requesting the approval-required cap with a `max` scope.
    Response regResp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "constrained-pending agent",
              "capabilities": [
                {
                  "name": "%s",
                  "constraints": {"amount": {"max": 100}}
                }
              ],
              "mode": "delegated"
            }
            """, capName))
        .when()
        .post("/agent/register");
    regResp.then()
        .statusCode(200)
        .body("status", equalTo("pending"))
        .body("agent_capability_grants", org.hamcrest.Matchers.hasSize(1))
        .body("agent_capability_grants[0].capability", equalTo(capName))
        .body("agent_capability_grants[0].status", equalTo("pending"))
        // §5.3: pending response MUST be compact — no `constraints`, no internal stash.
        .body("agent_capability_grants[0].constraints", org.hamcrest.Matchers.nullValue())
        .body("agent_capability_grants[0].requested_constraints",
            org.hamcrest.Matchers.nullValue());
    String agentId = regResp.jsonPath().getString("agent_id");
    String userCode = regResp.jsonPath().getString("approval.user_code");

    // User approves.
    String username = "constrained-reg-approver-" + suffix();
    createTestUser(username);
    String token = realmUserAccessToken(username);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("user_code", userCode))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(200);

    // §2.13: active grant carries the originally-requested scope.
    Map<String, Object> status = agentStatusBody(agentId, hostKey);
    assertThat(status.get("status")).isEqualTo("active");
    java.util.List<Map<String, Object>> grants = (java.util.List<Map<String, Object>>) status
        .get("agent_capability_grants");
    Map<String, Object> grant = grants.stream()
        .filter(g -> capName.equals(g.get("capability")))
        .findFirst()
        .orElseThrow(() -> new AssertionError("Grant missing on active agent"));
    assertThat(grant.get("status")).isEqualTo("active");
    assertThat(grant.get("requested_constraints"))
        .as("internal stash MUST NOT leak in agent/status response")
        .isNull();
    Map<String, Object> activeConstraints = (Map<String, Object>) grant.get("constraints");
    assertThat(activeConstraints)
        .as("active grant MUST carry the originally-requested scope after approval")
        .isNotNull();
    Map<String, Object> amountConstraint = (Map<String, Object>) activeConstraints.get("amount");
    assertThat(amountConstraint)
        .as("constraint operator survives pending→active flip")
        .isNotNull()
        .containsEntry("max", 100);

    // Execute with a violating argument MUST be rejected — the active grant carries the
    // restored scope, so ConstraintValidator catches the breach before the gateway forwards.
    String execJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        "https://resource.example.test/" + capName);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + execJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {"amount": 200}
            }
            """, capName))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(403)
        .body("error", equalTo("constraint_violated"));
  }

  /**
   * §2.13 + §5.4: same constraint-preservation rule applies to capability requests on an
   * already-active agent. The pending response from {@code /agent/request-capability} MUST be
   * compact, and approval MUST restore the requested scope onto the now-active grant.
   *
   * @see <a href=
   *      "https://agent-auth-protocol.com/specification/v1.0-draft#213-scoped-grants-constraints">
   *      §2.13 Scoped Grants (Constraints)</a>
   * @see <a href="https://agent-auth-protocol.com/specification/v1.0-draft#54-request-capability">
   *      §5.4 Request Capability — pending grant response shape</a>
   */
  @Test
  @SuppressWarnings("unchecked")
  void requestCapabilityWithConstraints_pendingCompactResponse_approvalRestoresConstraintsAndExecuteEnforces() {
    String autoCap = registerAutoCapability("devauth_capreq_constrained_auto_" + suffix());
    String approvalCap = registerApprovalRequiredCapability(
        "devauth_capreq_constrained_" + suffix());
    OctetKeyPair hostKey = TestKeys.generateEd25519();
    OctetKeyPair agentKey = TestKeys.generateEd25519();
    // Wave 5: active+unlinked hosts impossible. Run constraint-preservation under linked host
    // (CIBA flow) — the wire shape contract is identical; only the user_code-vs-agent_id
    // approval surface changes.
    String username = "capreq-constrained-approver-" + suffix();
    String userId = createTestUser(username);
    preRegisterHostForUser(hostKey, userId);

    // Register active agent with only the auto-approved cap so /agent/request-capability is
    // the entry point we exercise next.
    String agentId = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer "
            + TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl()))
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "constrained capreq agent",
              "capabilities": ["%s"],
              "mode": "delegated"
            }
            """, autoCap))
        .when()
        .post("/agent/register")
        .then()
        .statusCode(200)
        .body("status", equalTo("active"))
        .extract()
        .path("agent_id");

    // Agent requests the approval-required cap with a `max` scope.
    String agentJwt = TestJwts.agentJwt(hostKey, agentKey, agentId, issuerUrl());
    Response reqResp = given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + agentJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capabilities": [
                {
                  "name": "%s",
                  "constraints": {"amount": {"max": 50}}
                }
              ]
            }
            """, approvalCap))
        .when()
        .post("/agent/request-capability");
    reqResp.then()
        .statusCode(200)
        .body("agent_capability_grants",
            org.hamcrest.Matchers.hasItem(org.hamcrest.Matchers.allOf(
                org.hamcrest.Matchers.hasEntry("capability", approvalCap),
                org.hamcrest.Matchers.hasEntry("status", "pending"))))
        // §5.4 compact pending shape — no `constraints`, no internal stash.
        .body("agent_capability_grants.find { it.capability == '" + approvalCap + "' }.constraints",
            org.hamcrest.Matchers.nullValue())
        .body("agent_capability_grants.find { it.capability == '" + approvalCap
            + "' }.requested_constraints", org.hamcrest.Matchers.nullValue());

    // User approves via agent_id (CIBA).
    String token = realmUserAccessToken(username);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("agent_id", agentId))
        .when()
        .post("/verify/approve")
        .then()
        .statusCode(200);

    // §2.13: now-active grant carries the originally-requested scope.
    Map<String, Object> status = agentStatusBody(agentId, hostKey);
    java.util.List<Map<String, Object>> grants = (java.util.List<Map<String, Object>>) status
        .get("agent_capability_grants");
    Map<String, Object> grant = grants.stream()
        .filter(g -> approvalCap.equals(g.get("capability")))
        .findFirst()
        .orElseThrow(() -> new AssertionError("Approval cap grant missing"));
    assertThat(grant.get("status")).isEqualTo("active");
    assertThat(grant.get("requested_constraints"))
        .as("internal stash MUST NOT leak in agent/status response")
        .isNull();
    Map<String, Object> activeConstraints = (Map<String, Object>) grant.get("constraints");
    assertThat(activeConstraints).isNotNull();
    Map<String, Object> amountConstraint = (Map<String, Object>) activeConstraints.get("amount");
    assertThat(amountConstraint).isNotNull().containsEntry("max", 50);

    // Execute with a violating argument MUST be rejected.
    String execJwt = TestJwts.agentJwt(hostKey, agentKey, agentId,
        "https://resource.example.test/" + approvalCap);
    given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + execJwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "capability": "%s",
              "arguments": {"amount": 100}
            }
            """, approvalCap))
        .when()
        .post("/capability/execute")
        .then()
        .statusCode(403)
        .body("error", equalTo("constraint_violated"));
  }

  // --- helpers ---

  private static String suffix() {
    return UUID.randomUUID().toString().replace("-", "").substring(0, 8);
  }

  private static long currentApprovalExpirySeconds() {
    String token = adminAccessToken(); // touch first so ensureStarted() runs before we read
                                       // KEYCLOAK
    Response resp = given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + token)
        .when()
        .get("/admin/realms/" + REALM);
    resp.then().statusCode(200);
    String raw = resp.jsonPath().getString("attributes.agent_auth_approval_expires_in_seconds");
    if (raw == null || raw.isBlank()) {
      return 600L; // matches DEFAULT_APPROVAL_EXPIRES_IN
    }
    return Long.parseLong(raw.trim());
  }

  private static void setApprovalExpirySeconds(long seconds) {
    // Merge: GET → modify attribute → PUT. KC's PUT realm rep replaces the whole representation,
    // so we round-trip to avoid stomping unrelated realm settings.
    String token = adminAccessToken(); // ensureStarted() before reading KEYCLOAK
    Response current = given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + token)
        .when()
        .get("/admin/realms/" + REALM);
    current.then().statusCode(200);
    java.util.Map<String, Object> body = current.jsonPath().getMap("$");
    @SuppressWarnings("unchecked")
    java.util.Map<String, Object> attrs = body.get("attributes") instanceof java.util.Map
        ? (java.util.Map<String, Object>) body.get("attributes")
        : new java.util.HashMap<>();
    attrs = new java.util.HashMap<>(attrs);
    attrs.put("agent_auth_approval_expires_in_seconds", String.valueOf(seconds));
    body.put("attributes", attrs);

    given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + token)
        .contentType(ContentType.JSON)
        .body(body)
        .when()
        .put("/admin/realms/" + REALM)
        .then()
        .statusCode(204);
  }

  private static String createTestUser(String username) {
    String adminToken = adminAccessToken();
    Response resp = given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + adminToken)
        .contentType(ContentType.JSON)
        .body(Map.of(
            "username", username,
            "enabled", true,
            "emailVerified", true,
            "email", username + "@example.test",
            "firstName", "Test",
            "lastName", "User",
            "requiredActions", java.util.List.of()))
        .when()
        .post("/admin/realms/" + REALM + "/users");
    resp.then().statusCode(201);
    String location = resp.getHeader("Location");
    String userId = location.substring(location.lastIndexOf('/') + 1);

    // Set password via the dedicated reset-password endpoint so no "UPDATE_PASSWORD" required
    // action is planted on the account (which would block direct-access grant with
    // "Account is not fully set up").
    given()
        .baseUri(KEYCLOAK.getAuthServerUrl())
        .header("Authorization", "Bearer " + adminToken)
        .contentType(ContentType.JSON)
        .body(Map.of("type", "password", "value", USER_PASSWORD, "temporary", false))
        .when()
        .put("/admin/realms/" + REALM + "/users/" + userId + "/reset-password")
        .then()
        .statusCode(204);
    return userId;
  }

  private static String realmUserAccessToken(String username) {
    String tokenUrl = KEYCLOAK.getAuthServerUrl() + "/realms/" + REALM;
    Response resp = given()
        .baseUri(tokenUrl)
        .contentType(ContentType.URLENC)
        .formParam("grant_type", "password")
        .formParam("client_id", "agent-auth-test-client")
        .formParam("username", username)
        .formParam("password", USER_PASSWORD)
        .when()
        .post("/protocol/openid-connect/token");
    if (resp.getStatusCode() != 200) {
      throw new AssertionError("Password grant failed: status=" + resp.getStatusCode()
          + " body=" + resp.getBody().asString());
    }
    return resp.jsonPath().getString("access_token");
  }

  private static String registerAutoCapability(String name) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Auto-approved capability",
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
    return name;
  }

  private static String registerApprovalRequiredCapability(String name) {
    given()
        .baseUri(adminApiUrl())
        .header("Authorization", "Bearer " + adminAccessToken())
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "%s",
              "description": "Capability requiring approval",
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

  private static Response registerDelegatedAgent(OctetKeyPair hostKey, OctetKeyPair agentKey,
      String capability) {
    String jwt = TestJwts.hostJwtForRegistration(hostKey, agentKey, issuerUrl());
    return given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + jwt)
        .contentType(ContentType.JSON)
        .body(String.format("""
            {
              "name": "device-auth agent",
              "capabilities": ["%s"],
              "mode": "delegated"
            }
            """, capability))
        .when()
        .post("/agent/register");
  }

  private static Map<String, Object> agentStatusBody(String agentId, OctetKeyPair hostKey) {
    return given()
        .baseUri(issuerUrl())
        .header("Authorization", "Bearer " + TestJwts.hostJwt(hostKey, issuerUrl()))
        .queryParam("agent_id", agentId)
        .when()
        .get("/agent/status")
        .then()
        .statusCode(200)
        .extract()
        .jsonPath()
        .getMap("$");
  }
}
