package com.github.chh.keycloak.agentauth.notify;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class CibaEmailNotifierTest {

  @Test
  void subjectIncludesAgentName() {
    String subject = CibaEmailNotifier.buildSubject("balance-checker", null);
    assertThat(subject).contains("balance-checker");
  }

  @Test
  void subjectIncludesHostNameWhenAvailable() {
    String subject = CibaEmailNotifier.buildSubject("balance-checker", "my-laptop");
    assertThat(subject).contains("balance-checker").contains("my-laptop");
  }

  @Test
  void textBodyContainsVerifyLinkAndBindingMessage() {
    String body = CibaEmailNotifier.buildTextBody("balance-checker", "my-laptop",
        "https://kc.example.test/realms/r/agent-auth/verify?agent_id=abc",
        "Approve connection for daily balance checks");
    assertThat(body)
        .contains("balance-checker")
        .contains("my-laptop")
        .contains("https://kc.example.test/realms/r/agent-auth/verify?agent_id=abc")
        .contains("Approve connection for daily balance checks");
  }

  @Test
  void textBodyOmitsBindingBlockWhenAbsent() {
    String body = CibaEmailNotifier.buildTextBody("alpha", null,
        "https://example.test/verify", null);
    assertThat(body).contains("alpha")
        .contains("https://example.test/verify")
        .doesNotContain("The application says");
  }

  @Test
  void htmlBodyEscapesUserSuppliedFields() {
    // §8.10 display-text safety: agent_name, host_name, binding_message can carry attacker
    // input; the email body MUST escape them.
    String html = CibaEmailNotifier.buildHtmlBody(
        "<script>alert(1)</script>",
        "host\">",
        "https://kc.example/verify?agent_id=ok&x=1",
        "<img src=x onerror=alert(1)>");
    assertThat(html)
        .doesNotContain("<script>")
        .doesNotContain("<img")
        .contains("&lt;script&gt;")
        .contains("&lt;img")
        .contains("agent_id=ok&amp;x=1");
  }

  @Test
  void htmlBodyContainsApproveLink() {
    String html = CibaEmailNotifier.buildHtmlBody("alpha", null,
        "https://example.test/verify?agent_id=A", null);
    assertThat(html).contains("href=\"https://example.test/verify?agent_id=A\"");
  }

  /**
   * §7.2 throttle: rapid retries on the same (realm × user × agent) key collapse to a single send,
   * preserving the linked user's inbox as a useful approval channel rather than a spam vector. Uses
   * an injected clock so the test runs synchronously without sleeps.
   */
  @Test
  void shouldSendCollapsesRapidRetriesPerKey() {
    CibaEmailNotifier.resetThrottleForTesting();
    long t0 = 1_000_000L;
    java.util.concurrent.atomic.AtomicLong clock = new java.util.concurrent.atomic.AtomicLong(t0);

    // First call goes through.
    assertThat(CibaEmailNotifier.shouldSend("realm:user:agent", 30_000L, clock::get)).isTrue();

    // Same key, same instant — throttled.
    assertThat(CibaEmailNotifier.shouldSend("realm:user:agent", 30_000L, clock::get)).isFalse();

    // Same key, just inside the window — still throttled.
    clock.set(t0 + 29_999L);
    assertThat(CibaEmailNotifier.shouldSend("realm:user:agent", 30_000L, clock::get)).isFalse();

    // Same key, past the window — fresh send allowed.
    clock.set(t0 + 30_000L);
    assertThat(CibaEmailNotifier.shouldSend("realm:user:agent", 30_000L, clock::get)).isTrue();
  }

  /** Different keys are independent — one user's flood doesn't lock out another's first send. */
  @Test
  void shouldSendIsolatesKeys() {
    CibaEmailNotifier.resetThrottleForTesting();
    java.util.concurrent.atomic.AtomicLong clock = new java.util.concurrent.atomic.AtomicLong(0L);
    assertThat(CibaEmailNotifier.shouldSend("realm:alice:agent1", 30_000L, clock::get)).isTrue();
    // Alice's second send within window: throttled.
    assertThat(CibaEmailNotifier.shouldSend("realm:alice:agent1", 30_000L, clock::get)).isFalse();
    // Bob's first send (different user): allowed.
    assertThat(CibaEmailNotifier.shouldSend("realm:bob:agent1", 30_000L, clock::get)).isTrue();
    // Alice's other agent: also allowed (per-(user,agent) granularity).
    assertThat(CibaEmailNotifier.shouldSend("realm:alice:agent2", 30_000L, clock::get)).isTrue();
  }

  /**
   * Defensive: a non-positive or null configuration short-circuits to "allow" rather than throwing
   * — operators that mis-set the realm attribute don't take down approvals, they just lose
   * throttling.
   */
  @Test
  void shouldSendDegradesOpenForInvalidConfig() {
    CibaEmailNotifier.resetThrottleForTesting();
    java.util.concurrent.atomic.AtomicLong clock = new java.util.concurrent.atomic.AtomicLong(0L);
    assertThat(CibaEmailNotifier.shouldSend(null, 30_000L, clock::get)).isTrue();
    assertThat(CibaEmailNotifier.shouldSend("k", 0L, clock::get)).isTrue();
    assertThat(CibaEmailNotifier.shouldSend("k", -1L, clock::get)).isTrue();
  }
}
