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
}
