package com.github.chh.keycloak.agentauth;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;

class AgentAuthRealmResourceProviderFactoryTest {

  private final AgentAuthRealmResourceProviderFactory factory = new AgentAuthRealmResourceProviderFactory();

  @Test
  void providerIdIsAgentAuth() {
    assertThat(factory.getId()).isEqualTo("agent-auth");
  }

  @Test
  void createReturnsNonNullProvider() {
    // session is unused in the current implementation beyond storage
    KeycloakSession nullSession = null;
    AgentAuthRealmResourceProvider provider = factory.create(nullSession);
    assertThat(provider).isNotNull();
    assertThat(provider.getResource()).isSameAs(provider);
  }
}
