package com.github.chh.keycloak.agentauth;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.wellknown.WellKnownProvider;
import org.keycloak.wellknown.WellKnownProviderFactory;

public class AgentAuthWellKnownProviderFactory implements WellKnownProviderFactory {

  public static final String PROVIDER_ID = "agent-configuration";

  @Override
  public WellKnownProvider create(KeycloakSession session) {
    return new AgentAuthWellKnownProvider(session);
  }

  @Override
  public void init(Config.Scope config) {
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
  }

  @Override
  public void close() {
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }
}
