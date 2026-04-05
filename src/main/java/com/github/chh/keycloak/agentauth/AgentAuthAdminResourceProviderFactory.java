package com.github.chh.keycloak.agentauth;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;

public class AgentAuthAdminResourceProviderFactory implements AdminRealmResourceProviderFactory {

  public static final String PROVIDER_ID = "agent-auth";

  @Override
  public AdminRealmResourceProvider create(KeycloakSession session) {
    return new AgentAuthAdminResourceProvider(session);
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
