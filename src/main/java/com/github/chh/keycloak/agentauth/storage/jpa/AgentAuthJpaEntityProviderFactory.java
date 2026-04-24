package com.github.chh.keycloak.agentauth.storage.jpa;

import org.keycloak.Config.Scope;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class AgentAuthJpaEntityProviderFactory implements JpaEntityProviderFactory {

  public static final String ID = "agent-auth-provider";

  @Override
  public JpaEntityProvider create(KeycloakSession session) {
    return new AgentAuthJpaEntityProvider();
  }

  @Override
  public void init(Scope config) {
    // no-op
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    // no-op
  }

  @Override
  public void close() {
    // no-op
  }

  @Override
  public String getId() {
    return ID;
  }
}
