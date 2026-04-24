package com.github.chh.keycloak.agentauth.storage;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class InMemoryStorageFactory implements AgentAuthStorageProviderFactory {

  public static final String ID = "in-memory";
  private static final InMemoryStorage SINGLETON = new InMemoryStorage();

  @Override
  public AgentAuthStorage create(KeycloakSession session) {
    return SINGLETON;
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
