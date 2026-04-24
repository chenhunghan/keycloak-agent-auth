package com.github.chh.keycloak.agentauth.storage.jpa;

import com.github.chh.keycloak.agentauth.storage.AgentAuthStorage;
import com.github.chh.keycloak.agentauth.storage.AgentAuthStorageProviderFactory;
import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class JpaStorageFactory implements AgentAuthStorageProviderFactory {

  public static final String ID = "jpa";

  @Override
  public AgentAuthStorage create(KeycloakSession session) {
    return new JpaStorage(session);
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

  @Override
  public int order() {
    // Picked over the in-memory factory when both are registered and no explicit
    // `kc.spi.agent-auth-storage.provider` config is set.
    return 100;
  }
}
