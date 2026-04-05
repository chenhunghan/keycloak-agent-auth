package com.github.chh.keycloak.agentauth;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/** Factory that registers the Agent Auth Protocol REST endpoints under each realm. */
public class AgentAuthRealmResourceProviderFactory implements RealmResourceProviderFactory {

  public static final String PROVIDER_ID = "agent-auth";

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public AgentAuthRealmResourceProvider create(KeycloakSession session) {
    return new AgentAuthRealmResourceProvider(session);
  }

  @Override
  public void init(Config.Scope config) {
    // no configuration needed yet
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    // no post-init work
  }

  @Override
  public void close() {
    // no resources to release
  }
}
