package com.github.chh.keycloak.agentauth.storage;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

public class AgentAuthStorageSpi implements Spi {

  public static final String NAME = "agent-auth-storage";

  @Override
  public boolean isInternal() {
    return false;
  }

  @Override
  public String getName() {
    return NAME;
  }

  @Override
  public Class<? extends Provider> getProviderClass() {
    return AgentAuthStorage.class;
  }

  @Override
  @SuppressWarnings("rawtypes")
  public Class<? extends ProviderFactory> getProviderFactoryClass() {
    return AgentAuthStorageProviderFactory.class;
  }
}
