package com.github.chh.keycloak.agentauth.storage;

import org.keycloak.provider.ProviderFactory;

/** Factory SPI for {@link AgentAuthStorage} implementations. */
public interface AgentAuthStorageProviderFactory extends ProviderFactory<AgentAuthStorage> {
}
