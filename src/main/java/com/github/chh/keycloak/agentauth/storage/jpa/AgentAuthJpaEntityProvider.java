package com.github.chh.keycloak.agentauth.storage.jpa;

import java.util.Arrays;
import java.util.List;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;

public class AgentAuthJpaEntityProvider implements JpaEntityProvider {

  static final String CHANGELOG_LOCATION = "META-INF/agent-auth-changelog.xml";

  @Override
  public List<Class<?>> getEntities() {
    return Arrays.asList(
        HostEntity.class,
        AgentEntity.class,
        CapabilityEntity.class,
        RotatedHostEntity.class);
  }

  @Override
  public String getChangelogLocation() {
    return CHANGELOG_LOCATION;
  }

  @Override
  public String getFactoryId() {
    return AgentAuthJpaEntityProviderFactory.ID;
  }

  @Override
  public void close() {
    // no-op
  }
}
