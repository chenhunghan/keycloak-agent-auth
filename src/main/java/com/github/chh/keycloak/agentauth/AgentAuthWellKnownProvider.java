package com.github.chh.keycloak.agentauth;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.models.KeycloakSession;
import org.keycloak.urls.UrlType;
import org.keycloak.wellknown.WellKnownProvider;

public class AgentAuthWellKnownProvider implements WellKnownProvider {

  private final KeycloakSession session;

  public AgentAuthWellKnownProvider(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public Object getConfig() {
    String realmName = session.getContext().getRealm().getName();
    String agentAuthBase = session.getContext().getUri(UrlType.FRONTEND).getBaseUriBuilder()
        .path("realms").path(realmName).path("agent-auth").build().toString();

    Map<String, Object> config = new HashMap<>();
    config.put("version", "1.0-draft");
    config.put("provider_name", "keycloak-agent-auth");
    config.put("description", "Agent Auth Protocol Extension for Keycloak");
    config.put("issuer", agentAuthBase);
    config.put("algorithms", List.of("Ed25519"));
    config.put("modes", List.of("delegated", "autonomous"));
    config.put("approval_methods", List.of("admin"));

    Map<String, String> endpoints = new HashMap<>();
    endpoints.put("register", "/agent/register");
    endpoints.put("capabilities", "/capability/list");
    endpoints.put("describe_capability", "/capability/describe");
    endpoints.put("execute", "/capability/execute");
    endpoints.put("request_capability", "/agent/request-capability");
    endpoints.put("status", "/agent/status");
    endpoints.put("reactivate", "/agent/reactivate");
    endpoints.put("revoke", "/agent/revoke");
    endpoints.put("revoke_host", "/host/revoke");
    endpoints.put("rotate_key", "/agent/rotate-key");
    endpoints.put("rotate_host_key", "/host/rotate-key");
    endpoints.put("introspect", "/agent/introspect");
    config.put("endpoints", endpoints);

    config.put("default_location", agentAuthBase + "/capability/execute");
    return config;
  }

  @Override
  public void close() {
  }
}
