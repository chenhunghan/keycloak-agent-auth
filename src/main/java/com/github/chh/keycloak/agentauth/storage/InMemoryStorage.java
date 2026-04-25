package com.github.chh.keycloak.agentauth.storage;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Process-wide in-memory implementation of {@link AgentAuthStorage}. State is intentionally static
 * so it is shared across Keycloak sessions within the same JVM, matching the behaviour of the
 * previous {@code InMemoryRegistry} static maps.
 */
public class InMemoryStorage implements AgentAuthStorage {

  static final Map<String, Map<String, Object>> HOSTS = new ConcurrentHashMap<>();
  static final Map<String, Map<String, Object>> AGENTS = new ConcurrentHashMap<>();
  static final Map<String, Map<String, Object>> CAPABILITIES = new ConcurrentHashMap<>();
  static final Map<String, String> ROTATED_HOST_IDS = new ConcurrentHashMap<>();

  @Override
  public Map<String, Object> getHost(String hostId) {
    return HOSTS.get(hostId);
  }

  @Override
  public void putHost(String hostId, Map<String, Object> host) {
    HOSTS.put(hostId, host);
  }

  @Override
  public void removeHost(String hostId) {
    HOSTS.remove(hostId);
  }

  @Override
  public Map<String, Object> getAgent(String agentId) {
    return AGENTS.get(agentId);
  }

  @Override
  public void putAgent(String agentId, Map<String, Object> agent) {
    AGENTS.put(agentId, agent);
  }

  @Override
  public Map<String, Object> findAgentByKeyAndHost(String agentKeyThumbprint, String hostId) {
    for (Map<String, Object> agent : AGENTS.values()) {
      if (agentKeyThumbprint.equals(agent.get("agent_key_thumbprint"))
          && hostId.equals(agent.get("host_id"))) {
        return agent;
      }
    }
    return null;
  }

  @Override
  public List<Map<String, Object>> findAgentsByHost(String hostId) {
    List<Map<String, Object>> matches = new ArrayList<>();
    for (Map<String, Object> agent : AGENTS.values()) {
      if (hostId.equals(agent.get("host_id"))) {
        matches.add(agent);
      }
    }
    return matches;
  }

  @Override
  @SuppressWarnings("unchecked")
  public List<Map<String, Object>> findGrantsByAgent(String agentId) {
    List<Map<String, Object>> out = new ArrayList<>();
    if (agentId == null) {
      return out;
    }
    Map<String, Object> agent = AGENTS.get(agentId);
    if (agent == null) {
      return out;
    }
    Object rawGrants = agent.get("agent_capability_grants");
    if (!(rawGrants instanceof List<?>)) {
      return out;
    }
    for (Object rawGrant : (List<?>) rawGrants) {
      if (!(rawGrant instanceof Map<?, ?>)) {
        continue;
      }
      Map<String, Object> grant = (Map<String, Object>) rawGrant;
      Map<String, Object> projected = new java.util.HashMap<>();
      projected.put("agent_id", agentId);
      projected.put("capability", grant.get("capability"));
      projected.put("status", grant.get("status"));
      if (grant.get("granted_by") != null) {
        projected.put("granted_by", grant.get("granted_by"));
      }
      if (grant.get("reason") != null) {
        projected.put("reason", grant.get("reason"));
      }
      if (grant.get("constraints") != null) {
        projected.put("constraints", grant.get("constraints"));
      }
      out.add(projected);
    }
    return out;
  }

  @Override
  public List<Map<String, Object>> findHostsByUser(String userId) {
    List<Map<String, Object>> matches = new ArrayList<>();
    if (userId == null) {
      return matches;
    }
    for (Map<String, Object> host : HOSTS.values()) {
      if (userId.equals(host.get("user_id"))) {
        matches.add(host);
      }
    }
    return matches;
  }

  @Override
  public Map<String, Object> findAgentByUserCode(String userCode) {
    if (userCode == null) {
      return null;
    }
    for (Map<String, Object> agent : AGENTS.values()) {
      if (userCode.equals(agent.get("user_code"))) {
        return agent;
      }
    }
    return null;
  }

  @Override
  public int deletePendingAgentsOlderThan(long thresholdEpochMs) {
    int removed = 0;
    var iterator = AGENTS.entrySet().iterator();
    while (iterator.hasNext()) {
      var entry = iterator.next();
      Map<String, Object> agent = entry.getValue();
      if (!"pending".equals(agent.get("status"))) {
        continue;
      }
      Object createdAt = agent.get("created_at");
      if (!(createdAt instanceof String iso)) {
        continue;
      }
      try {
        long epochMs = java.time.Instant.parse(iso).toEpochMilli();
        if (epochMs < thresholdEpochMs) {
          iterator.remove();
          removed++;
        }
      } catch (java.time.format.DateTimeParseException ignored) {
        // Malformed timestamp — skip rather than delete; operator can force-clean manually.
      }
    }
    return removed;
  }

  @Override
  public Map<String, Object> getCapability(String name) {
    return CAPABILITIES.get(name);
  }

  @Override
  public Map<String, Object> putCapabilityIfAbsent(String name, Map<String, Object> capability) {
    return CAPABILITIES.putIfAbsent(name, capability);
  }

  @Override
  public void putCapability(String name, Map<String, Object> capability) {
    CAPABILITIES.put(name, capability);
  }

  @Override
  public void removeCapability(String name) {
    CAPABILITIES.remove(name);
  }

  @Override
  public List<Map<String, Object>> listCapabilities() {
    return new ArrayList<>(CAPABILITIES.values());
  }

  @Override
  public boolean isHostRotated(String hostId) {
    return ROTATED_HOST_IDS.containsKey(hostId);
  }

  @Override
  public void recordHostRotation(String oldHostId, String newHostId) {
    ROTATED_HOST_IDS.put(oldHostId, newHostId);
  }
}
