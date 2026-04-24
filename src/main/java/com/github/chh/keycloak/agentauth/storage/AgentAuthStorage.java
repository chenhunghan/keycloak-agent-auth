package com.github.chh.keycloak.agentauth.storage;

import java.util.List;
import java.util.Map;
import org.keycloak.provider.Provider;

/**
 * Storage abstraction for Agent Auth Protocol state: hosts, agents, capabilities and host-key
 * rotation history.
 *
 * <p>
 * Payloads are carried as {@code Map<String, Object>} — matching the protocol JSON shape — to keep
 * the interface thin. Implementations must not rely on reference aliasing: callers always issue an
 * explicit {@code putHost/putAgent} after any mutation. Rate-limit state and JTI replay state are
 * intentionally outside this interface.
 */
public interface AgentAuthStorage extends Provider {

  // --- Hosts (keyed by host thumbprint / host_id) ---

  Map<String, Object> getHost(String hostId);

  void putHost(String hostId, Map<String, Object> host);

  void removeHost(String hostId);

  // --- Agents (keyed by agent UUID) ---

  Map<String, Object> getAgent(String agentId);

  void putAgent(String agentId, Map<String, Object> agent);

  /** Locate the single agent registered under {@code hostId} with the given key thumbprint. */
  Map<String, Object> findAgentByKeyAndHost(String agentKeyThumbprint, String hostId);

  /** All agents belonging to {@code hostId}, regardless of status. */
  List<Map<String, Object>> findAgentsByHost(String hostId);

  // --- Capabilities (keyed by name) ---

  Map<String, Object> getCapability(String name);

  /**
   * Register a capability if no entry exists for {@code name}. Returns {@code null} on success, or
   * the existing record if the name is already taken.
   */
  Map<String, Object> putCapabilityIfAbsent(String name, Map<String, Object> capability);

  void putCapability(String name, Map<String, Object> capability);

  void removeCapability(String name);

  List<Map<String, Object>> listCapabilities();

  // --- Host-key rotation bookkeeping ---

  /** True if {@code hostId} is a retired host thumbprint (key has been rotated). */
  boolean isHostRotated(String hostId);

  void recordHostRotation(String oldHostId, String newHostId);

  @Override
  default void close() {
    // no-op; implementations may override
  }
}
