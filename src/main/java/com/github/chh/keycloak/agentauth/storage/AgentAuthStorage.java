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

  /**
   * All hosts whose {@code user_id} payload field equals {@code userId}. Used by the AAP §2.6
   * user-deletion cascade; returns an empty list when no host is linked to the given user.
   */
  List<Map<String, Object>> findHostsByUser(String userId);

  /**
   * All agents whose {@code user_id} field equals {@code userId}. Used by the Phase 4 eager cascade
   * on org-membership changes — finds the user's agents independently of which host they sit under
   * (autonomous-claimed agents may have a {@code user_id} that doesn't match the host's). Empty
   * list when no agent matches. The JPA implementation hits the indexed
   * {@code AGENT_AUTH_AGENT.USER_ID} column.
   */
  List<Map<String, Object>> findAgentsByUser(String userId);

  /**
   * The agent whose {@code user_code} payload field equals {@code userCode}, or {@code null} when
   * no match exists. Used by the AAP §7.1 device-authorization verify endpoints to resolve a
   * pending agent from the code the user enters.
   */
  Map<String, Object> findAgentByUserCode(String userCode);

  /**
   * Delete agents whose {@code status} is {@code pending} and whose first-seen timestamp is older
   * than {@code thresholdEpochMs}. Returns the number of agents removed. Used to satisfy AAP §7.1:
   * "Servers SHOULD periodically clean up agents that remain in pending state beyond a
   * server-defined threshold ... Cleaned-up pending agents are deleted, not revoked — they never
   * became active."
   */
  int deletePendingAgentsOlderThan(long thresholdEpochMs);

  /**
   * Phase 3 of the multi-tenant authz plan: returns the {@code AGENT_AUTH_AGENT_GRANT} rows
   * mirroring this agent's {@code agent_capability_grants} blob array. Each map carries the
   * normalized grant fields ({@code agent_id}, {@code capability}, {@code status},
   * {@code granted_by}, {@code reason}, {@code constraints}) — a strict subset of what the blob
   * would contain. Empty list when the agent has no grants or doesn't exist.
   *
   * <p>
   * For the JPA implementation this hits the indexed table (no JSON parse). For the in-memory
   * implementation it derives the same shape from the blob. Used by Phase 4's eager cascade and by
   * tests that want to verify the secondary index stays in sync.
   */
  List<Map<String, Object>> findGrantsByAgent(String agentId);

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
